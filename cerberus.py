
import os
import re
import json
import zipfile
import sys
import shutil
import urllib.parse
import time
from pathlib import Path

try:
    import ahocorasick
    _HAS_AHOCORASICK = True
except ImportError:
    _HAS_AHOCORASICK = False

_HAS_AHOCORASICK = False

BASE_DIR = Path(__file__).resolve().parent
INPUT_DIR = BASE_DIR / "input_raw"
OUTPUT_DIR = BASE_DIR / "output_clean"
MAPPING_FILE = BASE_DIR / "mapping_keys.json"
DEBUG_LOG_FILE = BASE_DIR / "cerberus_debug.log"

# Organisation-specific dictionaries (real employee names/logins, internal
# domains) are NOT hardcoded here — they load at runtime from a local,
# git-ignored file so this engine can be published without leaking PII or
# identifying any employer/clients. See cerberus_local.example.json.
LOCAL_CONFIG_FILE = BASE_DIR / "cerberus_local.json"

def _load_local_config():
    cfg = {
        "employee_names_and_logins": [],
        "allowed_domains": [],
        "keep_domains": [],
        "blocked_har_domains": ["google.com", "gmail.com", "gstatic.com"],
    }
    try:
        if LOCAL_CONFIG_FILE.exists():
            user = json.loads(LOCAL_CONFIG_FILE.read_text(encoding="utf-8"))
            for key in cfg:
                val = user.get(key)
                if isinstance(val, list):
                    cfg[key] = val
    except Exception:
        pass
    return cfg

_LOCAL_CONFIG = _load_local_config()

_debug_fh = None

def debug_log(msg: str) -> None:
    global _debug_fh
    print(f"[DEBUG] {msg}", flush=True)
    if _debug_fh is None:
        try:
            _debug_fh = open(DEBUG_LOG_FILE, "w", encoding="utf-8")
        except Exception:
            _debug_fh = False
    if _debug_fh:
        _debug_fh.write(msg + "\n")
        _debug_fh.flush()
LOG_FILE = BASE_DIR / "cerberus_run.log"

# Изображения НЕ собираем: из них (скриншоты, EXIF) PII не вычистить, поэтому
# они полностью отбрасываются, а не копируются в output.
IMAGE_DROP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tiff",
    ".tif", ".heic", ".heif", ".svg",
}

# Бинарные/непрозрачные файлы НЕ копируем: их нельзя вычистить от PII
# (БД с клиентами, запись звонка, таблица, документ). Отбрасываем целиком.
BINARY_DROP_EXT = {
    ".docx", ".pdf", ".xlsx", ".xls", ".doc", ".pptx", ".ppt", ".rtf",
    ".zip", ".rar", ".7z", ".gz", ".tar", ".exe", ".dll", ".pcap",
    ".pcapng", ".mp4", ".mp3", ".wav", ".ogg", ".opus", ".m4a",
    ".avi", ".mov", ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb",
    ".dat", ".dic", ".lock", ".bin",
}

ARCHIVE_RENAME_EXTS = {".zip", ".rar", ".7z", ".gz", ".tar"}

# Многие логи сериализуют не-ASCII как октальные escape'ы UTF-8 (\320\222...).
# Детекторы PII работают по тексту и такую кириллицу НЕ видят -> имена/адреса
# утекают. Нормализуем: декодируем валидные UTF-8 руны в реальные символы
# ДО анонимизации, чтобы все правила сработали.
_OCTAL_RUN_RE = re.compile(r'(?:\\[0-3][0-7][0-7]){2,}')

def _decode_octal_run(m):
    raw = m.group(0)
    buf = bytearray(int(tok, 8) for tok in raw.split("\\") if tok)
    try:
        decoded = buf.decode("utf-8")
    except UnicodeDecodeError:
        return raw  # не валидный UTF-8 — оставляем как было
    # декодируем только если получили осмысленный текст (есть буквы)
    if any(c.isalpha() for c in decoded):
        return decoded
    return raw

def decode_octal_escapes(text: str) -> str:
    if "\\" not in text:
        return text
    return _OCTAL_RUN_RE.sub(_decode_octal_run, text)

class Mapper:

    def __init__(self, path: Path):
        self.path = path
        self.data = {}
        self.counters = {}
        self.file_map = {}
        self._load()

    def _load(self):
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                self.data = raw.get("mapping", {})
                self.counters = raw.get("counters", {})
                self.file_map = raw.get("files", {})
            except Exception:
                self.data = {}
                self.counters = {}
                self.file_map = {}
        for t in self.data:
            self.counters.setdefault(t, 1)

    def save(self):
        out = {
            "mapping": self.data,
            "counters": self.counters,
            "files": self.file_map,
        }
        self.path.write_text(
            json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def register_file(self, rel_path: str, ext: str) -> str:
        ext = ext.lower()
        prefix = "archive" if ext in ARCHIVE_RENAME_EXTS else "file"
        idx = self.counters.get("_files", 1)
        new_name = f"{prefix}_{idx:02d}{ext}"
        while new_name in self.file_map:
            idx += 1
            new_name = f"{prefix}_{idx:02d}{ext}"
        self.counters["_files"] = idx + 1
        self.file_map[new_name] = rel_path
        return new_name

    def get_placeholder(self, value: str, type_: str) -> str:
        value = value.strip()
        if not value:
            return value
        if is_protected(value):
            return value
        bucket = self.data.setdefault(type_, {})
        if value in bucket:
            return bucket[value]
        idx = self.counters.get(type_, 1)
        placeholder = f"[{type_}_{idx:02d}]"
        bucket[value] = placeholder
        self.counters[type_] = idx + 1
        # v7.9 perf: версия растёт при каждом добавлении — ключ инвалидации
        # кэша trie-регекса в apply_dictionary_burn.
        self.version = getattr(self, "version", 0) + 1
        return placeholder

PHONE_ANCHOR_RE = re.compile(
    r"(?:тел(?:ефон)?\.?|номер|phone)\s*[:#]?[^\d+\r\n]{0,15}"
    r"(\+?[78][\d\-\(\)\s]{8,15}\d)",
    re.IGNORECASE,
)
PHONE_PLUS7_RE = re.compile(r"(\+7[\d\-\(\)\s]{8,13}\d)")
# Российские номера БЕЗ '+': "7 495 152-32-27", "8 (800) 100-20-30",
# "84951523227", "8-800-555-35-35". Требуем 7/8 + код + разбиение,
# чтобы не цеплять случайные числовые ID.
PHONE_RU_RE = re.compile(
    r"(?<![\d\-])([78][\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2})(?![\d\-])"
)
# CRM-поддомен раскрывает клиента: <org>.bitrix24.ru, <org>.amocrm.ru.
CRM_SUBDOMAIN_RE = re.compile(
    r"\b([a-z0-9][a-z0-9\-]{1,40})(\.(?:bitrix24|amocrm)\.(?:ru|com))\b",
    re.IGNORECASE,
)
# CRM-идентификаторы лидов/контактов: contact_id: "LD444500", lead/show/444500.
CRM_ID_FIELD_RE = re.compile(
    r'("?(?:contact_id|lead_id|deal_id|client_id)"?\s*[:=]\s*")([^"]{2,})(")',
    re.IGNORECASE,
)
CRM_URL_ID_RE = re.compile(
    r'(/(?:lead|deal|contact|company)/(?:show/)?)(\d{3,})'
)

ANI_RE = re.compile(
    r'(?i)\b(OutboundAni|InboundAni|CallerId|makeCall)(\s*[:=]\s*)'
    r'([+\d][\d\s\-\(\)]{8,18}\d)'
)

USER_OS_BACKSLASH_RE = re.compile(r"C:\\Users\\([^\\/\r\n\"]+)")
USER_OS_FORWARDSLASH_RE = re.compile(r"C:/Users/([^/\r\n\"]+)")
USERNAME_VAR_RE = re.compile(r"(USERNAME\s*=\s*)(\S+)")
COMPUTERNAME_RE = re.compile(r"(COMPUTERNAME\s*=\s*)(\S+)")
USERDOMAIN_RE = re.compile(r"(USERDOMAIN(?:_ROAMINGPROFILE)?\s*=\s*)(\S+)")
LOGONSERVER_RE = re.compile(r"(LOGONSERVER\s*=\s*\\\\)(\S+)")

JIRA_ANCHOR_RE = re.compile(
    r"(Исполнитель|Автор|Назначен(?:о|а)?|Reporter|Assignee)\s*:"
    r"(?:[ \t]*\r?\n){0,2}[ \t]*"
    r"(?:([a-zA-Z][a-zA-Z0-9._-]*)[ \t]+)?"
    r"([А-ЯЁ][а-яё]+(?:[ \t]+[А-ЯЁ][а-яё]+){0,2})"
)
JIRA_CHAT_RE = re.compile(
    r"^([А-ЯЁ][а-яё]+(?:\s+[А-ЯЁ][а-яё]+){0,2})"
    r"(?:\s*\[(?:X|Неактивн\w*)\])?"
    r"(?=\s*[\[\(]?\d{1,2}[:.]\d{2}|\s*,\s*\d{1,2}\.\d{2}\.\d{2,4})",
    re.MULTILINE,
)

HAR_HEADER_VALUE_RE = re.compile(
    r'("name"\s*:\s*"(?:[Cc]ookie|[Aa]uthorization|[Xx]-[Aa]uth-[Tt]oken|'
    r'[Xx]-[Cc]srf-[Tt]oken|[Aa]uth-[Tt]oken)"\s*,\s*"value"\s*:\s*")'
    r'([^"]*)(")'
)
HAR_COOKIE_FIELD_RE = re.compile(
    r'("(?:cookies?|token|access_token|refresh_token|auth_token|sessionid|'
    r'sid|jwt)"\s*:\s*")([^"]*)(")',
    re.IGNORECASE,
)
HAR_SETCOOKIE_RE = re.compile(
    r'(Set-Cookie["\']?\s*:\s*["\']?)([^;"\'\r\n]+)'
)
# Host в HAR-заголовках (:authority / Host) маскируем ЦЕЛИКОМ в [HOSTNAME] —
# даже свою инфраструктуру, т.к. конкретный хост (admin.internal.example.com)
# раскрывает внутреннюю топологию/инстанс, а не «о каком клиенте тикет».
HAR_HOST_RE = re.compile(
    r'("name"\s*:\s*"(?::authority|[Hh]ost)"\s*,\s*"value"\s*:\s*")([^"]+)(")'
)

DEATH_KEYS = [
    "customer_id", "abonent_id", "product_id", "account_id", "cdr_id",
    "billing_session_id", "ContextId", "sess_id", "User", "Point",
    "extension", "FromAddress", "ToAddress",
]
GLOBAL_KEY_RE = re.compile(
    r'\b(' + "|".join(re.escape(k) for k in DEATH_KEYS) + r')\b'
    r'("?\s*[:=]\s*"?)([A-Za-z0-9._\-]+)',
)

PERSON_KEYS = [
    "firstName", "lastName", "middleName", "patronymic",
    "FirstName", "LastName", "MiddleName",
    "first_name", "last_name", "middle_name",
    "fio", "FIO", "fullName", "full_name", "displayName", "display_name",
]
PERSON_KEY_RE = re.compile(
    r'(["\']?(?:' + "|".join(re.escape(k) for k in PERSON_KEYS) + r')["\']?'
    r'\s*[:=]\s*)(["\'])((?:\\.|(?!\2)[^\\])*)(\2)'
)

LONG_TOKEN_RE = re.compile(r'\b([A-Za-z0-9_\-]{24,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}|[A-Za-z0-9+/]{32,}={0,2})\b')

SIP_RE = re.compile(r'(?i)\bsip:([^@\s]+)@')
EMAIL_RE = re.compile(r'\b([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b')

VPBX_RE = re.compile(r'\b(vpbx)(\d{5,})\b', re.IGNORECASE)

IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'
)

LOGIN_AT_RE = re.compile(r'\b([a-zA-Z][a-zA-Z0-9._-]{1,30})@')

HOME_PATH_RE = re.compile(r'(/(?:home|Users)/)([A-Za-z0-9._-]+)')

LONG_DIGITS_RE = re.compile(r'\b\d{9,12}\b')

# Лицевой счёт, написанный инлайн в тексте ("VIP ЛС 16989609", "ЛС: test777").
# Значение — токен, содержащий хотя бы одну цифру (цифровой или буквенно-
# цифровой счёт), возможно с пробелами-разделителями.
LS_INLINE_RE = re.compile(
    r'(?<![А-Яа-яЁёA-Za-z])'
    r'((?:ЛС|Л/С|лиц(?:евой)?\.?[ \t]*сч[её]т\w*))([ \t:№#]*)'
    r'((?=[A-Za-z0-9 \-]*\d)[A-Za-z0-9][A-Za-z0-9 \-]{2,}[A-Za-z0-9])',
    re.IGNORECASE,
)
# Денежные суммы с валютой (баланс счёта): "47 344,60 ₽", "1 200 руб".
CURRENCY_AMOUNT_RE = re.compile(
    r'(?<![\d.,])(\d[\d   ]*(?:[.,]\d{1,2})?)'
    r'(\s*(?:₽|руб(?:\.|лей|ля)?|RUB|р\.))',
    re.IGNORECASE,
)

CYRILLIC_NAME_RE = re.compile(
    r'\b([А-ЯЁ][а-яё]{1,20}(?:[ \t]+[А-ЯЁ][а-яё]{1,20}){1,3})\b'
)

PATRONYMIC_RE = re.compile(
    r'\b([А-ЯЁ][а-яё]*(?:ович|евич|ич|овна|евна|ична|инична))\b'
)

# Одинокие фамилии в свободном тексте (медзаметки, CRM-комментарии), которые
# не попадают в дву-словные именные паттерны: ловим заглавное кириллическое
# слово с характерным русским фамильным суффиксом. Склейка с пунктуацией
# допускается (\b на границе). Перекос в приватность намеренный.
SURNAME_RE = re.compile(
    r'\b([А-ЯЁ][а-яё]+(?:ов|ова|ев|ева|ёв|ёва|ин|ина|ын|ына|'
    r'ский|ская|цкий|цкая|цев|цева|енко|енков|чук|юк|ян|'
    r'швили|дзе|ьев|ьева))\b'
)

# Свои email/SIP-домены (не анонимизируем). Из cerberus_local.json.
ALLOWED_DOMAINS = {d.lower() for d in _LOCAL_CONFIG["allowed_domains"]}

# Домены, которые НЕ прячем при сплошном поиске: (1) своя инфраструктура и
# публичные почтовики/CDN/платформы — они не раскрывают, о КАКОМ КЛИЕНТЕ тикет.
# Всё, чего тут нет (бренды клиентов), токенизируется в [DOMAIN]. Сравнение по
# суффиксу: поддомены наследуют статус (sub.example.com — свой). Свои
# инфраструктурные домены добавь в cerberus_local.json -> "keep_domains".
DOMAIN_KEEP_WHITELIST = {
    # публичные почтовики
    "gmail.com", "mail.ru", "yandex.ru", "ya.ru", "outlook.com",
    "hotmail.com", "icloud.com", "office365.com", "list.ru", "bk.ru",
    "inbox.ru", "rambler.ru",
    # публичные сервисы / CDN / платформы (не клиент-идентифицирующие)
    "google.com", "gstatic.com", "googleapis.com", "google-analytics.com",
    "googletagmanager.com", "microsoft.com", "windows.com", "live.com",
    "cloudflare.com", "jsdelivr.net", "unpkg.com", "jquery.com",
    "bootstrapcdn.com", "fontawesome.com", "github.com", "githubusercontent.com",
    "bitrix24.ru", "amocrm.ru",
} | {d.lower() for d in _LOCAL_CONFIG["keep_domains"]} | ALLOWED_DOMAINS

def _domain_kept(d: str) -> bool:
    d = d.lower().rstrip(".")
    return any(d == a or d.endswith("." + a) for a in DOMAIN_KEEP_WHITELIST)

# Отдельно стоящий домен (вне email-контекста): в логах, URL, HAR-заголовках
# (:authority, Host, Referer). Требуем реальный TLD, чтобы не цеплять
# "combined.js"/"file.pack". Лукбехайнды исключают @ (email уже обработан) и
# середину поддомена.
_TLD = (r'(?:ru|рф|com|net|org|su|by|kz|ua|am|ge|io|info|biz|me|tv|pro|app|'
        r'dev|cloud|online|site|shop|store|tech|digital|agency|group)')
STANDALONE_DOMAIN_RE = re.compile(
    r'(?<![@\w.\-])'
    r'((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + _TLD + r')'
    r'(?![\w.\-])',
    re.IGNORECASE,
)

BLOCKED_HAR_DOMAINS = tuple(_LOCAL_CONFIG["blocked_har_domains"])
EMAIL_DOMAIN_RE = re.compile(
    r'@([A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,})\b'
)
# URL-encoded '@' (%40) перед доменом: "user%40client.example.ru". Без этого
# домен не распознаётся как email-домен и утекает сырым (баг C-2).
URLENC_EMAIL_DOMAIN_RE = re.compile(
    r'%40([A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,})\b'
)

# Типы значений, которые надо «прожигать» по всему тексту (а не только там,
# где сработал контекстный детектор). Закрывает класс «сырое значение рядом с
# токеном раскрывает карту» (C-2): номер/токен/домен, единожды распознанный,
# заменяется во ВСЕХ местах — в URL, путях, JSON, именах файлов.
VALUE_BURN_TYPES = ("ACCOUNT", "PHONE", "TOKEN", "IP", "DOMAIN", "AMOUNT",
                    "ORG", "ADDRESS", "SECRET")

OPAQUE_TOKEN_RE = re.compile(r'\b[A-Za-z0-9][A-Za-z0-9_\-]{19,}\b')

SAPISIDHASH_RE = re.compile(r'\b(SAPISIDHASH)\s+(\S+)')

IP_CHAIN_RE = re.compile(r'\b(?:\d{1,3}\.){3,}\d{1,3}\b')

# Секреты в конфигах (Qt .conf / ini) и JSON: SSL-ключи/сертификаты, пароли,
# логины авторизации, токены. Значение секретного ключа маскируем целиком.
_SECRET_WORDS = (
    r'(?:passwd|password|psw|pwd|pass|secret|apikey|api_key|privatekey|'
    r'private_key|ssl|cert|credential|auth|login|token)'
)
SECRET_INI_RE = re.compile(
    r'(?im)^([ \t]*[\w.\-/]*' + _SECRET_WORDS + r'[\w.\-/]*[ \t]*=[ \t]*)'
    r'(@[A-Za-z]+\([^\r\n]*\)|"[^"\r\n]*"|[^\r\n]+?)[ \t]*$'
)
SECRET_JSON_RE = re.compile(
    r'(?i)("[\w.\-]*' + _SECRET_WORDS + r'[\w.\-]*"\s*:\s*")([^"\\]*)(")'
)
# Пустые/нулевые Qt-значения не трогаем.
_EMPTY_CONF_VAL_RE = re.compile(r'@(?:Invalid|ByteArray|Variant|String)\(\s*\)|""')

# --- v7.4: добивка остаточных утечек ------------------------------------
ANY_PLACEHOLDER = r'\[(?:USER|USER_OS|ACCOUNT|PHONE|TOKEN|HOSTNAME|ORG|ADDRESS|DOMAIN|IP|AMOUNT|ISSUE|SECRET)_\d+\]'
# Кириллическое имя-слово, прилипшее к уже проставленному плейсхолдеру:
# "Волков [USER_440]" / "[USER_10] Иванов". Соседний плейсхолдер доказывает,
# что слово — компонент имени, которое распалось при сжигании соседей.
NAME_BEFORE_ANY_PLACEHOLDER_RE = re.compile(
    r'([А-ЯЁ][а-яё]{1,20})([ \t]+)(' + ANY_PLACEHOLDER + r')'
)
NAME_AFTER_ANY_PLACEHOLDER_RE = re.compile(
    r'(' + ANY_PLACEHOLDER + r')([ \t]+)([А-ЯЁ][а-яё]{1,20})'
)
# ФИО как значение JSON-поля персоны (значение начинается с кириллицы).
JSON_PERSON_NAME_RE = re.compile(
    r'("(?:name|contactName|contact_name|callerName|caller_name|'
    r'subscriberName|abonentName|clientName|client_name)"\s*:\s*")'
    r'([А-ЯЁ][^"\\]{0,60})(")'
)
# Адреса / местоположение.
PLACE_KEY_RE = re.compile(
    r'("(?:place|address|city|location)"\s*:\s*")([^"\\]{1,120})(")',
    re.IGNORECASE,
)
PLACE_ANCHOR_RE = re.compile(r'(Местоположение\s*:\s*)([^"\\\r\n]{1,120})')
# Юрлица: ООО/ЗАО/ПАО/АО/ИП "..." .
ORG_RE = re.compile(
    r'((?:ООО|ОАО|ЗАО|ПАО|АО|ИП|НКО|АНО)[ _]*[«"][^"»\r\n]{1,80}[»"])'
)
# Структурные поля Jira (.txt). Значение может быть числом с пробелами-
# разделителями разрядов ("16 951 303"), поэтому пробел внутри значения
# разрешён, а перенос строки — нет.
_FIELD_VALUE = r'([0-9A-Za-z](?:[0-9A-Za-z \-]*[0-9A-Za-z])?)'
JIRA_ACCOUNT_FIELD_RE = re.compile(r'(Лицевой счет[^:\r\n]*:[^\S\r\n]*)' + _FIELD_VALUE)
JIRA_EXTNUM_FIELD_RE = re.compile(r'(Внешний\s*№[^:\r\n]*:[^\S\r\n]*)' + _FIELD_VALUE)
# Финансовое поле: сумма чеков клиента (раскрывает оборот).
JIRA_AMOUNT_FIELD_RE = re.compile(r'(Сумма чеков[^:\r\n]*:[^\S\r\n]*)(\d(?:[\d \-]*\d)?)')
JIRA_CONTRAGENT_RE = re.compile(r'(Контрагент\s*:\s*\r?\n[ \t]*)([^\r\n]{2,})')
# Логины-хэндлы Jira, которые не попадают под именные якоря.
JIRA_LOGIN_ANCHOR_RE = re.compile(
    r'((?:Автор|Исполнитель|Reporter|Assignee)\s*:?[ \t]*\r?\n[ \t]*)'
    r'([a-z][a-z0-9._\-]{2,19})\b'
)
JIRA_BARE_LOGIN_RE = re.compile(
    r'(?m)^(Удалить|Редактировать)(\r?\n)([a-z][a-z0-9._\-]{2,19})[ \t]*$'
)
_PLACEHOLDER_FULL_RE = re.compile(ANY_PLACEHOLDER)

FIRST_NAMES = [
    "Александр", "Алексей", "Андрей", "Антон", "Артём", "Артем", "Борис",
    "Вадим", "Валентин", "Валерий", "Василий", "Виктор", "Виталий",
    "Владимир", "Владислав", "Вячеслав", "Геннадий", "Георгий", "Денис",
    "Дмитрий", "Евгений", "Егор", "Иван", "Игорь", "Илья", "Кирилл",
    "Константин", "Леонид", "Максим", "Михаил", "Никита", "Олег", "Павел",
    "Петр", "Пётр", "Роман", "Руслан", "Сергей", "Станислав", "Степан",
    "Тимур", "Федор", "Фёдор", "Юрий", "Ярослав",
    "Алина", "Алла", "Анна", "Анастасия", "Арина", "Валентина", "Валерия",
    "Вера", "Виктория", "Галина", "Дарья", "Динара", "Екатерина", "Елена",
    "Жанна", "Зоя", "Ирина", "Карина", "Кристина", "Ксения", "Лариса",
    "Лидия", "Любовь", "Людмила", "Марина", "Мария", "Надежда", "Наталья",
    "Нина", "Оксана", "Ольга", "Полина", "Светлана", "Софья", "Татьяна",
    "Юлия", "Яна",
]
FIRST_NAME_RE = re.compile(
    r'\b(' + "|".join(re.escape(n) for n in FIRST_NAMES) + r')\b'
)
NAME_BEFORE_PLACEHOLDER_RE = re.compile(
    r'\b(?:' + "|".join(re.escape(n) for n in FIRST_NAMES) + r')[ \t]+(\[USER_\d+\])'
)
NAME_STOPWORDS = {
    "добрый", "доброе", "уважаемый", "уважаемая", "спасибо", "пожалуйста",
    "привет", "коллеги", "коллега", "итак", "также", "однако", "далее",
    "примечание", "внимание", "статус", "результат", "вопрос", "ответ",
    "чат", "поддержка", "поддержки", "исполнитель", "автор", "назначено",
    "назначена", "reporter", "assignee", "готово", "сделано", "ошибка",
    "запрос", "клиент", "клиента", "система", "системе", "тест", "тестовый",
}

# Конкретные фамилии/логины сотрудников — из cerberus_local.json, НЕ из репо.
# Пусто по умолчанию: движок опирается на структурные/морфологические детекторы.
EMP_LIST = list(_LOCAL_CONFIG["employee_names_and_logins"])
if EMP_LIST:
    EMP_LIST_RE = re.compile(
        r'\b(' + "|".join(re.escape(w) for w in EMP_LIST) + r')\b',
        re.IGNORECASE,
    )
else:
    EMP_LIST_RE = re.compile(r'(?!x)x')  # ничего не матчит, когда список пуст

GENERIC_WORDS = {"public", "manager", "admin", "user", "default", "all users"}

# Слова, которые НЕ анонимизируем (generic-термины ПО/инфраструктуры).
PROTECTED_WORDS = {"vpbx", "bitrix", "kibana", "elastic", "office", "telecom"}

def is_protected(value: str) -> bool:
    v = value.strip().lower()
    return v in GENERIC_WORDS or v in PROTECTED_WORDS

def scan_decoded_for_names(text: str, mapper: Mapper) -> None:
    # Назначение функции — имена, СПРЯТАННЫЕ в URL-encoding. Значения на
    # строках без '%' видны в сыром тексте и обрабатываются prepass/eraser
    # штатно. Поэтому декодируем и сканируем только строки с '%' — на больших
    # трейсах это на порядок меньше текста (v7.9 perf).
    if "%" not in text:
        return
    subset = "\n".join(ln for ln in text.splitlines() if "%" in ln)
    try:
        decoded = urllib.parse.unquote(subset, encoding="utf-8", errors="replace")
    except Exception:
        return
    if decoded == subset:
        return

    for m in CYRILLIC_NAME_RE.finditer(decoded):
        name = m.group(1)
        words = name.split()
        if any(w.lower() in NAME_STOPWORDS for w in words):
            continue
        if is_protected(name):
            continue
        mapper.get_placeholder(name, "USER")

    for m in PATRONYMIC_RE.finditer(decoded):
        word = m.group(1)
        if word.lower() in NAME_STOPWORDS or is_protected(word):
            continue
        mapper.get_placeholder(word, "USER")

    for m in EMP_LIST_RE.finditer(decoded):
        val = m.group(0).lower()
        if is_protected(val):
            continue
        mapper.get_placeholder(val, "USER")

    for m in PERSON_KEY_RE.finditer(decoded):
        val = m.group(3)
        if not val.strip() or is_protected(val):
            continue
        mapper.get_placeholder(val, "USER")

    for m in PHONE_PLUS7_RE.finditer(decoded):
        mapper.get_placeholder(m.group(1), "PHONE")
    for m in PHONE_ANCHOR_RE.finditer(decoded):
        mapper.get_placeholder(m.group(1), "PHONE")

def apply_global_prepass(text: str, mapper: Mapper) -> str:
    _pp_t0 = time.perf_counter()
    def _pp(name):
        nonlocal _pp_t0
        _now = time.perf_counter()
        debug_log(f"    prepass/{name}: {_now - _pp_t0:.2f}s")
        _pp_t0 = _now

    # v7.9 perf: дешёвые литеральные гарды. Regex-проход по 30 МБ без
    # совпадений стоит ~0.5-1 с; проверка `substr in text` — миллисекунды.
    # tl считается один раз: замены вставляют только плейсхолдеры [TYPE_NN]
    # и не могут ПОРОДИТЬ якорное слово, так что гард не может ошибочно
    # пропустить правило (только лишний раз запустить — это безопасно).
    tl = text.lower()

    def repl_secret_ini(m):
        val = m.group(2).strip()
        if not val or val.startswith("[") or _EMPTY_CONF_VAL_RE.fullmatch(val):
            return m.group(0)
        return m.group(1) + mapper.get_placeholder(val, "SECRET")
    _has_secret_word = any(w in tl for w in (
        "passw", "psw", "pwd", "pass", "secret", "apikey", "api_key",
        "privatekey", "private_key", "ssl", "cert", "credential", "auth",
        "login", "token"))
    if _has_secret_word:
        text = SECRET_INI_RE.sub(repl_secret_ini, text)
    _pp('SECRET_INI')

    def repl_secret_json(m):
        val = m.group(2)
        if not val or val.startswith("["):
            return m.group(0)
        return m.group(1) + mapper.get_placeholder(val, "SECRET") + m.group(3)
    if _has_secret_word:
        text = SECRET_JSON_RE.sub(repl_secret_json, text)
    _pp('SECRET_JSON')

    def repl_user_bs(m):
        val = m.group(1)
        if val.lower() in GENERIC_WORDS:
            return m.group(0)
        ph = mapper.get_placeholder(val, "USER_OS")
        return "C:\\Users\\" + ph
    if ":\\users\\" in tl:
        text = USER_OS_BACKSLASH_RE.sub(repl_user_bs, text)
    _pp('USER_OS_BACKSLASH')

    def repl_user_fs(m):
        val = m.group(1)
        if val.lower() in GENERIC_WORDS:
            return m.group(0)
        ph = mapper.get_placeholder(val, "USER_OS")
        return "C:/Users/" + ph
    if ":/users/" in tl:
        text = USER_OS_FORWARDSLASH_RE.sub(repl_user_fs, text)
    _pp('USER_OS_FORWARDSLASH')

    def repl_kv(rx, type_, src_text):
        def repl(m):
            val = m.group(2)
            if val.lower() in GENERIC_WORDS:
                return m.group(0)
            ph = mapper.get_placeholder(val, type_)
            return m.group(1) + ph
        return rx.sub(repl, src_text)

    if "USERNAME" in text:
        text = repl_kv(USERNAME_VAR_RE, "USER_OS", text)
    _pp('USERNAME_VAR')
    if "COMPUTERNAME" in text:
        text = repl_kv(COMPUTERNAME_RE, "HOSTNAME", text)
    _pp('COMPUTERNAME')
    if "USERDOMAIN" in text:
        text = repl_kv(USERDOMAIN_RE, "HOSTNAME", text)
    _pp('USERDOMAIN')
    if "LOGONSERVER" in text:
        text = repl_kv(LOGONSERVER_RE, "HOSTNAME", text)
    _pp('LOGONSERVER')

    def repl_ani(m):
        key, sep, val = m.group(1), m.group(2), m.group(3)
        if is_protected(val):
            return m.group(0)
        ph = mapper.get_placeholder(val, "PHONE")
        return f"{key}{sep}{ph}"
    if any(w in tl for w in ("outboundani", "inboundani", "callerid", "makecall")):
        text = ANI_RE.sub(repl_ani, text)
    _pp('ANI')

    def repl_phone(m):
        ph = mapper.get_placeholder(m.group(1), "PHONE")
        return m.group(0).replace(m.group(1), ph)
    if any(w in tl for w in ("тел", "номер", "phone")):
        text = PHONE_ANCHOR_RE.sub(repl_phone, text)
    _pp('PHONE_ANCHOR')
    if "+7" in text:
        text = PHONE_PLUS7_RE.sub(
            lambda m: mapper.get_placeholder(m.group(1), "PHONE"), text
        )
    _pp('PHONE_PLUS7')
    text = PHONE_RU_RE.sub(
        lambda m: mapper.get_placeholder(m.group(1), "PHONE"), text
    )
    _pp('PHONE_RU')

    def repl_crm_sub(m):
        sub = m.group(1)
        if sub.lower() in GENERIC_WORDS or is_protected(sub):
            return m.group(0)
        return mapper.get_placeholder(sub, "ORG") + m.group(2)
    if "bitrix24" in tl or "amocrm" in tl:
        text = CRM_SUBDOMAIN_RE.sub(repl_crm_sub, text)
    _pp('CRM_SUBDOMAIN')

    def repl_crm_id(m):
        return m.group(1) + mapper.get_placeholder(m.group(2), "ACCOUNT") + m.group(3)
    if "_id" in tl:
        text = CRM_ID_FIELD_RE.sub(repl_crm_id, text)
    _pp('CRM_ID_FIELD')

    if any(w in tl for w in ("/lead", "/deal", "/contact", "/company")):
        text = CRM_URL_ID_RE.sub(
            lambda m: m.group(1) + mapper.get_placeholder(m.group(2), "ACCOUNT"), text
        )
    _pp('CRM_URL_ID')

    def repl_person(m):
        prefix, q, val, q2 = m.group(1), m.group(2), m.group(3), m.group(4)
        if not val.strip() or val.lower() in GENERIC_WORDS:
            return m.group(0)
        ph = mapper.get_placeholder(val, "USER")
        return f"{prefix}{q}{ph}{q2}"
    text = PERSON_KEY_RE.sub(repl_person, text)
    _pp('PERSON_KEY')

    def repl_death(m):
        key, sep, val = m.group(1), m.group(2), m.group(3)
        if val.lower() in GENERIC_WORDS:
            return m.group(0)
        ph = mapper.get_placeholder(val, "ACCOUNT")
        return f"{key}{sep}{ph}"
    text = GLOBAL_KEY_RE.sub(repl_death, text)
    _pp('GLOBAL_KEY')

    def repl_token(m):
        ph = mapper.get_placeholder(m.group(1), "TOKEN")
        return ph
    text = LONG_TOKEN_RE.sub(repl_token, text)
    _pp('LONG_TOKEN')

    def repl_sip(m):
        local = m.group(1)
        if local.lower() in GENERIC_WORDS:
            return m.group(0)
        ph = mapper.get_placeholder(local, "USER")
        return "sip:" + ph + "@"
    if "sip:" in tl:
        text = SIP_RE.sub(repl_sip, text)
    _pp('SIP')

    def repl_email(m):
        local, domain = m.group(1), m.group(2)
        if local.lower() in GENERIC_WORDS:
            return m.group(0)
        ph = mapper.get_placeholder(local, "USER")
        return ph + "@" + domain
    if "@" in text:
        text = EMAIL_RE.sub(repl_email, text)
    _pp('EMAIL')

    def repl_vpbx(m):
        prefix, num = m.group(1), m.group(2)
        ph = mapper.get_placeholder(num, "ACCOUNT")
        return prefix + ph
    if "vpbx" in tl:
        text = VPBX_RE.sub(repl_vpbx, text)
    _pp('VPBX')

    def repl_home(m):
        prefix, val = m.group(1), m.group(2)
        if val.lower() in GENERIC_WORDS:
            return m.group(0)
        ph = mapper.get_placeholder(val, "USER_OS")
        return prefix + ph
    if "/home/" in text or "/Users/" in text:
        text = HOME_PATH_RE.sub(repl_home, text)
    _pp('HOME_PATH')

    def repl_login_at(m):
        login = m.group(1)
        if login.lower() in GENERIC_WORDS:
            return m.group(0)
        ph = mapper.get_placeholder(login, "USER")
        return ph + "@"
    if "@" in text:
        text = LOGIN_AT_RE.sub(repl_login_at, text)
    _pp('LOGIN_AT')

    def repl_domain(m):
        domain = m.group(1)
        if domain.lower() in ALLOWED_DOMAINS:
            return m.group(0)
        ph = mapper.get_placeholder(domain.lower(), "DOMAIN")
        return "@" + ph
    if "@" in text:
        text = EMAIL_DOMAIN_RE.sub(repl_domain, text)
    _pp('EMAIL_DOMAIN')

    def repl_urlenc_domain(m):
        domain = m.group(1)
        if domain.lower() in ALLOWED_DOMAINS:
            return m.group(0)
        ph = mapper.get_placeholder(domain.lower(), "DOMAIN")
        return "%40" + ph
    if "%40" in text:
        text = URLENC_EMAIL_DOMAIN_RE.sub(repl_urlenc_domain, text)
    _pp('URLENC_EMAIL_DOMAIN')

    def repl_standalone_domain(m):
        domain = m.group(1)
        if _domain_kept(domain):
            return m.group(0)
        # тот же тип DOMAIN — домен из почты и из лога получат один плейсхолдер
        return mapper.get_placeholder(domain.lower(), "DOMAIN")
    text = STANDALONE_DOMAIN_RE.sub(repl_standalone_domain, text)
    _pp('STANDALONE_DOMAIN')

    def repl_sapisid(m):
        val = m.group(2)
        ph = mapper.get_placeholder(val, "TOKEN")
        return m.group(1) + " " + ph
    if "SAPISIDHASH" in text:
        text = SAPISIDHASH_RE.sub(repl_sapisid, text)
    _pp('SAPISIDHASH')

    def repl_opaque(m):
        val = m.group(0)
        if val.lower() in GENERIC_WORDS:
            return m.group(0)
        digit_count = sum(c.isdigit() for c in val)
        if digit_count < 6:
            return m.group(0)
        ph = mapper.get_placeholder(val, "TOKEN")
        return ph
    text = OPAQUE_TOKEN_RE.sub(repl_opaque, text)
    _pp('OPAQUE_TOKEN')

    def repl_ip(m):
        ip = m.group(0)
        ph = mapper.get_placeholder(ip, "IP")
        return ph
    text = IP_CHAIN_RE.sub(repl_ip, text)
    _pp('IP_CHAIN')

    def repl_ls_inline(m):
        return m.group(1) + m.group(2) + mapper.get_placeholder(m.group(3), "ACCOUNT")
    if "лс" in tl or "л/с" in tl or "сч" in tl:
        text = LS_INLINE_RE.sub(repl_ls_inline, text)
    _pp('LS_INLINE')

    def repl_currency(m):
        return mapper.get_placeholder(m.group(1).strip(), "AMOUNT") + m.group(2)
    if any(w in tl for w in ("₽", "руб", "rub", "р.")):
        text = CURRENCY_AMOUNT_RE.sub(repl_currency, text)
    _pp('CURRENCY_AMOUNT')

    def repl_long_digits(m):
        val = m.group(0)
        ph = mapper.get_placeholder(val, "ACCOUNT")
        return ph
    text = LONG_DIGITS_RE.sub(repl_long_digits, text)
    _pp('LONG_DIGITS')

    def repl_emp(m):
        val = m.group(0)
        canon = val.lower()
        ph = mapper.get_placeholder(canon, "USER")
        return ph
    if EMP_LIST:
        text = EMP_LIST_RE.sub(repl_emp, text)
    _pp('EMP_LIST')

    def repl_json_person(m):
        val = m.group(2).strip()
        if not val or val.lower() in GENERIC_WORDS or _PLACEHOLDER_FULL_RE.search(val):
            return m.group(0)
        ph = mapper.get_placeholder(val, "USER")
        return m.group(1) + ph + m.group(3)
    text = JSON_PERSON_NAME_RE.sub(repl_json_person, text)
    _pp('JSON_PERSON_NAME')

    def repl_org(m):
        val = m.group(1).strip()
        ph = mapper.get_placeholder(val, "ORG")
        return ph
    if any(w in text for w in ("ООО", "ОАО", "ЗАО", "ПАО", "АО", "ИП", "НКО", "АНО")):
        text = ORG_RE.sub(repl_org, text)
    _pp('ORG')

    def repl_place_key(m):
        val = m.group(2).strip()
        if not val or _PLACEHOLDER_FULL_RE.search(val):
            return m.group(0)
        ph = mapper.get_placeholder(val, "ADDRESS")
        return m.group(1) + ph + m.group(3)
    if any(w in tl for w in ("place", "address", "city", "location")):
        text = PLACE_KEY_RE.sub(repl_place_key, text)
    _pp('PLACE_KEY')

    def repl_place_anchor(m):
        val = m.group(2).strip()
        if not val or _PLACEHOLDER_FULL_RE.search(val):
            return m.group(0)
        ph = mapper.get_placeholder(val, "ADDRESS")
        return m.group(1) + ph
    if "Местоположение" in text:
        text = PLACE_ANCHOR_RE.sub(repl_place_anchor, text)
    _pp('PLACE_ANCHOR')

    return text

_CYR_ANY_RE = re.compile(r'[А-Яа-яЁё]')

def apply_universal_name_eraser(text: str, mapper: Mapper) -> str:
    # v7.9 perf: все правила eraser'а кириллические. В ASCII-файле
    # (conf/трейс без русских строк) делать нечего — один дешёвый поиск
    # вместо шести полных regex-проходов.
    if not _CYR_ANY_RE.search(text):
        debug_log("    eraser: skipped (no cyrillic in file)")
        return text
    _en_t0 = time.perf_counter()
    def _en(name):
        nonlocal _en_t0
        _now = time.perf_counter()
        debug_log(f"    eraser/{name}: {_now - _en_t0:.2f}s")
        _en_t0 = _now
    def repl(m):
        name = m.group(1)
        words = name.split()
        if any(w.lower() in NAME_STOPWORDS for w in words):
            return m.group(0)
        if name.lower() in GENERIC_WORDS:
            return m.group(0)
        ph = mapper.get_placeholder(name, "USER")
        return ph
    text = CYRILLIC_NAME_RE.sub(repl, text)
    _en('CYRILLIC_NAME')

    def repl_patr(m):
        word = m.group(1)
        if word.lower() in NAME_STOPWORDS or word.lower() in GENERIC_WORDS:
            return m.group(0)
        ph = mapper.get_placeholder(word, "USER")
        return ph
    text = PATRONYMIC_RE.sub(repl_patr, text)
    _en('PATRONYMIC')

    text = NAME_BEFORE_PLACEHOLDER_RE.sub(r'\1', text)
    _en('NAME_BEFORE_PLACEHOLDER')

    def repl_first_name(m):
        name = m.group(1)
        if name.lower() in NAME_STOPWORDS or name.lower() in GENERIC_WORDS:
            return m.group(0)
        ph = mapper.get_placeholder(name, "USER")
        return ph
    text = FIRST_NAME_RE.sub(repl_first_name, text)
    _en('FIRST_NAME')

    def repl_surname(m):
        word = m.group(1)
        if word.lower() in NAME_STOPWORDS or word.lower() in GENERIC_WORDS \
                or is_protected(word):
            return m.group(0)
        ph = mapper.get_placeholder(word, "USER")
        return ph
    text = SURNAME_RE.sub(repl_surname, text)
    _en('SURNAME')

    # Имя-слово, прилипшее к плейсхолдеру: фамилия осталась открытой, потому
    # что соседние имя/отчество уже сожгли. Соседство с плейсхолдером —
    # доказательство, что это PII.
    def _adj_ok(name):
        return not (name.lower() in NAME_STOPWORDS
                    or name.lower() in GENERIC_WORDS or is_protected(name))

    def repl_before(m):  # "Волков [USER_440]"
        name = m.group(1)
        if not _adj_ok(name):
            return m.group(0)
        return mapper.get_placeholder(name, "USER") + m.group(2) + m.group(3)

    def repl_after(m):  # "[USER_10] Иванов"
        name = m.group(3)
        if not _adj_ok(name):
            return m.group(0)
        return m.group(1) + m.group(2) + mapper.get_placeholder(name, "USER")

    for _ in range(2):
        text = NAME_BEFORE_ANY_PLACEHOLDER_RE.sub(repl_before, text)
        text = NAME_AFTER_ANY_PLACEHOLDER_RE.sub(repl_after, text)
    _en('NAME_ADJ_PLACEHOLDER')

    return text

_HEX_PAIR_RE = re.compile(r'%[0-9A-Fa-f]{2}')

def _is_word_char(c: str) -> bool:
    return c.isalnum() or c == "_"

def _build_trie_pattern(words):
    """Свернуть список слов в trie-регулярку с общими префиксами.

    Плоская альтернатива (a|b|c|...) на тысячах веток в stdlib `re` работает
    перебором веток на каждой позиции -> O(N * веток). Trie схлопывает общие
    префиксы, и движок идёт по дереву на C-скорости -> практически O(N).
    """
    trie = {}
    for w in words:
        # Жёсткий предел глубины: to_regex рекурсивен по длине ключа. Длинное
        # значение (мусорный захват SSL/конфига или его URL-encoded вариант)
        # рвёт стек RecursionError. Реальные имена/хосты короче 120 символов.
        # Фильтр здесь страхует ВСЕ пути вызова, а не только основной словарь.
        if len(w) > 120:
            continue
        node = trie
        for ch in w:
            node = node.setdefault(ch, {})
        node[""] = {}  # маркер конца слова

    def to_regex(node):
        if "" in node and len(node) == 1:
            return None  # лист: дальше веток нет
        alts = []
        cc = []  # одиночные символы-листья -> в charset
        q = "" in node  # текущий узел сам является концом слова
        for ch in sorted(k for k in node if k != ""):
            sub = to_regex(node[ch])
            if sub is None:
                cc.append(ch)
            else:
                alts.append(re.escape(ch) + sub)
        cc_only = not alts
        if cc:
            if len(cc) == 1:
                alts.append(re.escape(cc[0]))
            else:
                alts.append("[" + "".join(re.escape(c) for c in cc) + "]")
        result = alts[0] if len(alts) == 1 else "(?:" + "|".join(alts) + ")"
        if q:
            # хвост опционален: само слово уже валидно
            result = result + "?" if cc_only else "(?:" + result + ")?"
        return result

    return to_regex(trie)

def _burn_with_trie_regex(text: str, pairs: dict) -> str:
    pattern = _build_trie_pattern(pairs.keys())
    if not pattern:
        return text
    rx = re.compile(r'(?<!\w)(?:' + pattern + r')(?!\w)')
    return rx.sub(lambda m: pairs[m.group(0)], text)

def _burn_with_ahocorasick(text: str, pairs: dict) -> str:
    A = ahocorasick.Automaton()
    for real, ph in pairs.items():
        A.add_word(real, (len(real), ph))
    A.make_automaton()

    matches = []
    for end_idx, (length, ph) in A.iter(text):
        start = end_idx - length + 1
        if start > 0 and _is_word_char(text[start - 1]):
            continue
        if end_idx + 1 < len(text) and _is_word_char(text[end_idx + 1]):
            continue
        matches.append((start, end_idx + 1, ph))

    if not matches:
        return text

    matches.sort(key=lambda m: (m[0], -(m[1] - m[0])))
    out = []
    pos = 0
    for start, end, ph in matches:
        if start < pos:
            continue
        out.append(text[pos:start])
        out.append(ph)
        pos = end
    out.append(text[pos:])
    return "".join(out)

def apply_dictionary_burn(text: str, mapper: Mapper) -> str:
    has_percent = "%" in text

    # v7.9 perf: кэш-хит по (версия маппера, has_percent) — словарь не менялся,
    # готовый регекс и pairs переиспользуются, сборка пропускается целиком.
    if not _HAS_AHOCORASICK:
        cache = getattr(mapper, "_burn_cache", None)
        key = (getattr(mapper, "version", 0), has_percent)
        if cache is not None and cache[0] == key:
            rx, cached_pairs = cache[1], cache[2]
            if rx is not None:
                _bn_t0 = time.perf_counter()
                text = rx.sub(lambda m: cached_pairs[m.group(0)], text)
                debug_log(f"    burn: trie-regex cached ({time.perf_counter() - _bn_t0:.2f}s)")
            if EMP_LIST:
                text = EMP_LIST_RE.sub(
                    lambda m: m.group(0) if is_protected(m.group(0).lower())
                    else mapper.get_placeholder(m.group(0).lower(), "USER"), text)
            return text

    pairs = {}
    for type_ in ("USER", "USER_OS", "HOSTNAME"):
        for real, ph in mapper.data.get(type_, {}).items():
            # Верхний предел длины: trie-regex рекурсивен по длине ключа, а
            # очень длинное значение (мусорный захват куска SSL/конфига) рвёт
            # стек RecursionError. Реальные имена/хосты короче 120 символов.
            if len(real) < 3 or len(real) > 120 or is_protected(real):
                continue
            pairs.setdefault(real, ph)

            if not has_percent:
                continue

            variants = {real, real.lower(), real.capitalize(), real.upper()}
            for variant in variants:
                try:
                    enc = urllib.parse.quote(variant, safe="")
                except Exception:
                    enc = variant
                if enc == variant:
                    continue
                pairs.setdefault(enc, ph)
                enc_lower = _HEX_PAIR_RE.sub(lambda mm: mm.group(0).lower(), enc)
                if enc_lower != enc:
                    pairs.setdefault(enc_lower, ph)

    # v7.5: прожигаем и значения (счета/токены/домены/IP/суммы) по всему тексту.
    # Это закрывает C-2: значение, единожды распознанное контекстным детектором,
    # больше не остаётся сырым в URL/путях/именах файлов. Защита от порчи:
    # пропускаем короткие и чисто-числовые короткие значения (могут совпасть со
    # случайными числами и сломать данные). Границы слова — в _burn_with_*.
    for type_ in VALUE_BURN_TYPES:
        for real, ph in mapper.data.get(type_, {}).items():
            r = real.strip()
            if len(r) < 5 or is_protected(r):
                continue
            if r.isdigit() and len(r) < 6:
                continue
            pairs.setdefault(r, ph)

    if pairs:
        debug_log(f"    burn: pairs={len(pairs)}")
        if _HAS_AHOCORASICK:
            text = _burn_with_ahocorasick(text, pairs)
        else:
            # v7.9 perf: кэш собранного trie-регекса. Burn зовётся 2+ раза на
            # файл и на каждом файле корпуса; словарь только растёт, поэтому
            # ключ (версия маппера, has_percent) однозначно определяет pairs.
            _bn_t0 = time.perf_counter()
            cache = getattr(mapper, "_burn_cache", None)
            key = (getattr(mapper, "version", 0), has_percent)
            if cache is not None and cache[0] == key:
                rx, cached_pairs = cache[1], cache[2]
            else:
                pattern = _build_trie_pattern(pairs.keys())
                rx = re.compile(r'(?<!\w)(?:' + pattern + r')(?!\w)') if pattern else None
                cached_pairs = pairs
                mapper._burn_cache = (key, rx, cached_pairs)
            if rx is not None:
                text = rx.sub(lambda m: cached_pairs[m.group(0)], text)
            debug_log(f"    burn: trie-regex done ({time.perf_counter() - _bn_t0:.2f}s)")

    def repl_emp2(m):
        canon = m.group(0).lower()
        if is_protected(canon):
            return m.group(0)
        ph = mapper.get_placeholder(canon, "USER")
        return ph
    if EMP_LIST:
        text = EMP_LIST_RE.sub(repl_emp2, text)

    return text

def apply_trace_profile(text: str, mapper: Mapper) -> str:
    return apply_dictionary_burn(text, mapper)

def apply_jira_profile(text: str, mapper: Mapper) -> str:
    def repl_anchor(m):
        anchor, login, name = m.group(1), m.group(2), m.group(3)
        name_clean = re.sub(r"[ \t\r\n]+", " ", name).strip()
        if name_clean.lower() in GENERIC_WORDS:
            return m.group(0)
        ph = mapper.get_placeholder(name_clean, "USER")
        if login:
            mapper.data.setdefault("USER", {})[login] = ph
            mapper.version = getattr(mapper, "version", 0) + 1
        return f"{anchor}: {ph}"
    text = JIRA_ANCHOR_RE.sub(repl_anchor, text)

    def repl_chat(m):
        name = m.group(1)
        if name.lower() in GENERIC_WORDS:
            return m.group(0)
        ph = mapper.get_placeholder(name, "USER")
        return ph
    text = JIRA_CHAT_RE.sub(repl_chat, text)

    def _field_ok(val):
        return bool(val) and not val.startswith("[") \
            and val.lower() not in GENERIC_WORDS

    def repl_account_field(m):
        if not _field_ok(m.group(2)):
            return m.group(0)
        return m.group(1) + mapper.get_placeholder(m.group(2), "ACCOUNT")
    text = JIRA_ACCOUNT_FIELD_RE.sub(repl_account_field, text)

    def repl_extnum_field(m):
        if not _field_ok(m.group(2)):
            return m.group(0)
        return m.group(1) + mapper.get_placeholder(m.group(2), "TOKEN")
    text = JIRA_EXTNUM_FIELD_RE.sub(repl_extnum_field, text)

    def repl_amount_field(m):
        if not _field_ok(m.group(2)):
            return m.group(0)
        return m.group(1) + mapper.get_placeholder(m.group(2), "AMOUNT")
    text = JIRA_AMOUNT_FIELD_RE.sub(repl_amount_field, text)

    def repl_contragent(m):
        val = m.group(2).strip()
        if not _field_ok(val):
            return m.group(0)
        return m.group(1) + mapper.get_placeholder(val, "ORG")
    text = JIRA_CONTRAGENT_RE.sub(repl_contragent, text)

    def repl_jira_login(m):
        if not _field_ok(m.group(2)):
            return m.group(0)
        return m.group(1) + mapper.get_placeholder(m.group(2), "USER")
    text = JIRA_LOGIN_ANCHOR_RE.sub(repl_jira_login, text)

    def repl_bare_login(m):
        if not _field_ok(m.group(3)):
            return m.group(0)
        return m.group(1) + m.group(2) + mapper.get_placeholder(m.group(3), "USER")
    text = JIRA_BARE_LOGIN_RE.sub(repl_bare_login, text)

    text = apply_dictionary_burn(text, mapper)

    return text

def apply_har_profile(text: str, mapper: Mapper) -> str:
    try:
        data = json.loads(text)
        entries = data.get("log", {}).get("entries")
        if isinstance(entries, list):
            before = len(entries)
            entries = [
                e for e in entries
                if not any(
                    dom in (e.get("request", {}).get("url") or "")
                    for dom in BLOCKED_HAR_DOMAINS
                )
            ]
            removed = before - len(entries)
            if removed:
                data["log"]["entries"] = entries
                text = json.dumps(data, ensure_ascii=False, indent=2)
    except (ValueError, AttributeError, TypeError):
        pass

    def repl3(m):
        val = m.group(2)
        if not val:
            return m.group(0)
        ph = mapper.get_placeholder(val, "TOKEN")
        return m.group(1) + ph + m.group(3)

    text = HAR_HEADER_VALUE_RE.sub(repl3, text)
    text = HAR_COOKIE_FIELD_RE.sub(repl3, text)

    def repl_setcookie(m):
        val = m.group(2)
        ph = mapper.get_placeholder(val, "TOKEN")
        return m.group(1) + ph
    text = HAR_SETCOOKIE_RE.sub(repl_setcookie, text)

    def repl_har_host(m):
        val = m.group(2).strip()
        if not val or val.startswith("["):
            return m.group(0)
        return m.group(1) + mapper.get_placeholder(val, "HOSTNAME") + m.group(3)
    text = HAR_HOST_RE.sub(repl_har_host, text)

    text = apply_dictionary_burn(text, mapper)

    return text

def detect_profile(path: Path, sample: str) -> str:
    ext = path.suffix.lower()

    if ext == ".har":
        return "har"

    if '"headers"' in sample and '"postdata"' in sample.lower():
        return "har"
    if sample.lstrip().startswith("{") and '"entries"' in sample:
        return "har"

    if re.search(r"(Исполнитель|Автор|Reporter|Assignee)\s*:", sample):
        return "jira"
    if JIRA_CHAT_RE.search(sample):
        return "jira"

    if ext == ".log":
        return "trace"
    if "C:\\Users\\" in sample or "C:/Users/" in sample:
        return "trace"

    return "trace"

def unpack_archives(root: Path, log):
    broken = set()
    extracted = set()
    found = True
    while found:
        found = False
        for zpath in list(root.rglob("*.zip")):
            if zpath in broken or zpath in extracted:
                continue
            try:
                dest = zpath.parent / zpath.stem
                with zipfile.ZipFile(zpath, "r") as zf:
                    zf.extractall(dest)
                log(f"[UNZIP] {zpath} -> {dest}/")
                extracted.add(zpath)
                found = True
                try:
                    zpath.unlink()
                except OSError as e:
                    log(f"[UNZIP] {zpath}: распаковано, но не удалено ({e})")
            except Exception as e:
                try:
                    head = open(zpath, "rb").read(8)
                except Exception:
                    head = b""
                if head[:6] == b"7z\xbc\xaf\x27\x1c":
                    log(f"[UNZIP ERROR] {zpath}: это 7z-архив (не zip), "
                        f"stdlib не умеет его распаковывать - "
                        f"распакуй вручную через 7-Zip/WinRAR и положи "
                        f"результат обратно в input_raw")
                elif head[:4] == b"Rar!":
                    log(f"[UNZIP ERROR] {zpath}: это RAR-архив (не zip), "
                        f"stdlib не умеет его распаковывать - "
                        f"распакуй вручную через 7-Zip/WinRAR")
                else:
                    log(f"[UNZIP ERROR] {zpath}: {e} (файл оставлен как есть)")
                broken.add(zpath)

def read_text_any_encoding(path: Path):
    for enc in ("utf-8", "utf-8-sig", "cp1251", "latin-1"):
        try:
            return path.read_text(encoding=enc), enc
        except (UnicodeDecodeError, UnicodeError):
            continue
    return None, None

def print_progress(current, total, prefix=""):
    width = 30
    if total == 0:
        pct = 1.0
    else:
        pct = current / total
    filled = int(width * pct)
    bar = "#" * filled + "-" * (width - filled)
    sys.stdout.write(f"\r{prefix} [{bar}] {current}/{total} ({pct*100:5.1f}%)")
    sys.stdout.flush()
    if current >= total:
        sys.stdout.write("\n")

def _find_7zip():
    import shutil
    for cand in (shutil.which("7z"), shutil.which("7za"),
                 r"C:\Program Files\7-Zip\7z.exe",
                 r"C:\Program Files (x86)\7-Zip\7z.exe"):
        if cand and os.path.exists(cand):
            return cand
    return None

def _plain_zip(log):
    zip_path = BASE_DIR / "Sanitized_Data_Migration_FINAL.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in OUTPUT_DIR.rglob("*"):
            if f.is_file():
                zf.write(f, f.relative_to(OUTPUT_DIR))
    return zip_path

def create_final_zip(log):
    if not OUTPUT_DIR.exists() or not any(OUTPUT_DIR.rglob("*")):
        log("Архив не создан: output_clean пуст.")
        return

    sevenzip = _find_7zip()
    if not sevenzip:
        zip_path = _plain_zip(log)
        log(f"7-Zip не найден. Создан архив БЕЗ пароля: {zip_path}")
        log("Поставь пароль вручную через 7-Zip/WinRAR перед выносом за контур.")
        return

    import getpass
    import subprocess
    try:
        pwd = getpass.getpass("Пароль для архива (Enter — без пароля): ")
    except Exception:
        pwd = ""

    # С паролем -> формат 7z с шифрованием имён файлов (-mhe=on; zip это не
    # умеет). Без пароля -> обычный zip (шифровать нечем).
    if pwd:
        arch_path = BASE_DIR / "Sanitized_Data_Migration_FINAL.7z"
        cmd = [sevenzip, "a", "-t7z", "-m0=lzma2", "-mhe=on",
               "-p" + pwd, "-bso0", "-bsp0", str(arch_path), "*"]
    else:
        arch_path = BASE_DIR / "Sanitized_Data_Migration_FINAL.zip"
        cmd = [sevenzip, "a", "-tzip", "-bso0", "-bsp0", str(arch_path), "*"]
    if arch_path.exists():
        try:
            arch_path.unlink()
        except OSError:
            pass

    try:
        res = subprocess.run(cmd, cwd=str(OUTPUT_DIR),
                             capture_output=True, text=True)
    except Exception as e:
        zip_path2 = _plain_zip(log)
        log(f"Запуск 7-Zip не удался ({e}). Создан архив БЕЗ пароля: {zip_path2}")
        return

    # Код 0 = ок, 1 = предупреждение (архив всё равно создан). Решаем по факту
    # наличия непустого архива, а НЕ только по коду — иначе при warning'е
    # сработал бы фолбэк и создал второй, незашифрованный zip рядом.
    archived = (res.returncode in (0, 1)
                and arch_path.exists() and arch_path.stat().st_size > 0)
    if archived:
        if res.returncode == 1:
            log("7-Zip: предупреждение (код 1), но архив создан.")
        prot = ("с паролем, AES-256 + шифрование имён (-mhe)" if pwd
                else "БЕЗ пароля")
        log(f"Анонимизация завершена. Архив {prot}: {arch_path}")
        return

    # Архив не создан — убираем возможный битый файл.
    if arch_path.exists():
        try:
            arch_path.unlink()
        except OSError:
            pass
    if pwd:
        # НЕ создаём незашифрованный zip вместо запрошенного зашифрованного.
        log(f"ОШИБКА: 7-Zip не создал зашифрованный архив (код {res.returncode}).")
        err = (res.stderr or "").strip()
        if err:
            log(f"7-Zip stderr: {err[:300]}")
        log("Архив БЕЗ пароля НЕ создаю (это был бы слив). "
            "Заархивируй output_clean вручную с паролем.")
    else:
        zip_path2 = _plain_zip(log)
        log(f"7-Zip не справился (код {res.returncode}). "
            f"Создан обычный zip: {zip_path2}")

def main():
    INPUT_DIR.mkdir(exist_ok=True)
    OUTPUT_DIR.mkdir(exist_ok=True)

    if OUTPUT_DIR.exists():
        for f in sorted(OUTPUT_DIR.rglob("*"), reverse=True):
            try:
                if f.is_file():
                    f.unlink()
                else:
                    f.rmdir()
            except OSError:
                pass
    OUTPUT_DIR.mkdir(exist_ok=True)

    log_lines = []
    def log(msg):
        print(msg)
        log_lines.append(msg)

    log("=== CERBERUS v8.0 (Perf + Domain-Split + HAR-Host + Trie-Depth-Fix) ===")
    log(f"Папка входа:  {INPUT_DIR}")
    log(f"Папка выхода: {OUTPUT_DIR}")
    log(f"Маппинг:      {MAPPING_FILE}")
    log("")

    log("Шаг 1/2: распаковка архивов...")
    unpack_archives(INPUT_DIR, log)

    mapper = Mapper(MAPPING_FILE)

    all_files = [p for p in INPUT_DIR.rglob("*") if p.is_file()]
    total = len(all_files)
    log(f"\nШаг 2/2: обработка {total} файлов...")

    processed = 0
    skipped = 0

    for i, src in enumerate(all_files, 1):
        rel = src.relative_to(INPUT_DIR)

        if src.suffix.lower() in IMAGE_DROP_EXT:
            log(f"[DROP-IMG] {rel} -> отброшено (изображение не очищается от PII)")
            skipped += 1
            print_progress(i, total, prefix="Обработка")
            continue

        if src.suffix.lower() in BINARY_DROP_EXT:
            log(f"[DROP-BIN] {rel} -> отброшено (бинарь не очищается от PII)")
            skipped += 1
            print_progress(i, total, prefix="Обработка")
            continue

        text, enc = read_text_any_encoding(src)
        if text is None:
            log(f"[DROP-BIN] {rel} -> отброшено (не читается как текст)")
            skipped += 1
            print_progress(i, total, prefix="Обработка")
            continue

        _t0 = time.perf_counter()
        debug_log(f"--- {rel} (size={len(text)} chars) ---")

        text = decode_octal_escapes(text)
        debug_log(f"  decode_octal_escapes: {time.perf_counter() - _t0:.2f}s")

        scan_decoded_for_names(text, mapper)
        debug_log(f"  scan_decoded_for_names: {time.perf_counter() - _t0:.2f}s")

        profile = detect_profile(src, text[:5000])

        _t = time.perf_counter()
        text = apply_global_prepass(text, mapper)
        debug_log(f"  apply_global_prepass: {time.perf_counter() - _t:.2f}s")

        _t = time.perf_counter()
        if profile == "har":
            clean = apply_har_profile(text, mapper)
        elif profile == "jira":
            clean = apply_jira_profile(text, mapper)
        else:
            clean = apply_trace_profile(text, mapper)
        debug_log(f"  apply_{profile}_profile: {time.perf_counter() - _t:.2f}s")

        # v7.9 perf: отдельный burn #1 удалён — каждый профиль уже вызывает
        # apply_dictionary_burn последним шагом, повторный проход по тому же
        # тексту с тем же маппером даёт байт-в-байт тот же результат
        # (проверено на бенчмарке), но стоит ~3.5 с на 30 МБ.

        _t = time.perf_counter()
        _clean_before_eraser = clean
        _mapper_size_before = sum(len(v) for v in mapper.data.values())
        clean = apply_universal_name_eraser(clean, mapper)
        _mapper_size_after = sum(len(v) for v in mapper.data.values())
        debug_log(f"  apply_universal_name_eraser: {time.perf_counter() - _t:.2f}s")

        debug_log("  apply_dictionary_burn #2: disabled (v7.3.2, too slow on large name dicts)")

        new_name = mapper.register_file(str(rel), src.suffix.lower() or ".txt")
        dst = OUTPUT_DIR / new_name
        dst.write_text(clean, encoding="utf-8")
        processed += 1
        debug_log(f"  TOTAL: {time.perf_counter() - _t0:.2f}s -> {new_name}")
        print_progress(i, total, prefix="Обработка")

    mapper.save()

    log("")
    log(f"Готово. Обработано: {processed}, пропущено: {skipped}.")
    log(f"Результат: {OUTPUT_DIR}")
    log(f"Маппинг (НЕ ПЕРЕДАВАТЬ): {MAPPING_FILE}")

    create_final_zip(log)

    LOG_FILE.write_text("\n".join(log_lines), encoding="utf-8")

if __name__ == "__main__":
    main()
