# CERBERUS

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-none-success)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)

**A fast, dependency-light anonymizer for messy real-world logs, traces and tickets.**

CERBERUS de-identifies personal and commercially sensitive data inside raw
diagnostic exports — VoIP/SIP traces, JSON call-detail records, and Jira
service-desk tickets — **before** they leave a secured perimeter for
third-party analysis. It is built to run on **locked-down, offline machines**
using only the Python standard library plus an optional pre-installed
archiver, so it works where `pip install` is not an option.

> ⚠️ CERBERUS is a privacy-engineering aid, not a compliance guarantee.
> Always review output before sharing data. See [Limitations](#limitations).

📄 For the design rationale and performance numbers, see the
[Engineering Case Study](CASE_STUDY.md).

---

## Why it exists

Diagnostic data is hostile to anonymization: a single file mixes full names,
account numbers, phone numbers, SIP identities, OS usernames, internal logins,
company names, revenue figures and addresses — each needing a different
detection strategy. Files reach tens of megabytes; a case can bundle hundreds
of megabytes. Manual redaction is slow and leaks edge cases. CERBERUS turns
that into one reproducible run with a deterministic, multi-layer pipeline and
**encrypted, password-protected output**.

## Key features

- **Multi-layer PII detection** across 8 placeholder classes: `USER`,
  `USER_OS`, `ACCOUNT`, `PHONE`, `TOKEN`, `ORG`, `ADDRESS`, `AMOUNT`.
- **Russian-language aware**: surname/patronymic morphology, full-name (ФИО)
  fields, inline personal-account (`лицевой счёт`) detection, legal entities
  (ООО/ЗАО/ПАО), and a *placeholder-adjacency* rule that recovers a surname
  stranded next to an already-redacted given name.
- **Near-linear performance**: a trie-compiled regex collapses thousands of
  replacement pairs into one shared-prefix automaton — ~36 MB with ~5,600
  pairs processes in a few seconds, with **no external dependencies**.
- **Consistent & reversible**: the same real value always maps to the same
  placeholder (across files), via a key map kept strictly local.
- **Encrypted output**: optional AES-256 archive with encrypted file-name
  headers (`.7z`, `-mhe=on`) when a password is supplied at runtime.
- **No secrets in code**: organisation-specific dictionaries are loaded from a
  git-ignored local file.

## How it works

```
input_raw/  ──►  unzip nested archives
            ──►  per file:
                   scan (collect names from URL-decoded text)
                   global prepass   (structural PII: paths, phones, emails,
                                     tokens, IPs, accounts, orgs, addresses)
                   profile          (trace | jira | har)
                   dictionary burn  (trie regex, cross-file consistency)
                   name eraser      (Cyrillic names, patronymics, adjacency)
            ──►  output_clean/  +  mapping_keys.json (LOCAL ONLY)
            ──►  optional encrypted archive
```

## Quick start

```bash
# 1. (optional) configure your local dictionaries
cp cerberus_local.example.json cerberus_local.json
#    edit cerberus_local.json — see "Configuration" below

# 2. drop files to anonymize into input_raw/
mkdir input_raw
#    ... copy your logs/traces/tickets here ...

# 3. run
python cerberus.py
```

Results land in `output_clean/`. The reversible key map is written to
`mapping_keys.json` — **keep it local, never share it.**

Requirements: **Python 3.8+**, standard library only. For password-protected
output, **7-Zip** must be installed (auto-detected on PATH and in
`C:\Program Files\7-Zip\`); otherwise CERBERUS falls back to a plain `.zip`.

## Configuration

All organisation-specific data lives in `cerberus_local.json` (git-ignored).
Copy `cerberus_local.example.json` and fill in:

| Key | Purpose |
|---|---|
| `employee_names_and_logins` | Exact surnames / logins to always redact |
| `allowed_domains` | Email/SIP domains to keep (not anonymized) |
| `blocked_har_domains` | Domains whose HAR entries are dropped entirely |

If the file is absent, CERBERUS runs with empty dictionaries and relies purely
on its structural and morphological detectors.

## Security model

- **Real names, logins and internal domains are never in source.** They load
  from a local, git-ignored file. The example config ships with placeholder
  values only.
- **Secrets are runtime-only.** The archive password is requested via
  `getpass` and is never written to source or logs.
- **The key map is sensitive.** `mapping_keys.json` reverses anonymization;
  it is git-ignored and must stay inside your perimeter.

## Limitations

- Detection is heuristic. It will miss novel formats and may over-redact
  (e.g. a non-person value in a `name` field). **Always review output.**
- Filename encryption requires the `.7z` format and 7-Zip; plain `.zip`
  cannot encrypt names.
- Tuned for Russian-language telecom/IT data; other domains may need new rules.

## Contributing

Issues and PRs welcome — especially new detection profiles and language
coverage. Please **never** include real PII in issues, tests, or fixtures;
use synthetic data only.

## License

MIT — see [LICENSE](LICENSE).

## Author

Created and maintained by **Alexander Mogilin**.
