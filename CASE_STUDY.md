# CERBERUS — Engineering Case Study

A short, factual write-up of the problem CERBERUS solves and the engineering
decisions behind it. All performance numbers are reproducible from the source
and run logs.

---

## Problem

Diagnostic data — VoIP/SIP traces, JSON call-detail records, and service-desk
tickets — has to be shared with third parties for analysis, but it is dense
with personal and commercially sensitive information. A single file mixes:

- full names (incl. Cyrillic surname/patronymic morphology),
- personal account numbers and phone numbers,
- SIP identities and OS usernames,
- internal logins, company names, revenue figures, and addresses.

Each requires a different detection strategy. Files reach **tens of megabytes**;
a single case can bundle **hundreds of megabytes**. The target was a **3–5
minute, reproducible run** on a **locked-down, offline workstation** where
installing third-party packages is not possible.

A naive regex redactor fails on every axis: too slow, leaks language-specific
name edge cases, breaks cross-file consistency, and ships unencrypted output.

## Key engineering decisions

### 1. Near-linear "dictionary burn" with a trie-compiled regex

For cross-file consistency the engine must replace **thousands** of
accumulated `real → placeholder` pairs (observed: **~5,600**) across a 36 MB
document. A flat alternation regex (`a|b|c|…`) in CPython's `re` degrades to
`O(N × pairs)` — the engine evaluates branches positionally with no trie
indexing — and effectively **hangs for minutes**. The usual fix
(`pyahocorasick`, a C extension) was unavailable in the offline target.

**Solution:** compile all pairs into a **shared-prefix trie regex**, restoring
effectively `O(N)` scanning at C speed with **zero external dependencies**.

| 36 MB document, ~5,600 pairs | Before | After |
|---|---|---|
| Wall time | hang (> minutes) | **~3 s** |
| External dependency | required (uninstallable) | **none** |

### 2. Language-aware detection taxonomy

Eight placeholder classes (`USER`, `USER_OS`, `ACCOUNT`, `PHONE`, `TOKEN`,
`ORG`, `ADDRESS`, `AMOUNT`) with rules tuned to Russian-language and telecom
structure. A notable case: a **placeholder-adjacency rule** recovers a
standalone surname stranded when its given name was already redacted
(`"<Surname> [USER_440]"` → fully masked) — a failure mode generic redactors
miss. Also covers inline personal-account references, legal entities
(ООО/ЗАО/ПАО), client revenue, SIP identities and OS credentials.

### 3. Adversarial validation loop

Each iteration was validated by re-attacking the anonymized output as an
adversary, enumerating residual re-identification vectors, and closing each
with a targeted rule plus a regression check. This drove the tool from several
residual leaks (plaintext surnames, space-separated account numbers, inline
account IDs, employee logins) to a **verified-clean run across ~360 MB of
production data**.

### 4. Encrypted, reversible output

- Optional **AES-256 archive with encrypted file-name headers** (`.7z`,
  `-mhe=on`) when a password is supplied at runtime (never stored).
- A **reversible key map** so engineers can still correlate entities across
  files — kept strictly local and never shared.

## Results

- Worst-case stage: multi-minute hang → **~3 s**.
- Full case (~360 MB / 15 files) within the **3–5 minute** target.
- **8** PII/confidentiality classes; **zero residual leaks** on the production
  corpus after the validation cycle.
- Runs on an **offline** host using only the Python standard library plus an
  optional pre-installed archiver.

## Design constraints that shaped it

- **No installable dependencies** → pure-stdlib trie regex instead of a C
  extension.
- **No secrets in source** → organisation-specific dictionaries load from a
  local, git-ignored file.
- **Reversibility required** → consistent mapping, not destructive hashing.

---

*Author: Alexander Mogilin. Released under the MIT License.*
*This is an engineering case study; figures are reproducible from the repo.*
