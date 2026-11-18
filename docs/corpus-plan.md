# Corpus plan (written BEFORE building, per step-03 T3)

Families in scope: sqli, xss, path-traversal, command-injection.
Rule: plain payload-list files only (one payload per line). No README or prose
files. If a family has no suitable plain-list file, that is stated here instead
of improvising.

## Chosen files and reasons

| Family | File | Why |
|---|---|---|
| sqli | SecLists `Fuzzing/Databases/SQLi/quick-SQLi.txt` | Plain one-payload-per-line list (77 lines) of generic SQLi probe strings; small enough that the 150-payload cap does not truncate it. |
| xss | SecLists `Fuzzing/XSS/human-friendly/XSS-Cheat-Sheet-PortSwigger.txt` | The PortSwigger XSS cheat-sheet as a plain list (6047 lines), one vector per line, consistent format; well-maintained upstream source. |
| path-traversal | PayloadsAllTheThings `File Inclusion/Intruders/Traversal.txt` | Plain list (4521 lines) of pure traversal sequences (`../..//etc/passwd`, `..%2f..%2f/...`), no prose. SecLists' traversal material is mostly .zip archives or LFI file-name lists, not traversal sequences. |
| command-injection | PayloadsAllTheThings `Command Injection/Intruder/command_exec.txt` | Plain list (448 lines) of command-injection separators and patterns (`;`, `&&`, `%0a`, backticks...). |

## Explicitly NOT chosen (and why)

- `SecLists/Fuzzing/LFI/LFI-Jhaddix.txt` etc.: file-name lists for LFI probing
  (paths of /etc files), not traversal payloads.
- `SecLists/Payloads/Zip-Traversal/*`: zip archives, not plain lists.
- `PayloadsAllTheThings/XSS Injection/Intruders/XSS_Polyglots.txt`: polyglots
  are multi-line blocks, not one-payload-per-line.
- README.md files anywhere: prose, excluded by the step's rule.

## Per-family availability

All four families have a suitable plain-list file. No family is missing.
