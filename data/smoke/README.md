# data/smoke

`manifest.jsonl` here is PLUMBING VALIDATION, NOT A DATASET: 12 hand-written
samples (6 attack, 6 benign) whose only job is to prove the runner, the block
discriminator and the audit correlation work end to end. Do not quote any
rate measured on it. `source` is "hand-written-smoke" on every sample.

`query`/`body`/`path` are stored exactly as they go on the wire (already
percent-encoded as intended; `query` has no leading "?").
