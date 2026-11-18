# Corpus sources

Recorded per standing rule 10-12 and step-03 T3. Cloned with `git clone --depth 1`
into `data/external/` (gitignored); the commit SHA below is what was actually used.

| Repo | URL | Commit SHA | License (from its LICENSE file) |
|---|---|---|---|
| SecLists | https://github.com/danielmiessler/SecLists | `6b19c2f5088c45b5dadb4d8918d2ab4f7efb03a9` | MIT (LICENSE: "MIT License, Copyright (c) 2018 Daniel Miessler") |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings | `08ea40e77db3f42ef8f20c65196f3936a19b6c86` | MIT (LICENSE: "MIT License, Copyright (c) 2019 Swissky") |

Clones verified:
    $ git -C data/external/SecLists rev-parse HEAD
    6b19c2f5088c45b5dadb4d8918d2ab4f7efb03a9
    $ git -C data/external/PayloadsAllTheThings rev-parse HEAD
    08ea40e77db3f42ef8f20c65196f3936a19b6c86
