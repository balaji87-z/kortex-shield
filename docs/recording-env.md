# Recording environment (benign-browse-v0)

Facts about the environment that produced `data/benign-browse-v0` (step 04).

## Versions

- Playwright (Python package): **1.65.2** (`pip show playwright`)
- Chromium (Playwright headless shell): **159.0.8154.6**
  (`playwright.sync_api.chromium.launch().version`, 2026-11-18)
- Juice Shop: image `bkimminich/juice-shop:v20.4.0`; the app's own version
  endpoint (`GET /rest/admin/application-version`) reports
  `{"version":"20.4.0-SNAPSHOT"}`.
- OS-level Chromium dependencies were NOT installable on this host (no sudo);
  see below.

## LD_LIBRARY_PATH workaround

Chromium fails to launch with the default environment because several system
libraries (nspr4, nss3, atk, cairo, cups, gbm, asound, and others) are missing
from the system paths and cannot be installed (`sudo apt-get` requires a
password that is not available in this environment). A set of pre-existing
libraries found at `~/.opencode/pwlibs/usr/lib/x86_64-linux-gnu/` (42+ shared
libraries, including the ones above) works when added to the loader path:

    export LD_LIBRARY_PATH=$HOME/.opencode/pwlibs/usr/lib/x86_64-linux-gnu:$HOME/.opencode/pwlibs/usr/lib/x86_64-linux-gnu/gbm
    .venv/bin/python tools/record_benign.py --sessions 20 --out data/benign-browse-v0/candidates.jsonl

## Reproducibility caveat

**The recording is not reproducible without those libraries.** On a machine
without `~/.opencode/pwlibs` (and without sudo to install the Chromium
dependencies), `tools/record_benign.py` will fail at browser launch. The
frozen dataset itself is unaffected (samples are plain JSON), but re-recording
a v1 corpus on another host requires either the same library set or a
environment with the Playwright system dependencies installed.
