"""Record natural benign traffic by driving the REAL Juice Shop UI with Playwright.

The browser records through the TARGET directly (no WAF) so blocks cannot alter
the recording. Every request the browser makes is captured: method, raw path,
raw query, headers, raw body, content-type. Requests are then converted to
benign samples (label "benign", family "benign"), keeping recorded headers
except Host, Content-Length, Connection and Accept-Encoding, and deduped by
content hash.

Sessions (default 20, each seeded by its index):
  - anonymous (even indices): open home, wait for products, open 5 product
    dialogs, run 10 searches using terms derived from the app's own product
    catalog (read from the rendered page, not from API calls by us).
  - registered (odd indices): register a user with deterministic seeded name,
    email and a punctuation-rich password; log in; browse; add 2 products to
    the basket; open the basket and the profile; post one product review using
    a sentence from a hand-written list of 20 plain-English sentences (some
    with apostrophes and commas).

Run:  LD_LIBRARY_PATH=<playwright libs> .venv/bin/python tools/record_benign.py \
          --base-url http://localhost:13000 --sessions 20 \
          --out data/benign-browse-v0/candidates.jsonl

step-07 additions (all additive; without --extra-flows the tool behaves
exactly as it did for v0):
  --start-index N   first session index (default 0). Sessions are seeded by
                    their index; benign-browse-v1 uses --start-index 1000.
  --extra-flows     enable the v1 flows for registered sessions: review
                    edit, basket quantity change, basket item removal,
                    language switch, log out and back in; also dismiss the
                    fruit-cookie banner (it intercepts clicks otherwise).
                    Always writes <out-dir>/sessions.jsonl mapping each
                    sample id to the sorted session indices that produced
                    it (dedupe must not erase the session dimension).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import urllib.parse
from pathlib import Path

from playwright.sync_api import sync_playwright

REVIEW_SENTENCES = [
    "I bought this for my daughter's birthday and she loves it.",
    "Good value for the money, arrived on time and well packed.",
    "The packaging was damaged, but the product itself works fine.",
    "Would buy again; shipping was faster than expected.",
    "My son uses it every day, it's holding up well so far.",
    "It's okay, nothing special, does what it says on the box.",
    "Great quality for the price, I was pleasantly surprised.",
    "Broke after two weeks, customer service was helpful though.",
    "Perfect gift for a coffee-loving friend of mine.",
    "The color looks different in person, still nice though.",
    "Works as described, setup took me about ten minutes.",
    "I wish it came in other sizes, but overall I'm happy.",
    "Solid little gadget, my whole family uses it now.",
    "Not worth the price in my opinion, but the kids like it.",
    "Exactly what I ordered, no complaints at all.",
    "Arrived early, well made, and easy to clean.",
    "It stopped working after a month, very disappointed.",
    "Better than the one I had before, much sturdier.",
    "Nice addition to my desk setup at the office.",
    "My wife and I both use it daily, great purchase.",
]

FIRST_NAMES = ["alex", "blake", "casey", "devon", "emery", "frankie", "gale",
               "harper", "indigo", "jules", "kai", "logan", "morgan", "noel",
               "oakley", "payton", "quinn", "riley", "sage", "taylor"]


def content_hash(method: str, path: str, query: str, content_type: str, body: str) -> str:
    raw = "\x00".join([method.upper(), path, query, content_type, body])
    return hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()


class Recorder:
    def __init__(self):
        self.captured: list[dict] = []
        self.current_session: int | None = None  # set by main() per session

    def on_request(self, request):
        try:
            parts = urllib.parse.urlsplit(request.url)
            if parts.hostname is None:
                return
            if request.method.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                return
            headers = dict(request.headers)  # lowercase keys, as sent by the browser
            body = request.post_data if request.post_data is not None else ""
            self.captured.append({
                "method": request.method.upper(),
                "path": parts.path or "/",
                "query": parts.query,
                "headers": headers,
                "body": body,
                "content_type": headers.get("content-type", ""),
                "session": self.current_session,
            })
        except Exception as exc:  # a failed capture must not kill the session
            print(f"record_benign: capture error: {exc}", file=sys.stderr)


def _dismiss_banner(page):
    try:
        page.get_by_role("button", name="Close Welcome Banner").click(timeout=4000)
        page.wait_for_timeout(400)
    except Exception:
        pass


def _dismiss_cookie_banner(page):
    """v1 only: the fruit-cookie banner intercepts clicks until dismissed."""
    for label in ("Me want it!", "Dismiss"):
        try:
            page.get_by_role("button", name=label).first.click(timeout=2000)
            page.wait_for_timeout(300)
            return
        except Exception:
            continue


def _wait_products(page, timeout=15000):
    page.wait_for_selector(".product", timeout=timeout)
    _dismiss_banner(page)


def _search_terms(page, rng: random.Random, count: int) -> list[str]:
    """Derive search terms from product names rendered on the page."""
    names = page.eval_on_selector_all(
        ".product .name", "els => els.map(e => e.textContent.trim())")
    terms: list[str] = []
    for name in names:
        words = [w for w in name.split() if w.isalpha() and len(w) > 2]
        if words:
            terms.append(words[0])            # single word from the product name
            terms.append(" ".join(words[:2]))  # first two words
    rng.shuffle(terms)
    seen, picked = set(), []
    for t in terms:
        if t.lower() not in seen:
            seen.add(t.lower())
            picked.append(t)
        if len(picked) == count:
            break
    while len(picked) < count:  # fall back to catalog words if not enough
        picked.append(rng.choice(names).split()[0])
    return picked


def _do_search(page, term):
    box = page.query_selector("input[type=text]")
    box.fill(term)
    box.press("Enter")
    page.wait_for_timeout(900)
    page.wait_for_timeout(300)


def _open_product_dialog(page, index):
    tiles = page.query_selector_all(".product")
    if index < len(tiles):
        tiles[index].click()
        page.wait_for_timeout(1000)
        page.keyboard.press("Escape")  # close dialog
        page.wait_for_timeout(500)


# ---- v1-only flows (extra_flows=True); each is best-effort and reported ----

def _edit_review(page, sentence, report):
    """Edit the just-posted review via its Edit Review button."""
    try:
        page.get_by_role("button", name="Edit Review").first.click(timeout=4000)
        page.wait_for_timeout(800)
        ta = page.query_selector("mat-dialog-container textarea") or page.query_selector("textarea")
        if not (ta and ta.is_visible()):
            report["steps"].append("review-edit FAILED: textarea not visible")
            return
        ta.fill(sentence + " Edited after posting.")
        page.get_by_role("button", name="Submit").first.click(timeout=4000)
        page.wait_for_timeout(1200)
        report["steps"].append("review-edit")
    except Exception as exc:
        report["steps"].append(f"review-edit FAILED: {exc.__class__.__name__}")


def _basket_quantity_change(page, report):
    """Click the first basket row's plus button once (PUT /api/BasketItems/:id)."""
    try:
        page.goto(page.url.split("#")[0] + "/#/basket", wait_until="domcontentloaded", timeout=30000)
        page.wait_for_timeout(1500)
        plus = page.query_selector("button:has(svg.fa-plus-square)")
        if not plus:
            report["steps"].append("basket-qty FAILED: plus button not found")
            return
        plus.click()
        page.wait_for_timeout(1000)
        report["steps"].append("basket-qty")
    except Exception as exc:
        report["steps"].append(f"basket-qty FAILED: {exc.__class__.__name__}")


def _basket_item_removal(page, report):
    """Click the first basket row's trash button (DELETE /api/BasketItems/:id)."""
    try:
        trash = page.query_selector("button:has(svg.fa-trash-alt)")
        if not trash:
            report["steps"].append("basket-remove FAILED: trash button not found")
            return
        trash.click()
        page.wait_for_timeout(1000)
        report["steps"].append("basket-remove")
    except Exception as exc:
        report["steps"].append(f"basket-remove FAILED: {exc.__class__.__name__}")


def _language_switch(page, base_url, report):
    """Switch language away from English and back (GET /assets/i18n/*)."""
    try:
        page.goto(base_url + "/", wait_until="domcontentloaded", timeout=30000)
        page.wait_for_timeout(800)
        page.get_by_role("button", name="Language selection menu").click(timeout=4000)
        page.wait_for_timeout(600)
        items = page.query_selector_all("button[role='menuitem'], .mat-menu-content button")
        target = None
        for it in items:
            if it.text_content().strip() not in ("English", "", None) and "English" not in it.text_content():
                target = it
                break
        if not target:
            report["steps"].append("language FAILED: no non-English menu item")
            return
        target.click()
        page.wait_for_timeout(1200)
        # switch back to English
        page.get_by_role("button", name="Language selection menu").click(timeout=4000)
        page.wait_for_timeout(600)
        for it in page.query_selector_all("button[role='menuitem'], .mat-menu-content button"):
            if "English" in (it.text_content() or ""):
                it.click()
                break
        page.wait_for_timeout(1000)
        report["steps"].append("language-switch")
    except Exception as exc:
        report["steps"].append(f"language FAILED: {exc.__class__.__name__}")


def _logout_and_login(page, base_url, email, password, report):
    """Log out via the account menu, then log in again with the same user."""
    try:
        page.get_by_role("button", name="Show/hide account menu").click(timeout=4000)
        page.wait_for_timeout(600)
        page.get_by_role("button", name="Log out").first.click(timeout=4000)
        page.wait_for_timeout(1200)
        report["steps"].append("logout")
    except Exception as exc:
        report["steps"].append(f"logout FAILED: {exc.__class__.__name__}")
        return
    try:
        page.goto(base_url + "/#/login", wait_until="domcontentloaded", timeout=30000)
        page.wait_for_selector("#email", timeout=15000)
        page.fill("#email", email)
        page.fill("#password", password)
        page.click("#loginButton")
        page.wait_for_timeout(1500)
        report["steps"].append("login-again")
    except Exception as exc:
        report["steps"].append(f"login-again FAILED: {exc.__class__.__name__}")


def run_session(page, recorder: Recorder, index: int, base_url: str,
                extra_flows: bool = False) -> dict:
    """Drive one session. Returns a report of which steps ran."""
    rng = random.Random(index)
    report = {"session": index, "steps": []}
    registered = index % 2 == 1

    page.goto(base_url + "/", wait_until="domcontentloaded", timeout=30000)
    try:
        _wait_products(page)
        report["steps"].append("home+products")
    except Exception as exc:
        report["steps"].append(f"home+products FAILED: {exc.__class__.__name__}")
        return report

    if not registered:
        # 5 product dialogs
        for i in rng.sample(range(min(8, 12)), 5):
            try:
                _open_product_dialog(page, i)
                report["steps"].append(f"dialog-{i}")
            except Exception as exc:
                report["steps"].append(f"dialog-{i} FAILED: {exc.__class__.__name__}")
        # 10 searches from the catalog
        for term in _search_terms(page, rng, 10):
            try:
                _do_search(page, term)
                report["steps"].append(f"search:{term}")
            except Exception as exc:
                report["steps"].append(f"search FAILED: {exc.__class__.__name__}")
        return report

    # ---- registered session ----
    name = rng.choice(FIRST_NAMES) + str(index)
    email = f"{name}@example.com"
    password = f"C0rrect!Horse-Battery#{index:02d}"
    try:
        page.goto(base_url + "/#/register", wait_until="domcontentloaded", timeout=30000)
        page.wait_for_selector("#emailControl", timeout=15000)
        page.fill("#emailControl", email)
        page.fill("#passwordControl", password)
        page.fill("#repeatPasswordControl", password)
        # pick the first enabled security question
        page.click("#securityQuestionControl mat-select, #securityQuestionControl")
        page.wait_for_timeout(600)
        options = page.query_selector_all("mat-option")
        if options:
            options[0].click()
        page.fill("#securityAnswerControl", "Sesame")
        page.click("#registerButton")
        page.wait_for_timeout(1500)
        report["steps"].append(f"register:{email}")
    except Exception as exc:
        report["steps"].append(f"register FAILED: {exc.__class__.__name__}")

    try:
        page.goto(base_url + "/#/login", wait_until="domcontentloaded", timeout=30000)
        page.wait_for_selector("#email", timeout=15000)
        page.fill("#email", email)
        page.fill("#password", password)
        page.click("#loginButton")
        page.wait_for_timeout(1500)
        report["steps"].append("login")
    except Exception as exc:
        report["steps"].append(f"login FAILED: {exc.__class__.__name__}")

    # browse: 2 product dialogs
    page.goto(base_url + "/#/search", wait_until="domcontentloaded", timeout=30000)
    try:
        _wait_products(page)
    except Exception:
        page.goto(base_url + "/", wait_until="domcontentloaded", timeout=30000)
        try:
            _wait_products(page)
        except Exception as exc:
            report["steps"].append(f"browse FAILED: {exc.__class__.__name__}")
            return report

    basket_added = 0
    for i in rng.sample(range(min(10, 20)), 2):
        try:
            btn = page.query_selector_all("button[aria-label='Add to Basket']")
            if len(btn) > i:
                btn[i].click()
                page.wait_for_timeout(600)
                basket_added += 1
                report["steps"].append(f"basket-add-{i}")
        except Exception as exc:
            report["steps"].append(f"basket-add FAILED: {exc.__class__.__name__}")

    for route, label in (("/#/basket", "basket"), ("/#/profile", "profile")):
        try:
            page.goto(base_url + route, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_timeout(1200)
            report["steps"].append(label)
        except Exception as exc:
            report["steps"].append(f"{label} FAILED: {exc.__class__.__name__}")

    # one product review with a sentence from the hand-written list
    sentence = REVIEW_SENTENCES[index % len(REVIEW_SENTENCES)]
    try:
        page.goto(base_url + "/#/search", wait_until="domcontentloaded", timeout=30000)
        _wait_products(page)
        page.query_selector_all(".product")[0].click()
        page.wait_for_timeout(1500)
        page.click("mat-expansion-panel-header")  # expand the Reviews panel
        page.wait_for_timeout(1200)
        ta = page.query_selector("textarea")
        if ta and ta.is_visible():
            ta.fill(sentence)
            page.get_by_text("Submit", exact=True).click()
            page.wait_for_timeout(1500)
            report["steps"].append(f"review:{sentence[:30]}...")
        else:
            report["steps"].append("review FAILED: textarea not visible")
    except Exception as exc:
        report["steps"].append(f"review FAILED: {exc.__class__.__name__}")

    # ---- v1-only extra flows (registered sessions) ----
    if extra_flows:
        _edit_review(page, sentence, report)
        _basket_quantity_change(page, report)
        _basket_item_removal(page, report)
        _language_switch(page, base_url, report)
        _logout_and_login(page, base_url, email, password, report)

    return report


def build_session_map(captured: list[dict], samples: list[dict]) -> list[dict]:
    """Map each sample id to the sorted session indices that produced it.

    The dedupe keeps only the first occurrence's request fields, but the
    session dimension must survive: every captured request's session index
    contributes to its content hash's row.
    """
    id_by_hash = {content_hash(s["method"], s["path"], s["query"],
                               s["content_type"], s["body"]): s["id"]
                  for s in samples}
    sessions: dict[str, set[int]] = {}
    for cap in captured:
        ch = content_hash(cap["method"], cap["path"], cap["query"],
                          cap["content_type"], cap["body"])
        sid = id_by_hash.get(ch)
        if sid is None or cap.get("session") is None:
            continue
        sessions.setdefault(sid, set()).add(cap["session"])
    return [{"id": sid, "sessions": sorted(sessions[sid])}
            for sid in sorted(sessions)]


def main() -> int:
    ap = argparse.ArgumentParser(description="Record benign browsing sessions via Playwright.")
    ap.add_argument("--base-url", default="http://localhost:13000")
    ap.add_argument("--sessions", type=int, default=20)
    ap.add_argument("--start-index", type=int, default=0,
                    help="first session index; sessions are seeded by index (v1 uses 1000)")
    ap.add_argument("--extra-flows", action="store_true",
                    help="enable v1 flows (review edit, basket qty/remove, language, logout+login) "
                         "and dismiss the cookie banner; also writes sessions.jsonl")
    ap.add_argument("--out", default="data/benign-browse-v0/candidates.jsonl")
    ap.add_argument("--headless", default="true")
    args = ap.parse_args()

    commit = None
    try:
        import subprocess
        commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True,
                                text=True, check=True).stdout.strip()
    except Exception:
        commit = "unknown"

    import playwright
    pw_version = playwright.__version__ if hasattr(playwright, "__version__") else "unknown"

    recorder = Recorder()
    reports = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=args.headless != "false")
        context = browser.new_context()
        for index in range(args.start_index, args.start_index + args.sessions):
            # fresh page per session; cookies persist within a session only
            recorder.current_session = index
            page = context.new_page()
            if args.extra_flows:
                page.goto(args.base_url + "/", wait_until="domcontentloaded", timeout=30000)
                _dismiss_cookie_banner(page)
            page.on("request", recorder.on_request)
            reports.append(run_session(page, recorder, index, args.base_url,
                                       extra_flows=args.extra_flows))
            page.close()
        browser.close()

    failed = [r for r in reports if any("FAILED" in s for s in r["steps"])]
    print(f"sessions: {len(reports)}, sessions with failed steps: {len(failed)}", file=sys.stderr)
    for r in reports:
        print(f"  session {r['session']}: {', '.join(r['steps'])}", file=sys.stderr)

    # convert to samples; dedupe by content hash; report counts
    before = len(recorder.captured)
    seen: set[str] = set()
    samples = []
    for cap in recorder.captured:
        ch = content_hash(cap["method"], cap["path"], cap["query"],
                          cap["content_type"], cap["body"])
        if ch in seen:
            continue
        seen.add(ch)
        headers = {k: v for k, v in cap["headers"].items()
                   if k.lower() not in ("host", "content-length", "connection", "accept-encoding")}
        samples.append({
            "id": f"browse-{ch[:12]}",
            "label": "benign",
            "family": "benign",
            "source": f"playwright-{pw_version}:tools/record_benign.py@{commit}",
            "method": cap["method"],
            "path": cap["path"],
            "query": cap["query"],
            "body": cap["body"],
            "content_type": cap["content_type"],
            "headers": headers,
        })
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        for s in samples:
            fh.write(json.dumps(s, ensure_ascii=False) + "\n")
    # session map: sample id -> sorted session indices that produced it
    session_rows = build_session_map(recorder.captured, samples)
    with open(out.parent / "sessions.jsonl", "w", encoding="utf-8") as fh:
        for row in session_rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"captured {before} requests -> {len(samples)} samples after dedupe "
          f"({len(session_rows)} rows in sessions.jsonl) -> {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
