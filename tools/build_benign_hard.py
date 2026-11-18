"""Hand-authored hard benign inputs (stress testing, NOT natural traffic).

About 150 legitimate inputs in categories that look attack-adjacent:
natural-language search terms containing SQL/shell/HTML words, names with
apostrophes and unicode, passwords with special characters, URLs and email
addresses inside text, long review-style sentences, and ordinary code-like
text a developer might type.

Same two injection points as the attack corpus:
  (a) GET  /rest/products/search?q=<urllib.parse.quote(value, safe='')>
  (b) POST /rest/user/login, body json.dumps({"email": ..., "password": ...})
      with the value in "email" or "password" (alternating).

source: "hand-authored-hard-benign@<git commit>".
Output: data/benign-hard-v0/candidates.jsonl

WARNING (also in the dataset README): this set intentionally overstates the
false positive rate on natural traffic; never merge it with natural benign
traffic into one rate (standing rule 14).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import urllib.parse
from pathlib import Path

HARD_VALUES = [
    # natural-language search terms containing SQL/shell/HTML words
    "how to union two tables in my report",
    "select the best juice for breakfast",
    "drop the price a little please",
    "script for a nice birthday party",
    "exec summary of our product line",
    "whoami in the customer service team",
    "products that cost 5 > 3 stars",
    "union of apple and banana flavors",
    "select * from my shopping list",
    "drop shipping options for juice",
    "is there a script for the advert",
    "executive (exec) summary juice report",
    "whoami: the story of a smoothie",
    "5 > 3 so I pick the larger bottle",
    "select juice, pay, leave",
    "union members get a discount",
    "drop by our store for fresh juice",
    "script writing workshop flyer",
    "exec board meeting minutes",
    "select your delivery slot",
    # names with apostrophes and unicode
    "O'Brien",
    "D'Angelo",
    "Müller",
    "José García",
    "Ştefan Bălăcescu",
    " François",
    "Smörgåsbord Ltd",
    "O'Neill & Sons",
    "Žiga Novak",
    "Åse Bergström",
    "Conan O'Brien Jr.",
    "L'Orange Aroma",
    "Père Noël Juice",
    "Núñez Family",
    "Mc'Donald Farms",
    # passwords with special characters (legitimate strong passwords)
    "C0rrect!Horse-Battery#Staple",
    "tr0ub4dor&3",
    "P@ssw0rd!2024#secure",
    "letmein$Please42",
    "¡Señorita!Clave#1",
    "my#dog+has$fleas",
    "correct-horse_battery=staple",
    "Pa$$w0rd!with$double$$",
    "ünicode&passwörd!",
    "1am@w0rk^right*now&ok",
    # URLs and email addresses inside text
    "read more at https://example.com/juice?id=42",
    "contact me via mailto:support@example.org",
    "our site moved to https://owasp-juice.shop",
    "email me at first.last@example.com please",
    "see http://localhost:3000 for the demo",
    "follow https://example.com/path?q=apple&sort=price",
    "ftp://files.example.com/catalog.pdf is outdated",
    "my homepage is https://müller.example.de",
    "ping me at juice+tag@example.com",
    "docs live at https://docs.example.com/v2/#section-3",
    # long review-style sentences
    "I bought this for my daughter's birthday, and she absolutely loves it; "
    "the bottle arrived intact and the juice tasted fresh.",
    "The delivery took three days longer than promised, but customer service "
    "answered within an hour and refunded the shipping cost.",
    "Great value: five liters of apple juice for the price of four, and the "
    "bottles are recyclable, which matters to our family.",
    "My son is allergic to nuts and the label clearly says which flavors are "
    "safe, so I will keep buying this brand every month.",
    "The flavor is fine but the cap leaks if you don't tighten it all the way; "
    "I lost half a bottle in my backpack last week.",
    "We served this smoothie at a kids' party and every single glass was empty "
    "within minutes, so I'm ordering another crate today.",
    "It's okay, nothing special: the taste is a bit sweet for my liking, but "
    "my wife and my brother-in-law both liked it a lot.",
    "After trying six different brands, this is the only one that doesn't "
    "taste like artificial sweetener; keep the recipe unchanged, please.",
    "The box looked damaged when it arrived, yet the bottles inside were fine; "
    "still, please use more padding next time.",
    "I use the 1000ml bottles for my morning run; they fit the holder and "
    "don't spill, unlike the ones from the other shop.",
    # ordinary code-like text a developer might type
    "for (let i = 0; i < items.length; i++) { cart.push(items[i]); }",
    "SELECT name FROM products WHERE price < 10",
    "curl -X POST http://localhost:3000/rest/user/login",
    "git commit -m 'fix: cart total rounding'",
    "if (user && user.role === 'admin') { allow(); }",
    "docker compose -f deploy/compose.yml up -d",
    "print(f\"total: {sum(prices):.2f}\")",
    "UPDATE inventory SET stock = stock - 1",
    "x = 5 > 3 ? 'yes' : 'no'",
    "TODO: refactor the search endpoint (q param)",
    "SELECT * FROM users; -- just reading the schema docs",
    "while true; do echo waiting; sleep 1; done",
    "npm install --save-dev @types/node",
    "ls -la /var/log | grep nginx",
    "echo $HOME && whoami # sanity check",
    # more natural-language with trigger words
    "apple juice or apple cider, which do you select?",
    "the union of flavors in this smoothie is great",
    "please drop the price on the 1000ml bottle",
    "my script for the juice bar opening",
    "exec decision: we buy the whole crate",
    "whoami? just a smoothie enthusiast",
    "the label says 5 > 3 servings per bottle",
    "select delivery, then drop the cart",
    "union station is where I first tried this",
    "script kiddies can't make good juice",
]


def main() -> int:
    ap = argparse.ArgumentParser(description="Build hard benign candidates (hand-authored).")
    ap.add_argument("--out", default="data/benign-hard-v0/candidates.jsonl")
    args = ap.parse_args()

    commit = None
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True,
                                text=True, check=True).stdout.strip()
    except Exception:
        commit = "unknown"

    samples = []
    for i, value in enumerate(HARD_VALUES):
        sha8 = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
        # (a) GET search
        samples.append({
            "id": f"hardben-{sha8}-q",
            "label": "benign",
            "family": "benign",
            "source": f"hand-authored-hard-benign@{commit}",
            "method": "GET",
            "path": "/rest/products/search",
            "query": "q=" + urllib.parse.quote(value, safe=""),
            "body": "",
            "content_type": "",
        })
        # (b) POST login, alternating the value between "email" and "password"
        if i % 2 == 0:
            creds = {"email": value, "password": "x"}
        else:
            creds = {"email": f"user{i}@example.com", "password": value}
        samples.append({
            "id": f"hardben-{sha8}-login",
            "label": "benign",
            "family": "benign",
            "source": f"hand-authored-hard-benign@{commit}",
            "method": "POST",
            "path": "/rest/user/login",
            "query": "",
            "body": json.dumps(creds),
            "content_type": "application/json",
        })

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        for s in samples:
            fh.write(json.dumps(s, ensure_ascii=False) + "\n")
    print(f"{len(HARD_VALUES)} hard values -> {len(samples)} samples -> {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
