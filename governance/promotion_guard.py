#!/usr/bin/env python3
import argparse, fnmatch, json, os, pathlib
p=argparse.ArgumentParser()
p.add_argument("--head")
p.add_argument("--base")
a=p.parse_args()
head=a.head or os.environ.get("GITHUB_HEAD_REF","")
base=a.base or os.environ.get("GITHUB_BASE_REF","")
policy=json.loads(pathlib.Path("governance/promotion-policy.json").read_text())
ok=False
for rule in policy["accepted_promotions"]:
    if fnmatch.fnmatch(head,rule["head"]) and fnmatch.fnmatch(base,rule["base"]):
        ok=True
        if rule.get("relation")=="matching-section-required":
            ok=(head.startswith("subsection/") and base.startswith("section/") and head[len("subsection/"):].split("--",1)[0]==base[len("section/"):])
        if ok:
            break
if not ok:
    print(f"PROMOTION_GUARD=BLOCK head={head} base={base}")
    raise SystemExit(1)
print(f"PROMOTION_GUARD=PASS head={head} base={base}")
