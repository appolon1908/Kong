#!/usr/bin/env python3
import os,re,sys
repo=os.environ.get("GITHUB_REPOSITORY","").split("/")[-1]
head=sys.argv[1]
base=sys.argv[2]
maps={
"Middleware-":("mw","testing","staging","production/environment"),
"Kong":("kg","testing","staging","production"),
"Caddy":("cd","testing","staging","production"),
"Keycloak":("kc","testing","staging","production"),
"Codestra-OpenBao":("ob","testing","staging","production"),
"N8N":("n8","testing/environment","staging","production/environment"),
}
if repo not in maps:
    print("PROMOTION_ALLOWED=NO unknown_repository")
    raise SystemExit(2)
prefix,testing,staging,production=maps[repo]
section_re=re.compile(rf"^{re.escape(prefix)}-[0-9]{{2}}-[a-z0-9][a-z0-9-]*$")
ok=False
reason=""
if head=="governance/agent-hierarchy-main-v1" and base=="main":
    print("PROMOTION_ALLOWED=YES governance_main_bootstrap")
    raise SystemExit(0)
if head=="governance/agent-hierarchy-v1" and base=="development":
    print("PROMOTION_ALLOWED=YES governance_development_bootstrap")
    raise SystemExit(0)
if head.startswith("subsection/"):
    name=head.split("/",1)[1]
    section=name.split("--",1)[0]
    ok=("--" in name and base==section and bool(section_re.match(section)))
    reason="subsection_to_parent_section"
elif section_re.match(head):
    ok=(base=="development")
    reason="section_to_development"
elif head=="development":
    ok=(base==testing)
    reason="development_to_testing"
elif head==testing:
    ok=(base==staging)
    reason="testing_to_staging"
elif head==staging:
    ok=(base==production)
    reason="staging_to_production"
elif head==production:
    ok=(base=="main")
    reason="production_to_main"
if ok:
    print("PROMOTION_ALLOWED=YES",reason)
    raise SystemExit(0)
print(f"PROMOTION_ALLOWED=NO head={head} base={base} expected_chain=subsection->section->development->{testing}->{staging}->{production}->main")
raise SystemExit(1)
