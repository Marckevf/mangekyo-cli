import json, re
from pathlib import Path

cache = Path("mitre_attack_cache.json")
with open(cache, encoding="utf-8") as f:
    data = json.load(f)
bundle = data.get("bundle", data)

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
hits = {}
for obj in bundle.get("objects", []):
    if obj.get("type") != "attack-pattern": continue
    if obj.get("revoked") or obj.get("x_mitre_deprecated"): continue
    desc = obj.get("description", "")
    found = CVE_RE.findall(desc)
    if found:
        attack_id = next((r.get("external_id","") for r in obj.get("external_references",[]) if r.get("source_name")=="mitre-attack"), "")
        name = obj.get("name","")
        for cve in found:
            hits.setdefault(cve.upper(), []).append(attack_id + " " + name)

print("Distinct CVEs in ATT&CK descriptions: " + str(len(hits)))
for cve, techs in sorted(hits.items()):
    print("  " + cve + " -> " + str(techs))

targets = ["CVE-2021-40438","CVE-2023-44487","CVE-2018-15473","CVE-2021-41773"]
print("\nSearching all bundle text for test CVEs:")
found_any = False
for obj in bundle.get("objects",[]):
    raw = json.dumps(obj)
    for t in targets:
        if t in raw:
            found_any = True
            print("  FOUND " + t + " in type=" + obj.get("type","") + " name=" + obj.get("name","")[:50])
if not found_any:
    print("  (test CVEs not found anywhere in the bundle)")
