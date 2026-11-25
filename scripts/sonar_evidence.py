#!/usr/bin/env python3
"""Save sanitized SonarQube API evidence. The token is read from SONAR_TOKEN and never written."""
import json
import os
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "evidence" / "sonarqube"
OUT.mkdir(parents=True, exist_ok=True)
HOST = os.environ.get("SONAR_HOST_URL", "http://localhost:9000").rstrip("/")
TOKEN = os.environ.get("SONAR_TOKEN", "")
PROJECT = "lab9b-aes-file-demo"
if not TOKEN:
    raise SystemExit("ERROR: set SONAR_TOKEN in the environment before running this script.")

def get(path):
    req = urllib.request.Request(HOST + path, headers={"Authorization": "Bearer " + TOKEN})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))

def save(name, obj):
    (OUT / name).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return obj

status = save("server-status.json", get("/api/system/status"))
profiles = save("quality-profiles.json", get(f"/api/qualityprofiles/search?project={PROJECT}"))
issues = save("issues.json", get(f"/api/issues/search?componentKeys={PROJECT}&resolved=false&ps=100&p=1"))
hotspots = save("hotspots.json", get(f"/api/hotspots/search?project={PROJECT}&ps=100&p=1"))

metric_names = ["ncloc", "code_smells", "vulnerabilities", "security_hotspots",
                "bugs", "comment_lines", "complexity", "cognitive_complexity",
                "security_rating", "reliability_rating", "maintainability_rating"]
metrics = {}
for name in metric_names:
    try:
        obj = get(f"/api/measures/component?component={PROJECT}&metricKeys={name}")
        vals = obj.get("component", {}).get("measures", [])
        if vals:
            metrics[name] = vals[0].get("value")
    except Exception:
        pass
save("measures.json", {"component": PROJECT, "metrics": metrics})

rule_details = []
for issue in issues.get("issues", []):
    try:
        rule_details.append(save(f"rule-{issue['rule'].replace(':', '_')}.json",
                                 get(f"/api/rules/show?key={urllib.parse.quote(issue['rule'], safe='')}")))
    except Exception as exc:
        rule_details.append({"rule": issue["rule"], "error": str(exc)})

active = [p for p in profiles.get("profiles", [])
          if p.get("language") == "py" and (p.get("isDefault") or p.get("isActive"))]
profile_name = active[0].get("name") if active else "not reported"
scanner_log = (OUT / "scanner-output.txt").read_text(encoding="utf-16")
for line in scanner_log.splitlines():
    if "Quality profile for py:" in line:
        profile_name = line.split("Quality profile for py:", 1)[1].strip()
        break

lines = [
    "SonarQube API-derived analysis evidence",
    f"Server URL: {HOST}",
    f"SonarQube version: {status.get('version')}",
    f"Server ID: {status.get('id')}",
    f"Status: {status.get('status')}",
    f"Project key: {PROJECT}",
    f"Active Python quality profile: {profile_name}",
    "",
    "Measures:",
]
lines += [f"  {k} = {v}" for k, v in metrics.items()]
lines += ["", f"Open issues: {issues.get('paging', {}).get('total', len(issues.get('issues', [])))}"]
for issue in issues.get("issues", []):
    lines += [
        f"  [{issue.get('type')} / {issue.get('severity')}] {issue.get('rule')}",
        f"    location: {issue.get('component')}:{issue.get('line')}",
        f"    message: {issue.get('message')}",
        f"    impact: {', '.join(i.get('softwareQuality','') + '=' + i.get('severity','') for i in issue.get('impacts', []))}",
    ]
lines += ["", f"Security hotspots: {hotspots.get('paging', {}).get('total', len(hotspots.get('hotspots', [])))}"]
for hot in hotspots.get("hotspots", []):
    lines.append(f"  {hot.get('ruleKey')} {hot.get('component')}:{hot.get('line')} status={hot.get('status')}")
lines += ["", "Token was supplied via SONAR_TOKEN and is not present in any saved file."]
(OUT / "analysis-summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
print("SONAR_EVIDENCE_WRITTEN", OUT)
print("issues", len(issues.get("issues", [])), "hotspots", len(hotspots.get("hotspots", [])), "metrics", len(metrics))
