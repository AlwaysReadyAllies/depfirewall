"""SARIF 2.1.0 output for depfirewall — findings land in the GitHub Security tab / any SARIF consumer.

Upload from a workflow with `github/codeql-action/upload-sarif@v3`. Findings are about a dependency
(not a source line), so they use logicalLocations naming the package. Only failing/warning verdicts
become results — SAFE is not a finding.
"""
from __future__ import annotations

# verdict → (SARIF level, GitHub security-severity score)
_VERDICT = {
    "UNKNOWN":    ("error", "8.0"),   # hallucinated / slopsquat — nonexistent package
    "VULNERABLE": ("error", None),    # score from the CVE's CVSS when present
    "DEPRECATED": ("warning", "3.0"),
    "STALE":      ("note", "1.0"),
    "NEW":        ("note", "0.0"),
}
INFO_URI = "https://github.com/AlwaysReadyAllies/depfirewall"


def to_sarif(results: list[dict], *, version: str = "1.0.0") -> dict:
    rules: dict[str, dict] = {}
    sarif_results = []
    for r in results:
        verdict = r["verdict"]
        if verdict not in _VERDICT:            # SAFE and anything benign is not a finding
            continue
        level, default_score = _VERDICT[verdict]
        score = str(r["severity"]) if (verdict == "VULNERABLE" and r.get("severity")) else default_score
        rules.setdefault(verdict, {
            "id": verdict, "name": verdict.title(),
            "shortDescription": {"text": {"UNKNOWN": "Dependency exists on no registry (hallucination/slopsquat)",
                                          "VULNERABLE": "Dependency has known vulnerabilities"}.get(verdict, verdict)},
            "properties": {"tags": ["security", "supply-chain"]},
        })
        dep = f"{r['dep']}@{r.get('version') or 'latest'}"
        props = {"ecosystem": r["system"], "source": r.get("source", "deps.dev")}
        if score is not None:
            props["security-severity"] = score
        sarif_results.append({
            "ruleId": verdict,
            "level": level,
            "message": {"text": f"{r['system']} dependency `{dep}`: {r.get('reason', verdict)}"},
            "locations": [{"logicalLocations": [
                {"name": r["dep"], "fullyQualifiedName": f"{r['system']}:{dep}", "kind": "package"}]}],
            "properties": props,
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "depfirewall", "version": version, "informationUri": INFO_URI,
                                "rules": list(rules.values())}},
            "results": sarif_results,
        }],
    }
