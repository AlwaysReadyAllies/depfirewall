"""Markdown verdict table for the PR comment + step summary."""

MARKER = "<!-- depfirewall-verdict -->"

ICON = {"VULNERABLE": "🔴", "UNKNOWN": "⛔", "NEW": "🆕", "DEPRECATED": "🟠",
        "STALE": "🟡", "SAFE": "🟢"}


def table(results, overall, mode, purchase_note=""):
    lines = [
        MARKER,
        f"## {'❌' if overall == 'FAIL' else '✅'} Dependency Firewall — {overall}",
        "",
        f"Checked **{len(results)}** {'changed' if mode == 'diff' else ''} dependencies "
        f"({'PR diff' if mode == 'diff' else 'full manifest scan'}).",
        "",
    ]
    if results:
        lines += [
            "| | Dependency | Verdict | Severity | Why |",
            "|---|---|---|---|---|",
        ]
        order = {"VULNERABLE": 0, "UNKNOWN": 1, "NEW": 2, "DEPRECATED": 3, "STALE": 4, "SAFE": 5}
        for r in sorted(results, key=lambda r: order.get(r["verdict"], 9)):
            sev = f"CVSS {r['severity']}" if r.get("severity") else "—"
            dep = f"`{r['name']}@{r['version'] or 'latest'}` ({r['system']})"
            reason = (r.get("reason") or "no known issues").replace("|", "\\|")
            lines.append(f"| {ICON.get(r['verdict'], '?')} | {dep} | **{r['verdict']}** | {sev} | {reason} |")
        lines.append("")
        for r in results:
            for adv in r.get("advisories", [])[:5]:
                lines.append(f"> `{r['name']}` ↳ {adv['cve']} (CVSS {adv['cvss']}) {adv['title']}")
    if purchase_note:
        lines += ["", purchase_note]
    lines += ["", "<sub>🛡️ [depfirewall](https://github.com/alwaysreadyallies/depfirewall) — "
              "blocks hallucinated & vulnerable dependencies before merge. "
              "UNKNOWN = the package does not exist on any registry (AI hallucination / slopsquat bait).</sub>"]
    return "\n".join(lines)
