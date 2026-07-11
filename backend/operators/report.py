"""
Report Operator — Phase 4 of the Swarm pipeline.
Compiles all findings into a structured report and saves it.
"""

from datetime import datetime
from .base import BaseOperator


class ReportOperator(BaseOperator):
    """Final report generation: compiles all findings into a comprehensive report."""

    def __init__(self):
        super().__init__("report", "📄 Report Generator")

    async def run(self, swarm) -> list:
        self.status = "running"
        target = swarm.target

        # Gather all findings
        all_findings = swarm.get_all_findings()

        swarm.add_log(f"[report] Compiling {len(all_findings)} findings into report...")

        # Compute stats
        by_operator = {}
        by_severity = {}
        by_tool = {}
        for f in all_findings:
            op = f.get("source", "swarm").replace("swarm:", "")
            by_operator[op] = by_operator.get(op, 0) + 1
            sev = f.get("severity", "info")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            tool = f.get("tool", "?")
            by_tool[tool] = by_tool.get(tool, 0) + 1

        severity_order = ["critical", "high", "medium", "low", "info"]
        severity_labels = {
            "critical": "🔴 Critical",
            "high": "🟠 High",
            "medium": "🟡 Medium",
            "low": "🔵 Low",
            "info": "ℹ️ Info",
        }

        # ── Build report content ──
        report_lines = [
            f"# 🐝 Swarm Report — {target}",
            "",
            f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Total Findings:** {len(all_findings)}",
            f"**Operators:** {len(swarm.operators)}",
            "",
            "---",
            "",
            "## 📊 Summary",
            "",
            "### By Operator",
            "| Operator | Findings |",
            "|----------|----------|",
        ]
        for op, count in sorted(by_operator.items()):
            label = op.capitalize() if op else "Swarm"
            report_lines.append(f"| {label} | {count} |")

        report_lines.append("")
        report_lines.append("### By Severity")
        report_lines.append("| Severity | Count |")
        report_lines.append("|----------|-------|")
        for sev in severity_order:
            cnt = by_severity.get(sev, 0)
            label = severity_labels.get(sev, sev)
            report_lines.append(f"| {label} | {cnt} |")
        report_lines.append("")

        report_lines.append("### Tools Used")
        for tool, cnt in sorted(by_tool.items()):
            report_lines.append(f"- **{tool}**: {cnt} finding{'s' if cnt > 1 else ''}")
        report_lines.append("")

        # ── Detailed findings by severity ──
        report_lines.append("---")
        report_lines.append("## 🔎 Detailed Findings")
        report_lines.append("")

        for sev in severity_order:
            items = [f for f in all_findings if f.get("severity") == sev]
            if not items:
                continue
            label = severity_labels.get(sev, sev)
            report_lines.append(f"### {label} ({len(items)})")
            report_lines.append("")
            for i, f in enumerate(items, 1):
                title = f.get("title", "Finding")[:150]
                detail = f.get("detail", "")[:300]
                tool = f.get("tool", "?")
                port = f.get("port", "")
                extra = f" on port {port}" if port else ""
                report_lines.append(f"**{i}. {title}**")
                report_lines.append(f"- Tool: `{tool}`{extra}")
                if detail:
                    report_lines.append(f"- Detail: {detail}")
                report_lines.append("")

        # ── Commands executed ──
        report_lines.append("---")
        report_lines.append("## ⚙️ Commands Executed")
        report_lines.append("")
        for op in swarm.operators:
            if op.commands_run:
                report_lines.append(f"### {op.display_name}")
                report_lines.append("")
                report_lines.append("```bash")
                for cmd in op.commands_run:
                    report_lines.append(f"# {cmd}")
                report_lines.append("```")
                report_lines.append("")

        # ── Recommendations ──
        high_crit = by_severity.get("critical", 0) + by_severity.get("high", 0)
        report_lines.append("---")
        report_lines.append("## 🎯 Recommendations")
        report_lines.append("")
        if high_crit > 0:
            report_lines.append(f"⚠️ **{high_crit} critical/high findings** require immediate attention.")
            report_lines.append("")
        report_lines.append("1. Review all high-severity findings first")
        report_lines.append("2. Manually verify each finding before exploitation")
        report_lines.append("3. Prioritize remote code execution vulnerabilities")
        report_lines.append("4. Check for default credentials on discovered services")
        report_lines.append("5. Document all findings for the final penetration test report")
        report_lines.append("")

        report_lines.append("---")
        report_lines.append(f"*Report generated by VulnForge Swarm on {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}*")

        report_md = "\n".join(report_lines)

        # ── Save to DB ──
        try:
            from backend import database as db
            report = db.save_report({
                "type": "swarm",
                "title": f"🐝 Swarm Report — {target}",
                "target": target,
                "raw_output": report_md,
                "parsed_data": {
                    "summary": {
                        "total": len(all_findings),
                        "by_severity": by_severity,
                        "by_operator": by_operator,
                        "by_tool": by_tool,
                    },
                    "findings": all_findings,
                },
                "format": "md",
            })
            if report:
                self.add_finding(swarm, "report", "info",
                                 f"Swarm report saved (ID: {report.get('id', '?')})",
                                 f"Report saved to database with {len(all_findings)} findings.",
                                 "", "")
                swarm.add_log(f"[report] ✅ Report saved to DB (ID: {report.get('id', '?')})")
            else:
                # Fallback: save to swarm findings even without DB
                swarm.add_log("[report] ℹ Report generated (DB unavailable — stored in session)")
                self.add_finding(swarm, "report", "info",
                                 "Swarm report generated",
                                 report_md[:300] + "...",
                                 "", "")
        except Exception as e:
            swarm.add_log(f"[report] ⚠ Could not save to DB: {e}")
            # Still save as finding
            self.add_finding(swarm, "report", "info",
                             "Swarm report generated",
                             report_md[:300] + "...",
                             "", "")

        self.status = "completed"
        swarm.add_log(f"[report] ✅ Complete — {len(self.findings)} findings, report generated")
        return self.findings
