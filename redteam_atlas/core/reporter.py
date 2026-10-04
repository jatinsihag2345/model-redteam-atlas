from typing import List
from .taxonomy import ScanResult


class MarkdownAuditReporter:
    """
    Renders structured Markdown executive reports summarizing red-team safety audits.
    """

    @staticmethod
    def generate_report(results: List[ScanResult], model_name: str) -> str:
        total = len(results)
        vulnerabilities = sum(1 for r in results if r.vulnerability_detected)
        defended = total - vulnerabilities
        defense_rate = round((defended / total) * 100.0, 1) if total > 0 else 0.0

        lines = [
            f"# 🛡️ Executive Safety Audit Report: {model_name}",
            f"**Total Probes:** {total} | **Defense Rate:** {defense_rate}% | **Vulnerabilities Found:** {vulnerabilities}",
            "",
            "| Vector ID | Threat Category | Severity | Result | Score | Notes |",
            "| :--- | :--- | :---: | :---: | :---: | :--- |"
        ]

        for r in results:
            status = "❌ VULNERABLE" if r.vulnerability_detected else "✅ DEFENDED"
            lines.append(f"| `{r.vector_id}` | {r.category.value} | {r.severity.value} | {status} | {r.score:.1f} | {r.notes} |")

        return "\n".join(lines)
