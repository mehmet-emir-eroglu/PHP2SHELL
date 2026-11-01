"""Safe console and JSON serialization."""

import json

from .models import Report


def render(result: Report, output_format: str = "console", quiet: bool = False) -> str:
    if output_format == "json":
        return json.dumps(result.to_dict(), indent=2, ensure_ascii=True) + "\n"
    if quiet:
        return result.status.value + "\n"
    lines = [
        f"{result.status.value} | scope={result.scope}",
        f"Target: {json.dumps(result.target, ensure_ascii=True)}",
        f"Method: {result.verification_method}",
        f"UTC: {result.timestamp}",
    ]
    for finding in result.findings:
        lines.extend(
            [
                f"{finding.cve}: {finding.status.value}",
                f"  {finding.evidence_summary}",
                f"  Confidence: {finding.confidence}",
                f"  Reference: {finding.reference}",
            ]
        )
    lines.append("Observations: " + json.dumps(result.observations, ensure_ascii=True))
    lines.extend("Limitation: " + limitation for limitation in result.limitations)
    return "\n".join(lines) + "\n"
