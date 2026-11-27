"""Groups findings across hosts and sorts them into the report sections."""

from __future__ import annotations

from dataclasses import dataclass, field

from portgoblin.core.models import Finding, Status, group_findings


@dataclass
class Sections:
    quick_wins: list[Finding] = field(default_factory=list)  # issues, then manual checks
    observations: list[Finding] = field(default_factory=list)
    passed: list[Finding] = field(default_factory=list)
    not_assessed: list[Finding] = field(default_factory=list)

    @property
    def issue_count(self) -> int:
        return sum(1 for f in self.quick_wins if f.status is Status.ISSUE)

    @property
    def manual_count(self) -> int:
        return sum(1 for f in self.quick_wins if f.status is Status.MANUAL_CHECK)


def sections(findings: list[Finding]) -> Sections:
    grouped = group_findings(findings)
    result = Sections()
    result.quick_wins = sorted(
        (f for f in grouped if f.status is Status.ISSUE), key=lambda f: f.finding_id
    ) + sorted((f for f in grouped if f.status is Status.MANUAL_CHECK), key=lambda f: f.finding_id)
    result.observations = sorted(
        (f for f in grouped if f.status is Status.OBSERVATION), key=lambda f: f.finding_id
    )
    result.passed = sorted(
        (f for f in grouped if f.status is Status.OK), key=lambda f: f.finding_id
    )
    result.not_assessed = [f for f in grouped if f.status is Status.NOT_ASSESSED]
    return result
