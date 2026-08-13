"""Evidence-driven release gate model (R5B).

Pure and importable: :func:`evaluate_gates` performs no I/O. It maps an
evidence mapping to one :class:`Gate` verdict per release concern, then
computes the three release safeties from those verdicts.

CRITICAL SEMANTIC: absence of evidence NEVER yields PASS for any gate.
A gate with no evidence is PARTIAL (unknown), never green.

Evidence keys consumed (all optional; missing means PARTIAL):

- ``regression``: ``{"passed": bool, "tests": int, "failures": int,
  "errors": int, "resource_warnings": int, "where": str}``
  → TECHNICAL_CORE. PASS iff passed and failures/errors/resource_warnings
  are all 0 and tests is positive; a failed, empty, or dirty run is BLOCKED.
- ``packaging``: ``{"wheel_ok": bool, "sdist_ok": bool, "details": [str]}``
  → PACKAGING. PASS iff both artifacts satisfy the content contract.
- ``platforms``: ``{"windows": "pass|partial|fail|pending", "linux": ...,
  "macos": ...}`` → the WINDOWS / LINUX / MACOS gates.
- ``cbm``: ``{"certified_platforms": [str], "notes": [str],
  "claims": [{"platform": str, "certified": bool, "evidence": str}]}``
  → CBM_CERTIFICATION. PASS only when every desktop platform
  (windows/linux/darwin amd64) is certified; windows-only certification
  is PARTIAL with an honest-degradation note; claiming a non-Windows
  platform certified without an evidence entry is BLOCKED; empty
  certified_platforms is never PASS.
- ``hosts``: ``{"certified_hosts": [str], "regenerated_in_ci": bool}``
  → HOST_CERTIFICATION. PASS iff certified_hosts is non-empty AND the
  certification was regenerated in CI; historical/local certification is
  PARTIAL with a note.
- ``docs``: ``{"release_doc": bool, "readme_sections": bool,
  "installation_doc": bool}`` → DOCUMENTATION. PASS iff all true.
- ``legal``: ``{"license_present": bool, "notice_complete": bool|None}``
  → LEGAL. No LICENSE file is BLOCKED (distribution rights undefined);
  an incomplete NOTICE is PARTIAL.
- ``security``: ``{"workflows_minimal_permissions": bool,
  "no_untrusted_triggers": bool, "actions_pinned": bool}`` → SECURITY.
  PASS iff all true; a present-but-failing control is BLOCKED.
- ``ci``: ``{"workflows_present": bool, "remote_runs_passed": bool|None}``
  → CI. Present + remote green → PASS; present without remote evidence →
  PARTIAL ("REMOTE_CI_PENDING"); present + failed remote runs → BLOCKED;
  absent → BLOCKED.
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from typing import Any, List, Mapping

TECHNICAL_CORE = "TECHNICAL_CORE"
PACKAGING = "PACKAGING"
WINDOWS = "WINDOWS"
LINUX = "LINUX"
MACOS = "MACOS"
CBM_CERTIFICATION = "CBM_CERTIFICATION"
HOST_CERTIFICATION = "HOST_CERTIFICATION"
DOCUMENTATION = "DOCUMENTATION"
LEGAL = "LEGAL"
SECURITY = "SECURITY"
CI = "CI"

#: Gate names in canonical evaluation/report order.
GATE_ORDER = (
    TECHNICAL_CORE,
    PACKAGING,
    WINDOWS,
    LINUX,
    MACOS,
    CBM_CERTIFICATION,
    HOST_CERTIFICATION,
    DOCUMENTATION,
    LEGAL,
    SECURITY,
    CI,
)

#: Desktop CBM platform tags that must all be certified for a full PASS.
_CBM_DESKTOP_PLATFORMS = ("windows-amd64", "linux-amd64", "darwin-amd64")


class GateStatus(enum.Enum):
    PASS = "PASS"
    PARTIAL = "PARTIAL"
    BLOCKED = "BLOCKED"
    NOT_APPLICABLE = "NOT_APPLICABLE"

    def __str__(self) -> str:
        return self.value


@dataclass
class Gate:
    """One release-gate verdict with its evidence trail."""

    name: str
    status: GateStatus
    evidence: List[str] = field(default_factory=list)
    blockers: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status.value,
            "evidence": list(self.evidence),
            "blockers": list(self.blockers),
            "notes": list(self.notes),
        }


def _gate(name, status, evidence=None, blockers=None, notes=None) -> Gate:
    return Gate(
        name=name,
        status=status,
        evidence=list(evidence or []),
        blockers=list(blockers or []),
        notes=list(notes or []),
    )


def _eval_technical_core(evidence: Mapping[str, Any]) -> Gate:
    data = evidence.get("regression")
    if not isinstance(data, Mapping):
        return _gate(TECHNICAL_CORE, GateStatus.PARTIAL,
                     notes=["no regression evidence"])
    passed = bool(data.get("passed"))
    failures = int(data.get("failures") or 0)
    errors = int(data.get("errors") or 0)
    warnings = int(data.get("resource_warnings") or 0)
    tests = int(data.get("tests") or 0)
    where = str(data.get("where") or "unspecified")
    ev = [f"{tests} tests at {where}; failures={failures} "
          f"errors={errors} resource_warnings={warnings}"]
    if passed and tests > 0 and failures == 0 and errors == 0 and warnings == 0:
        return _gate(TECHNICAL_CORE, GateStatus.PASS, evidence=ev)
    reasons = []
    if tests <= 0:
        reasons.append(
            "regression test count must be greater than zero (tests <= 0)"
        )
    if not passed:
        reasons.append("regression run did not pass")
    if failures:
        reasons.append(f"{failures} test failures")
    if errors:
        reasons.append(f"{errors} test errors")
    if warnings:
        reasons.append(f"{warnings} ResourceWarnings")
    return _gate(TECHNICAL_CORE, GateStatus.BLOCKED, evidence=ev,
                 blockers=reasons or ["regression evidence is not green"])


def _eval_packaging(evidence: Mapping[str, Any]) -> Gate:
    data = evidence.get("packaging")
    if not isinstance(data, Mapping):
        return _gate(PACKAGING, GateStatus.PARTIAL,
                     notes=["no packaging evidence"])
    details = [str(item) for item in data.get("details") or []]
    wheel_ok = bool(data.get("wheel_ok"))
    sdist_ok = bool(data.get("sdist_ok"))
    if wheel_ok and sdist_ok:
        return _gate(PACKAGING, GateStatus.PASS, evidence=details)
    blockers = []
    if not wheel_ok:
        blockers.append("wheel does not satisfy the content contract")
    if not sdist_ok:
        blockers.append("sdist does not satisfy the content contract")
    return _gate(PACKAGING, GateStatus.BLOCKED, evidence=details,
                 blockers=blockers)


def _eval_platform(name: str, key: str, evidence: Mapping[str, Any]) -> Gate:
    data = evidence.get("platforms")
    value = data.get(key) if isinstance(data, Mapping) else None
    ev = [f"platform {key}: {value}"] if value else []
    if value == "pass":
        return _gate(name, GateStatus.PASS, evidence=ev)
    if value == "fail":
        return _gate(name, GateStatus.BLOCKED, evidence=ev,
                     blockers=[f"{key} regression failed"])
    return _gate(name, GateStatus.PARTIAL, evidence=ev,
                 notes=[f"no passing {key} evidence"])


def _eval_cbm(evidence: Mapping[str, Any]) -> Gate:
    data = evidence.get("cbm")
    if not isinstance(data, Mapping):
        return _gate(CBM_CERTIFICATION, GateStatus.PARTIAL,
                     notes=["no CBM certification evidence"])
    certified = [str(item) for item in data.get("certified_platforms") or []]
    notes = [str(item) for item in data.get("notes") or []]
    claims = data.get("claims") or []

    for claim in claims:
        if not isinstance(claim, Mapping):
            continue
        platform = str(claim.get("platform") or "")
        if (
            claim.get("certified")
            and not platform.startswith("windows")
            and not str(claim.get("evidence") or "").strip()
        ):
            return _gate(
                CBM_CERTIFICATION,
                GateStatus.BLOCKED,
                evidence=[f"certified: {', '.join(certified)}"] if certified else [],
                blockers=[
                    f"{platform} claimed certified without an evidence entry"
                ],
            )

    if not certified:
        return _gate(CBM_CERTIFICATION, GateStatus.PARTIAL,
                     notes=["no certified CBM platforms recorded"])

    ev = [f"certified platforms: {', '.join(sorted(certified))}"]
    if all(platform in certified for platform in _CBM_DESKTOP_PLATFORMS):
        if notes:
            return _gate(CBM_CERTIFICATION, GateStatus.PASS,
                         evidence=ev + notes)
        return _gate(CBM_CERTIFICATION, GateStatus.PARTIAL, evidence=ev,
                     notes=["certification lacks documentation notes"])
    return _gate(
        CBM_CERTIFICATION,
        GateStatus.PARTIAL,
        evidence=ev,
        notes=notes or ["Linux/macOS CBM not certified "
                        "(honest degradation verified)"],
    )


def _eval_hosts(evidence: Mapping[str, Any]) -> Gate:
    data = evidence.get("hosts")
    if not isinstance(data, Mapping):
        return _gate(HOST_CERTIFICATION, GateStatus.PARTIAL,
                     notes=["no host certification evidence"])
    certified = [str(item) for item in data.get("certified_hosts") or []]
    regenerated = bool(data.get("regenerated_in_ci"))
    if not certified:
        return _gate(HOST_CERTIFICATION, GateStatus.PARTIAL,
                     notes=["no certified hosts recorded"])
    ev = [f"certified hosts: {', '.join(sorted(certified))}"]
    if regenerated:
        return _gate(HOST_CERTIFICATION, GateStatus.PASS, evidence=ev)
    return _gate(
        HOST_CERTIFICATION,
        GateStatus.PARTIAL,
        evidence=ev,
        notes=["host certification is historical/local, not regenerated "
               "in CI"],
    )


def _eval_docs(evidence: Mapping[str, Any]) -> Gate:
    data = evidence.get("docs")
    if not isinstance(data, Mapping):
        return _gate(DOCUMENTATION, GateStatus.PARTIAL,
                     notes=["no documentation evidence"])
    checks = {
        "release_doc": bool(data.get("release_doc")),
        "readme_sections": bool(data.get("readme_sections")),
        "installation_doc": bool(data.get("installation_doc")),
    }
    missing = [key for key, ok in checks.items() if not ok]
    if not missing:
        return _gate(DOCUMENTATION, GateStatus.PASS,
                     evidence=["release doc, README sections and "
                               "installation doc present"])
    return _gate(DOCUMENTATION, GateStatus.PARTIAL,
                 notes=[f"missing: {', '.join(sorted(missing))}"])


def _eval_legal(evidence: Mapping[str, Any]) -> Gate:
    data = evidence.get("legal")
    if not isinstance(data, Mapping):
        return _gate(LEGAL, GateStatus.PARTIAL,
                     notes=["no legal evidence"])
    if not data.get("license_present"):
        return _gate(
            LEGAL,
            GateStatus.BLOCKED,
            blockers=["no LICENSE file — distribution rights undefined"],
        )
    if data.get("notice_complete") is False:
        return _gate(LEGAL, GateStatus.PARTIAL,
                     notes=["LICENSE present but NOTICE is incomplete"])
    return _gate(LEGAL, GateStatus.PASS, evidence=["LICENSE present"])


def _eval_security(evidence: Mapping[str, Any]) -> Gate:
    data = evidence.get("security")
    if not isinstance(data, Mapping):
        return _gate(SECURITY, GateStatus.PARTIAL,
                     notes=["no security evidence"])
    checks = {
        "workflows_minimal_permissions": bool(
            data.get("workflows_minimal_permissions")
        ),
        "no_untrusted_triggers": bool(data.get("no_untrusted_triggers")),
        "actions_pinned": bool(data.get("actions_pinned")),
    }
    failing = [key for key, ok in checks.items() if not ok]
    if not failing:
        return _gate(SECURITY, GateStatus.PASS,
                     evidence=["workflow permissions minimal, no untrusted "
                               "triggers, actions pinned"])
    return _gate(SECURITY, GateStatus.BLOCKED,
                 blockers=[f"security control not satisfied: {key}"
                           for key in sorted(failing)])


def _eval_ci(evidence: Mapping[str, Any]) -> Gate:
    data = evidence.get("ci")
    if not isinstance(data, Mapping):
        return _gate(CI, GateStatus.PARTIAL, notes=["no CI evidence"])
    if not data.get("workflows_present"):
        return _gate(CI, GateStatus.BLOCKED,
                     blockers=["no CI workflows present"])
    remote = data.get("remote_runs_passed")
    if remote is True:
        return _gate(CI, GateStatus.PASS,
                     evidence=["workflows present and remote runs green"])
    if remote is False:
        return _gate(
            CI,
            GateStatus.BLOCKED,
            evidence=["workflows present; remote runs reported failure"],
            blockers=["remote CI runs failed (remote_runs_passed=False)"],
        )
    return _gate(CI, GateStatus.PARTIAL,
                 evidence=["workflows present"],
                 notes=["REMOTE_CI_PENDING: no passing remote CI evidence"])


_EVALUATORS = {
    TECHNICAL_CORE: _eval_technical_core,
    PACKAGING: _eval_packaging,
    WINDOWS: lambda ev: _eval_platform(WINDOWS, "windows", ev),
    LINUX: lambda ev: _eval_platform(LINUX, "linux", ev),
    MACOS: lambda ev: _eval_platform(MACOS, "macos", ev),
    CBM_CERTIFICATION: _eval_cbm,
    HOST_CERTIFICATION: _eval_hosts,
    DOCUMENTATION: _eval_docs,
    LEGAL: _eval_legal,
    SECURITY: _eval_security,
    CI: _eval_ci,
}


@dataclass
class ReleaseReport:
    """The full gate set plus computed release safeties."""

    gates: List[Gate] = field(default_factory=list)

    def _by_name(self, name: str) -> Gate:
        for gate in self.gates:
            if gate.name == name:
                return gate
        raise KeyError(name)

    def _status(self, name: str) -> GateStatus:
        return self._by_name(name).status

    @property
    def overall(self) -> GateStatus:
        statuses = [gate.status for gate in self.gates]
        if GateStatus.BLOCKED in statuses:
            return GateStatus.BLOCKED
        if GateStatus.PARTIAL in statuses:
            return GateStatus.PARTIAL
        return GateStatus.PASS

    @property
    def blockers(self) -> List[str]:
        items: List[str] = []
        for gate in self.gates:
            if gate.status is GateStatus.BLOCKED:
                reason = "; ".join(gate.blockers) or "blocked"
                items.append(f"{gate.name}: {reason}")
        return items

    @property
    def safe_to_merge(self) -> bool:
        core = (TECHNICAL_CORE, PACKAGING, SECURITY, CI)
        if any(self._status(name) is GateStatus.BLOCKED for name in core):
            return False
        if any(
            self._status(name) is not GateStatus.PASS
            for name in (TECHNICAL_CORE, PACKAGING, SECURITY)
        ):
            return False
        return self._status(CI) in (GateStatus.PASS, GateStatus.PARTIAL)

    @property
    def safe_to_tag_rc(self) -> bool:
        if not self.safe_to_merge:
            return False
        for name in (WINDOWS, LINUX, MACOS, CI):
            if self._status(name) is not GateStatus.PASS:
                return False
        if self._status(DOCUMENTATION) not in (
            GateStatus.PASS,
            GateStatus.PARTIAL,
        ):
            return False
        # An internal RC tag tolerates a LEGAL blocker (surfaced in
        # blockers); every other BLOCKED gate vetoes the tag.
        for gate in self.gates:
            if gate.name == LEGAL:
                continue
            if gate.status is GateStatus.BLOCKED:
                return False
        return True

    @property
    def safe_for_public_release(self) -> bool:
        for gate in self.gates:
            if gate.status is GateStatus.BLOCKED:
                return False
            if gate.name in (CBM_CERTIFICATION, HOST_CERTIFICATION):
                # Documented evidence debt: PARTIAL is acceptable.
                if gate.status not in (GateStatus.PASS, GateStatus.PARTIAL):
                    return False
            elif gate.status is not GateStatus.PASS:
                return False
        return (
            self._status(DOCUMENTATION) is GateStatus.PASS
            and self._status(LEGAL) is GateStatus.PASS
        )

    def to_dict(self) -> dict:
        return {
            "gates": [gate.to_dict() for gate in self.gates],
            "overall": self.overall.value,
            "safe_to_merge": self.safe_to_merge,
            "safe_to_tag_rc": self.safe_to_tag_rc,
            "safe_for_public_release": self.safe_for_public_release,
            "blockers": self.blockers,
        }

    @classmethod
    def from_evidence_json(cls, text: str) -> "ReleaseReport":
        """Evaluate a JSON-encoded evidence mapping."""
        return evaluate_gates(json.loads(text))


def evaluate_gates(evidence: Mapping[str, Any]) -> ReleaseReport:
    """Map an evidence mapping to the full release-gate report."""
    source = evidence if isinstance(evidence, Mapping) else {}
    gates = [_EVALUATORS[name](source) for name in GATE_ORDER]
    return ReleaseReport(gates=gates)
