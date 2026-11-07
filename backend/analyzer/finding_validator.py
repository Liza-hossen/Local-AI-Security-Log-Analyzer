"""Turns the model's raw reply into trusted Finding objects.

The model output is treated as untrusted:
- broken/truncated/extra-text JSON is repaired where possible (else the caller retries),
- enum values are normalised, impossible values are fixed and a warning recorded,
- evidence lines that do not exist in the chunk or the context summary are removed,
- a finding left with no real evidence is dropped (no fabricated findings).
"""
import json
import re
from typing import Any, Optional

import config
from analyzer.schemas import AttackType, Evidence, Finding, FindingStatus, Severity

# --------------------------------------------------------------------------- JSON parsing
_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.I)


def parse_json_reply(text: Optional[str]) -> Optional[Any]:
    """Return parsed JSON, or None if nothing usable could be recovered."""
    if not text or not text.strip():
        return None
    text = _FENCE_RE.sub("", text.strip())
    for candidate in (text, _outer_object(text)):
        if candidate:
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass
    return _repair_truncated(text)


def _outer_object(text: str) -> Optional[str]:
    """Strip chatter around the JSON: from the first '{' to the last '}'."""
    start, end = text.find("{"), text.rfind("}")
    return text[start:end + 1] if 0 <= start < end else None


def _repair_truncated(text: str) -> Optional[Any]:
    """Recover JSON that was cut off (e.g. output hit num_predict).

    Walk back to the last complete value, then close any open brackets. This drops
    the half-written last item instead of guessing its content.
    """
    start = text.find("{")
    if start < 0:
        return None
    text = text[start:]
    cut_points = [i for i, ch in enumerate(text) if ch in ",}]"]
    for cut in reversed(cut_points[-200:]):
        prefix = text[:cut + 1] if text[cut] != "," else text[:cut]
        closers = _closing_brackets(prefix)
        if closers is None:
            continue
        try:
            return json.loads(prefix + closers)
        except json.JSONDecodeError:
            continue
    return None


def _closing_brackets(prefix: str) -> Optional[str]:
    """Brackets needed to close prefix, or None if it ends inside a string."""
    stack, in_str, escaped = [], False, False
    for ch in prefix:
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "{[":
            stack.append("}" if ch == "{" else "]")
        elif ch in "}]" and stack:
            stack.pop()
    return None if in_str else "".join(reversed(stack))


# --------------------------------------------------------------------------- field normalising
_ATTACK_SYNONYMS = {
    "brute": AttackType.BRUTE_FORCE, "credential": AttackType.BRUTE_FORCE,
    "sql": AttackType.SQL_INJECTION, "sqli": AttackType.SQL_INJECTION,
    "rate": AttackType.UNUSUAL_RATE, "dos": AttackType.UNUSUAL_RATE, "flood": AttackType.UNUSUAL_RATE,
    "unauthori": AttackType.UNAUTHORIZED_ACCESS, "privilege": AttackType.UNAUTHORIZED_ACCESS,
    "traversal": AttackType.UNAUTHORIZED_ACCESS, "compromise": AttackType.UNAUTHORIZED_ACCESS,
    "scan": AttackType.SCANNING, "recon": AttackType.SCANNING, "probe": AttackType.SCANNING,
}
_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]{3,}$")


def _match_enum(enum_cls, value) -> Optional[Any]:
    text = str(value or "").strip().lower()
    for member in enum_cls:
        if member.value.lower() == text:
            return member
    return None


def _attack_type(value, warnings: list) -> AttackType:
    exact = _match_enum(AttackType, value)
    if exact:
        return exact
    text = str(value or "").lower()
    for key, member in _ATTACK_SYNONYMS.items():
        if key in text:
            warnings.append(f"attack_type '{value}' mapped to '{member.value}'")
            return member
    warnings.append(f"unknown attack_type '{value}' set to 'Other'")
    return AttackType.OTHER


def _severity(value, warnings: list) -> Severity:
    exact = _match_enum(Severity, value)
    if exact:
        return exact
    warnings.append(f"invalid severity '{value}' set to 'Medium'")
    return Severity.MEDIUM


def _status(value, warnings: list) -> FindingStatus:
    exact = _match_enum(FindingStatus, value)
    if exact:
        return exact
    warnings.append(f"invalid status '{value}' set to 'Attempted'")
    return FindingStatus.ATTEMPTED


def _confidence(value, warnings: list) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        warnings.append(f"invalid confidence '{value}' set to 0.5")
        return 0.5
    if number > 1:            # model answered as a percentage
        number /= 100
    return min(max(number, 0.0), 1.0)


def _line_number(value) -> Optional[int]:
    """Accept 42, "42", "L42", "[L42]" or "L42-45" (first line)."""
    match = re.search(r"\d+", str(value))
    return int(match.group(0)) if match else None


def _text(value, limit: int = 400) -> str:
    return " ".join(str(value or "").split())[:limit]


# --------------------------------------------------------------------------- validation
def validate_findings(data: Any, valid_lines: set[int], line_ips: dict[int, str]) -> tuple[list[Finding], list[str]]:
    """Validate the parsed reply.

    valid_lines: every line number the model was shown (chunk + context summary).
    line_ips:    line number -> client IP, used to check/repair source_ip.
    """
    warnings: list[str] = []
    items = data.get("findings", []) if isinstance(data, dict) else data
    if not isinstance(items, list):
        return [], ["reply has no 'findings' list"]
    findings = []
    for raw in items[: config.MAX_FINDINGS_PER_CHUNK * 2]:  # tolerate a little over-production
        finding = _validate_one(raw, valid_lines, line_ips, warnings)
        if finding:
            findings.append(finding)
    return findings, warnings


def _validate_one(raw: Any, valid_lines: set[int], line_ips: dict[int, str], warnings: list) -> Optional[Finding]:
    if not isinstance(raw, dict):
        warnings.append("dropped a finding that was not an object")
        return None
    evidence = _valid_evidence(raw.get("evidence"), valid_lines, warnings)
    if not evidence:
        warnings.append(f"dropped '{raw.get('attack_type')}' finding: no evidence on real lines")
        return None
    source_ip = _source_ip(raw.get("source_ip"), evidence, line_ips, warnings)
    # A finding is about ONE IP: lines that belong to a different IP are not its evidence.
    foreign = [e.line for e in evidence if source_ip and line_ips.get(e.line, source_ip) != source_ip]
    if foreign:
        warnings.append(f"removed evidence lines {foreign}: they belong to another IP")
        evidence = [e for e in evidence if e.line not in foreign]
    return Finding(
        attack_type=_attack_type(raw.get("attack_type"), warnings),
        severity=_severity(raw.get("severity"), warnings),
        source_ip=source_ip,
        evidence=evidence,
        reason=_text(raw.get("reason")) or "No reason given by the model.",
        suggested_action=_text(raw.get("suggested_action")) or "Review the cited log lines.",
        confidence=_confidence(raw.get("confidence"), warnings),
        status=_status(raw.get("status"), warnings),
    )


def _valid_evidence(items: Any, valid_lines: set[int], warnings: list) -> list[Evidence]:
    if not isinstance(items, list):
        return []
    evidence, seen = [], set()
    for item in items:
        line = _line_number(item.get("line") if isinstance(item, dict) else item)
        if line is None or line not in valid_lines:
            warnings.append(f"removed evidence with non-existent line {line}")
            continue
        if line in seen:
            continue  # same line cited twice
        seen.add(line)
        desc = _text(item.get("description"), 200) if isinstance(item, dict) else ""
        evidence.append(Evidence(line=line, description=desc or "cited by model"))
    return evidence


def _source_ip(value, evidence: list[Evidence], line_ips: dict[int, str], warnings: list) -> Optional[str]:
    """Trust the IP only if it matches one of the evidence lines; otherwise take it from them."""
    evidence_ips = [line_ips[e.line] for e in evidence if e.line in line_ips]
    ip = str(value or "").strip()
    if ip and _IP_RE.match(ip) and (not evidence_ips or ip in evidence_ips):
        return ip
    if evidence_ips:
        if ip:
            warnings.append(f"source_ip '{ip}' not on evidence lines, replaced by {evidence_ips[0]}")
        return evidence_ips[0]
    return ip if ip and _IP_RE.match(ip) else None
