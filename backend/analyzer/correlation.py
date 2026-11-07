"""Code-level pass after all chunks are analyzed.

Steps, in order:
1. Merge model findings with the same (source IP, attack type) across chunks:
   one campaign = one finding. Evidence lines are unioned, duplicates removed.
2. Add rule-based findings for strong deterministic signals the model missed
   (source="rules"), so a weak or manipulated model cannot hide an attack.
3. Decide each finding's status from the real HTTP responses
   (Attempted / Blocked / Possibly Successful) instead of trusting the model.
4. Flag model findings that no rule-based signal supports (corroborated=False,
   severity Low): normal errors must not be reported as confirmed attacks.
5. Detect multi-step sequences per IP (failed logins -> success -> privileged
   access), make sure each one also appears as a finding, and raise severity for
   the IPs involved.
Nothing here knows about the sample log: all decisions come from the per-IP state.
"""
from typing import Optional

import config
from analyzer.context_manager import ContextManager, EventLines, IPState
from analyzer.schemas import (AttackType, ChunkResult, Correlation, Evidence, Finding,
                              FindingStatus, Severity, Stage)

SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

# Which deterministic signals support which attack type.
TYPE_SIGNALS = {
    AttackType.BRUTE_FORCE: ("auth_failure",),
    AttackType.SQL_INJECTION: ("sqli_pattern",),
    AttackType.SCANNING: ("scan_path",),
    AttackType.UNUSUAL_RATE: ("rate_limited", "high_rate"),
    AttackType.UNAUTHORIZED_ACCESS: ("traversal_pattern", "access_denied", "sensitive_success"),
    AttackType.OTHER: ("injection_text", "security_rule", "validation_error"),
}


def raise_to(current: Severity, minimum: Severity) -> Severity:
    return max(current, minimum, key=SEVERITY_ORDER.index)


def _lower(sev: Severity) -> Severity:
    return SEVERITY_ORDER[max(SEVERITY_ORDER.index(sev) - 1, 0)]


# --------------------------------------------------------------------------- 1. merge
def merge_findings(results: list[ChunkResult], ctx: ContextManager) -> list[Finding]:
    merged: dict[tuple, Finding] = {}
    for result in results:
        for f in result.findings:
            f = f.model_copy(deep=True)
            f.chunk_indexes = [f.chunk_index] if f.chunk_index is not None else []
            f.evidence = _dedupe_evidence(f.evidence, ctx)
            key = (f.source_ip, f.attack_type)
            if key not in merged:
                merged[key] = f
                continue
            _merge_into(merged[key], f, ctx)
    return list(merged.values())


def _dedupe_evidence(evidence: list[Evidence], ctx: ContextManager) -> list[Evidence]:
    """Map duplicate log lines to their first copy and keep each line once."""
    out, seen = [], set()
    for ev in sorted(evidence, key=lambda e: e.line):
        line = ctx.duplicates.get(ev.line, ev.line)
        if line not in seen:
            seen.add(line)
            out.append(Evidence(line=line, description=ev.description))
    return out


def _merge_into(target: Finding, other: Finding, ctx: ContextManager) -> None:
    target.evidence = _dedupe_evidence(target.evidence + other.evidence, ctx)
    target.severity = raise_to(target.severity, other.severity)
    if other.confidence > target.confidence:
        target.reason, target.suggested_action = other.reason, other.suggested_action
        target.confidence = other.confidence
    target.chunk_indexes = sorted(set(target.chunk_indexes) | set(other.chunk_indexes))
    target.notes.append(f"merged with finding from chunk(s) {other.chunk_indexes}")


# --------------------------------------------------------------------------- 2. rule-based findings
def _rule_candidates(state: IPState) -> list[tuple[AttackType, str, Severity, str, str]]:
    """(type, signal, base severity, reason, action) for strong signals of one IP."""
    out = []
    fails = state.count("auth_failure")
    if fails >= config.BRUTE_FORCE_MIN_FAILURES:
        out.append((AttackType.BRUTE_FORCE, "auth_failure", Severity.MEDIUM,
                    f"{fails} failed logins from this IP.",
                    "Block or rate-limit the IP, enforce MFA and account lockout."))
    if state.count("sqli_pattern"):
        out.append((AttackType.SQL_INJECTION, "sqli_pattern", Severity.HIGH,
                    f"{state.count('sqli_pattern')} requests with SQL injection patterns.",
                    "Block the IP, confirm queries are parameterised, review WAF rules."))
    if state.count("scan_path") >= config.SCAN_MIN_PATHS:
        out.append((AttackType.SCANNING, "scan_path", Severity.LOW,
                    f"{state.count('scan_path')} probes for sensitive files/admin tools.",
                    "Block the IP at the edge; make sure the probed files are not deployed."))
    if state.count("traversal_pattern"):
        out.append((AttackType.UNAUTHORIZED_ACCESS, "traversal_pattern", Severity.HIGH,
                    f"{state.count('traversal_pattern')} path traversal attempts.",
                    "Validate file names server-side; block the IP."))
    rate = max(state.count("rate_limited"), state.count("high_rate"))
    if rate >= config.RATE_MIN_EVENTS:
        signal = "rate_limited" if state.count("rate_limited") >= state.count("high_rate") else "high_rate"
        out.append((AttackType.UNUSUAL_RATE, signal, Severity.MEDIUM,
                    f"Request burst: {state.count('high_rate')} rate-window lines, "
                    f"{state.count('rate_limited')} answered 429.",
                    "Keep rate limiting on; consider a temporary block for the IP."))
    if state.count("injection_text"):
        out.append((AttackType.OTHER, "injection_text", Severity.MEDIUM,
                    "Request contains text that tries to instruct an AI/log analyst (prompt injection).",
                    "Treat as hostile input; check where submitted text is stored or displayed."))
    return out


def add_rule_findings(findings: list[Finding], ctx: ContextManager) -> list[Finding]:
    existing = {(f.source_ip, f.attack_type) for f in findings}
    for ip, state in ctx.states.items():
        for attack_type, signal, severity, reason, action in _rule_candidates(state):
            if (ip, attack_type) in existing:
                continue
            lines = state.events[signal].lines[:10]
            findings.append(Finding(
                attack_type=attack_type, severity=severity, source_ip=ip,
                evidence=[Evidence(line=n, description=signal.replace("_", " ")) for n in lines],
                reason=reason, suggested_action=action, confidence=0.9,
                status=FindingStatus.ATTEMPTED, source="rules",
                notes=["added by rule-based detector (model did not report it)"],
            ))
    return findings


# --------------------------------------------------------------------------- 3. status
def _success_after_failures(state: IPState) -> Optional[int]:
    """Line of the first successful login that follows a failed one, else None."""
    fails, wins = state.events.get("auth_failure"), state.events.get("auth_success")
    if not fails or not wins:
        return None
    first_fail = fails.lines[0]
    return next((n for n in wins.lines if n > first_fail), None)


def decide_status(f: Finding, ctx: ContextManager) -> FindingStatus:
    state = ctx.states.get(f.source_ip or "")
    if f.attack_type == AttackType.BRUTE_FORCE and state:
        return FindingStatus.POSSIBLY_SUCCESSFUL if _success_after_failures(state) else FindingStatus.ATTEMPTED
    if f.attack_type == AttackType.UNUSUAL_RATE and state:
        return FindingStatus.BLOCKED if state.count("rate_limited") else FindingStatus.ATTEMPTED
    statuses = [ctx.line_info[e.line].status for e in f.evidence
                if e.line in ctx.line_info and ctx.line_info[e.line].status is not None]
    if not statuses:
        return f.status   # nothing to check against: keep the model's answer
    if any(200 <= s < 300 for s in statuses):
        return FindingStatus.POSSIBLY_SUCCESSFUL
    if all(s >= 400 for s in statuses):
        return FindingStatus.BLOCKED
    return FindingStatus.ATTEMPTED


# --------------------------------------------------------------------------- 4. corroboration
def is_corroborated(f: Finding, ctx: ContextManager) -> bool:
    """True if any evidence line, or the IP's state, carries a signal for this type."""
    state = ctx.states.get(f.source_ip or "")
    if f.attack_type == AttackType.BRUTE_FORCE:
        # One mistyped password is not brute force: require a minimum number of failures.
        return bool(state and state.count("auth_failure") >= config.COMPROMISE_MIN_FAILURES)
    wanted = TYPE_SIGNALS[f.attack_type]
    for ev in f.evidence:
        info = ctx.line_info.get(ev.line)
        if info and any(s in wanted for s in info.signals):
            return True
    return bool(state and any(state.count(s) for s in wanted))


def add_known_evidence(f: Finding, ctx: ContextManager, limit: int = 12) -> None:
    """Complete a finding's evidence with the lines code already knows for this IP/type."""
    state = ctx.states.get(f.source_ip or "")
    if not state:
        return
    have = {e.line for e in f.evidence}
    added = 0
    for signal in TYPE_SIGNALS[f.attack_type]:
        for line in state.events.get(signal, EventLines()).lines:
            if len(have) >= limit:
                break
            if line not in have:
                have.add(line)
                f.evidence.append(Evidence(line=line, description=signal.replace("_", " ")))
                added += 1
    if added:
        f.evidence.sort(key=lambda e: e.line)
        f.notes.append(f"{added} evidence line(s) added from rule-based state")


# --------------------------------------------------------------------------- 5. sequences
def _stage(name: str, ev: EventLines, after: int = 0) -> Optional[Stage]:
    lines = [n for n in ev.lines if n > after]
    return Stage(name=name, count=len(lines), lines=lines[:10]) if lines else None


def detect_sequences(ctx: ContextManager, line_chunk: dict[int, int]) -> list[Correlation]:
    correlations = []
    for ip, state in ctx.states.items():
        success = _success_after_failures(state)
        if not success:
            continue
        fails_before = [n for n in state.events["auth_failure"].lines if n < success]
        if len(fails_before) < config.COMPROMISE_MIN_FAILURES:
            continue
        stages = [Stage(name="failed logins", count=len(fails_before), lines=fails_before[:10]),
                  Stage(name="successful login", count=1, lines=[success])]
        privileged = _stage("privileged access after login", state.events.get("sensitive_success", EventLines()), success)
        large = _stage("large response (possible data export)", state.events.get("large_response", EventLines()), success)
        stages += [s for s in (privileged, large) if s]
        compromised = privileged is not None or large is not None
        users = sorted(state.users)
        description = (
            f"{len(fails_before)} failed logins, then a successful login at L{success}"
            + (f", then privileged access at L{privileged.lines[0]}" if privileged else "")
            + (f" and a large response at L{large.lines[0]}" if large else "")
            + (f" (account: {', '.join(users)})" if users else "")
            + ("." if not compromised else ". Possible account compromise.")
        )
        all_lines = [n for s in stages for n in s.lines]
        correlations.append(Correlation(
            kind="account_compromise" if compromised else "login_after_failures",
            source_ip=ip, severity=Severity.CRITICAL if compromised else Severity.HIGH,
            description=description, stages=stages, users=users,
            chunk_indexes=sorted({line_chunk[n] for n in all_lines if n in line_chunk}),
        ))
    return correlations


def add_sequence_findings(findings: list[Finding], correlations: list[Correlation]) -> None:
    """Every detected sequence must also show up as a finding, even when the model
    missed it and the failure count is below the brute-force rule threshold."""
    existing = {(f.source_ip, f.attack_type) for f in findings}
    for c in correlations:
        if c.kind == "account_compromise":
            attack_type, after = AttackType.UNAUTHORIZED_ACCESS, c.stages[1:]   # success + access
            action = "Reset the account's credentials, revoke its sessions and review what was accessed."
        else:
            attack_type, after = AttackType.BRUTE_FORCE, c.stages
            action = "Reset the account's password and confirm the login was legitimate."
        if (c.source_ip, attack_type) in existing:
            continue
        evidence, seen = [], set()
        for s in after:
            for n in s.lines[:3]:
                if n not in seen:      # one line can be both "privileged" and "large response"
                    seen.add(n)
                    evidence.append(Evidence(line=n, description=s.name))
        findings.append(Finding(
            attack_type=attack_type, severity=c.severity, source_ip=c.source_ip, evidence=evidence,
            reason=c.description, suggested_action=action, confidence=0.85,
            status=FindingStatus.POSSIBLY_SUCCESSFUL, source="rules",
            notes=[f"added from correlated sequence '{c.kind}'"],
        ))


# --------------------------------------------------------------------------- entry point
def correlate(results: list[ChunkResult], ctx: ContextManager,
              line_chunk: dict[int, int]) -> tuple[list[Finding], list[Correlation]]:
    findings = merge_findings(results, ctx)
    findings = add_rule_findings(findings, ctx)
    correlations = detect_sequences(ctx, line_chunk)
    add_sequence_findings(findings, correlations)
    escalated_ips = {c.source_ip: c.severity for c in correlations}

    for f in findings:
        if f.source == "model" and not is_corroborated(f, ctx):
            # Checked first: an unsupported claim must not be escalated by later rules.
            f.corroborated = False
            f.severity = Severity.LOW
            f.confidence = min(f.confidence, 0.3)
            f.notes.append("no rule-based signal supports this; severity set to Low, review manually")
            continue
        add_known_evidence(f, ctx)
        new_status = decide_status(f, ctx)
        if new_status != f.status:
            f.notes.append(f"status {f.status.value} -> {new_status.value} (from HTTP responses)")
            f.status = new_status
        if f.status == FindingStatus.POSSIBLY_SUCCESSFUL:
            f.severity = raise_to(f.severity, Severity.HIGH)
        elif f.status == FindingStatus.BLOCKED and f.source_ip not in escalated_ips:
            before = f.severity
            f.severity = _lower(f.severity)   # every request was rejected: less urgent
            if f.severity != before:
                f.notes.append(f"severity {before.value} -> {f.severity.value} (all attempts blocked)")
        if f.source_ip in escalated_ips:
            before = f.severity
            f.severity = raise_to(f.severity, Severity.HIGH)
            if f.severity != before:
                f.notes.append("severity raised: IP is part of a correlated attack sequence")

    for f in findings:   # show which chunks the evidence lives in (also for rule findings)
        f.chunk_indexes = sorted(set(f.chunk_indexes) | {line_chunk[e.line] for e in f.evidence
                                                          if e.line in line_chunk})
    findings.sort(key=lambda f: (-SEVERITY_ORDER.index(f.severity), f.evidence[0].line))
    return findings, correlations
