"""Builds the final report from real results only. No extra LLM call: the executive
summary is a template filled with computed numbers, so it cannot hallucinate."""
from collections import Counter
from typing import Any

import config
from analyzer.context_manager import SUMMARY_EVENTS, ContextManager
from analyzer.correlation import SEVERITY_ORDER
from analyzer.prefilter import FilterStats
from analyzer.schemas import AttackType, ChunkResult, Correlation, Finding, Severity


def _by_severity(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.severity.value for f in findings)
    return {s.value: counts.get(s.value, 0) for s in reversed(SEVERITY_ORDER)}


def _by_type(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.attack_type.value for f in findings)
    return {t.value: counts[t.value] for t in AttackType if counts.get(t.value)}


def _suspicious_ips(findings: list[Finding], ctx: ContextManager) -> list[dict[str, Any]]:
    by_ip: dict[str, list[Finding]] = {}
    for f in findings:
        if f.source_ip and f.corroborated:
            by_ip.setdefault(f.source_ip, []).append(f)
    rows = []
    for ip, fs in by_ip.items():
        state = ctx.states.get(ip)
        top = max((f.severity for f in fs), key=SEVERITY_ORDER.index)
        rows.append({
            "ip": ip,
            "max_severity": top.value,
            "attack_types": sorted({f.attack_type.value for f in fs}),
            "requests": state.requests if state else 0,
            "users": sorted(state.users) if state else [],
            "first_line": state.first_line if state else None,
            "last_line": state.last_line if state else None,
            "signals": {short: state.events[key].count for key, short in SUMMARY_EVENTS
                        if state and key in state.events},
        })
    rows.sort(key=lambda r: -SEVERITY_ORDER.index(Severity(r["max_severity"])))
    return rows


def _actions(findings: list[Finding], correlations: list[Correlation]) -> list[str]:
    actions = []
    for c in correlations:
        if c.kind == "account_compromise":
            who = ", ".join(c.users) or "the affected account"
            actions.append(f"URGENT: reset credentials and revoke sessions for {who}; "
                           f"block {c.source_ip}; review what was accessed at "
                           f"{', '.join('L' + str(s.lines[0]) for s in c.stages[2:])}.")
    for f in findings:
        if f.corroborated and f.suggested_action not in actions:
            actions.append(f.suggested_action)
    return actions[:12]


def _summary_text(n_entries: int, stats: FilterStats, results: list[ChunkResult],
                  findings: list[Finding], correlations: list[Correlation]) -> str:
    failed = [r for r in results if not r.ok]
    sev = _by_severity(findings)
    parts = [
        f"Analyzed {n_entries} log entries: {stats.interesting} were sent to the local model "
        f"in {len(results)} chunks ({len(failed)} failed), {stats.low_interest} routine entries "
        f"were counted but not sent, {stats.duplicates} duplicate lines were counted once.",
        f"{len(findings)} findings: " + ", ".join(f"{v} {k}" for k, v in sev.items() if v) + "."
        if findings else "No suspicious activity was found.",
    ]
    for c in correlations:
        parts.append(f"Correlated sequence from {c.source_ip}: {c.description}")
    weak = sum(1 for f in findings if not f.corroborated)
    if weak:
        parts.append(f"{weak} model finding(s) are not supported by rule-based signals and are marked Low for manual review.")
    if failed:
        parts.append("Some chunks failed; their lines were only covered by rule-based detection.")
    return " ".join(parts)


def build_report(job: dict, stats: FilterStats, ctx: ContextManager, results: list[ChunkResult],
                 findings: list[Finding], correlations: list[Correlation]) -> dict[str, Any]:
    n_entries = stats.total_entries + stats.duplicates
    return {
        "job_id": job["id"],
        "filename": job["filename"],
        "model": job.get("model") or config.MODEL_NAME,
        "executive_summary": _summary_text(n_entries, stats, results, findings, correlations),
        "totals": {
            "total_entries": n_entries,
            "entries_sent_to_model": stats.interesting,
            "entries_prefiltered": stats.low_interest,
            "duplicate_lines": stats.duplicates,
            "malformed_lines": stats.malformed,
            "chunks_total": len(results),
            "chunks_ok": sum(r.ok for r in results),
            "chunks_failed": sum(not r.ok for r in results),
            "total_findings": len(findings),
            "prompt_tokens": sum(r.prompt_tokens for r in results),
            "output_tokens": sum(r.output_tokens for r in results),
            "model_seconds": round(sum(r.duration_s for r in results), 1),
        },
        "by_severity": _by_severity(findings),
        "by_attack_type": _by_type(findings),
        "suspicious_ips": _suspicious_ips(findings, ctx),
        "correlations": [c.model_dump(mode="json") for c in correlations],
        "findings": [f.model_dump(mode="json") for f in findings],
        "failed_chunks": [{"chunk_index": r.chunk_index, "lines": [r.first_line, r.last_line],
                           "error": r.error} for r in results if not r.ok],
        "duplicate_lines": [{"line": d, "duplicate_of": o} for d, o in sorted(ctx.duplicates.items())],
        "recommended_actions": _actions(findings, correlations),
    }
