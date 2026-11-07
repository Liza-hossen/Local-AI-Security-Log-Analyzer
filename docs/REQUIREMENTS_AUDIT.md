# Requirements Audit

**Source of requirements:** the original assessment brief was **not available** in the
workspace. This audit uses the requirements as written in `plan.md.md` (the Shared Context
Block, Prompts 0–5 and the manual checklist).
**PLACEHOLDER:** check this list against the original brief and add anything it requires that
`plan.md.md` leaves out.

Legend: **Done** = implemented and verified as described · **Partial** = implemented but not
fully verified, or only part of it · **Missing** = not implemented.
"Real run" means the sample log with the real `qwen3.5:2b-q4_K_M` through Ollama.

## Hard limits

| Requirement | Status | How it was verified |
|---|---|---|
| ≤ 4 GB RAM in total (model + backend) | **Done** (measured), with caveats | `llama-server` RSS sampled during calls: 1.44–1.61 GB; backend 25–60 MB. Highest reading 2.0 GB working set / 2.9 GB private right after loading. Not measured on a machine that actually has only 4 GB. After a model switch, both models stay loaded for 10 min. |
| 2 vCPU, no GPU | **Partial** | No GPU used. Tested only on 8 logical CPUs, so timings on 2 vCPU are unknown. |
| Local model through Ollama, no cloud APIs | **Done** | Code review: the only HTTP client call goes to `OLLAMA_URL` (localhost). |
| Works offline after setup | **Partial** | No external calls in the code, but **not tested with the network disconnected**. |
| ≤ 2,048 tokens per call, including output | **Done** | `num_ctx=2048`, `num_predict=500`, budget enforced in `config.py`. Real calls: largest 1,471 tokens; every sample chunk ≤ 786 real tokens (limit 850). |
| Log text is untrusted data | **Done** | System prompt, delimiters, newline flattening, tag neutralising; tests `test_injection_*`; real run: L217 not obeyed. |

## Model

| Requirement | Status | How it was verified |
|---|---|---|
| Qwen3.5 2B preferred, 0.8B fallback, real tags checked | **Done** | `ollama pull` of `qwen3.5:2b-q4_K_M` and `qwen3.5:0.8b` succeeded; `ollama list`. |
| Model name configurable | **Done** | `MODEL_NAME` environment variable; real chunk run with `qwen3.5:0.8b`. |
| Thinking disabled | **Done** | `"think": false`; answers were plain JSON of 140–441 tokens. |
| Measure RAM and time per call; say whether 2B fits | **Done** | README "Model details and measurements". |
| Gemma 4 E2B as an option | **Missing** | Not pulled or tested; it would only need `MODEL_NAME`, but that's unverified. |

## Core pipeline

| Requirement | Status | How it was verified |
|---|---|---|
| Stream the file; keep 1-based line numbers | **Done** | `parse_file` is a generator; tests `test_line_numbers_*`, `test_sample_log_parses_every_line`. |
| Group continuation / stack-trace lines | **Done** | `test_stack_trace_grouped_into_previous_entry`, `test_multiline_entry_stays_whole_in_one_chunk`. The sample has no multi-line entries. |
| Extract timestamp, IP, method, path, status, user, message | **Done** | `test_json_fields_extracted`, `test_plain_text_apache_line`. |
| Malformed lines don't crash and are kept | **Done** | `test_malformed_lines_kept_not_crashing`, `test_non_utf8_bytes_do_not_crash`. |
| Reject empty files and non-.log/.txt | **Done** | Unit + API tests; `.pdf` rejected in the real UI. |
| Token budget 350/250/850/≥500/~100 in config | **Done** | `config.py` (98 margin, assert); `test_budget_adds_up_to_2048`. |
| Qwen tokenizer or a stated conservative estimate | **Done** (estimate) | 1.8 chars/token, checked against real Ollama counts; reason in README. |
| Never split an entry; truncate oversized ones with a marker | **Done** | `test_chunks_respect_budget_and_never_split_entries`, `test_very_long_line_is_truncated_but_keeps_line_number`. |
| Pre-filter that never drops security events | **Done** | `test_security_events_are_never_filtered` (20 cases) and a check on the real sample. |
| Per-IP state across all chunks; ≤ 250-token summary per chunk | **Done** | `test_context_*`, `test_summary_*`; real summaries printed in the session. |
| Ollama: low temperature, JSON mode, bounded output, keep_alive, sequential, timeout, 2–3 retries with backoff, clear errors | **Done** | `ai_analyzer.py`; tests for timeout, retries running out, missing model, backoff timing. |
| Pydantic output schema with the required enums and fields | **Done** | `schemas.py`; the same schema is given to Ollama. |
| Validator: broken/truncated/extra-text JSON, invalid fields, invented lines | **Done** | `test_parse_*`, `test_fake_line_numbers_*`, `test_invalid_fields_*`, `test_evidence_from_another_ip_is_removed`. |
| One failed chunk never crashes the run; save each result immediately | **Done** | `test_one_failed_chunk_does_not_stop_the_run_*`, `test_failed_chunk_is_reported_and_run_continues`. |
| Correlation: merge duplicates, never count a line twice | **Done** | `test_duplicate_findings_merge_*`, `test_duplicate_log_lines_are_counted_once`; real run: L223 → L222. |
| Fail → success → admin sequence across chunks | **Done** | `test_cross_chunk_compromise_*` (events in different chunks); real run: Critical, spanning 7 chunks. |
| Attempted vs Blocked vs Possibly Successful | **Done** | `test_sqli_blocked_vs_answered`, `test_model_brute_force_upgraded_*`. |
| Don't call normal errors confirmed attacks | **Done** | `test_normal_errors_are_not_confirmed_attacks`; real run: 503s, timeouts, 500s and 502s not reported. |
| Raise severity for correlated stages | **Done** | Correlation tests; real run. |
| No hard-coded findings | **Done** | Tests use made-up logs; rules are generic and thresholds are in config. |
| Report: summary, totals, by severity/type, IPs, evidence, correlations, actions | **Done** | `test_run_job_report_totals_are_consistent`; real report. |
| API: upload, analyze, status (incl. RAM, elapsed), findings, report, download | **Done** | `test_full_flow`; used by the real UI. |
| Background task, one job at a time | **Done** | Single-worker executor; not stress-tested with many uploads at once. |
| Resume after restart (optional) | **Done** | `test_resume_skips_saved_chunks`; real re-run after a server restart (~1 s, no model calls). |

## Frontend

| Requirement | Status | How it was verified |
|---|---|---|
| Header with name and description | **Done** | Screenshot. |
| Upload area with validation errors, Start Analysis | **Done** | Browser test (`.pdf` error, button disabled). |
| Status panel: state, progress, chunk, entries, elapsed, RAM; polls /status | **Done** | Browser test screenshot during the run (chunk 4/11, 1,551 MB). |
| Findings table with distinct severity colors | **Done** | Screenshot. |
| Detail view: explanation, evidence lines, status, action, confidence | **Done** | Browser test: dialog with 3 raw evidence lines. |
| Report view with IPs, correlations, JSON download | **Done** | Browser test: report rendered, download link present. The downloaded file itself is checked by an API test. |
| Responsive | **Done** | 390 px wide: 0 px horizontal overflow (screenshot). |
| Handles API errors and failed chunks | **Partial** | Error messages, failed-chunk list and "Retry failed chunks" exist. A failure during a real run was **not** triggered in the UI (see the manual checklist). |

## Optional extras

| Extra | Status | Notes |
|---|---|---|
| Resume after restart | **Done** | see above |
| RAM display | **Done** | status panel |
| Model switching | **Partial** | Environment variable only (verified); no UI control. |
| PDF export | **Missing** | JSON only |

## Documentation

| Requirement | Status | Notes |
|---|---|---|
| README with all the requested sections | **Done** | Screenshots included (from the browser test). |
| AI_USAGE.md | **Partial** | Complete except for the author's real prompts (PLACEHOLDER). |
| 3–5 minute video script | **Done** | `docs/VIDEO_SCRIPT.md`; the video itself still has to be recorded. |

## Manual checklist (`plan.md.md`)

| Item | Status |
|---|---|
| Injection line in a test log has no effect | **Partial**: automated tests and sample L217 in two real runs; not yet done by hand |
| Empty file, `.pdf`, malformed lines through the UI | **Partial**: `.pdf` in the UI; the others through API and unit tests |
| Stop Ollama mid-run | **Not done**: only mocked |
| RAM in Task Manager | **Not done by hand**: measured with psutil instead |
| Re-read `chunker.py` and `context_manager.py` before the interview | Author's task |
