"""Central settings for the analyzer.

Everything tunable lives here so it can be explained (and changed live) in one place.
Model settings can be overridden with environment variables.
"""
import os
from pathlib import Path

# ---------------------------------------------------------------- model / Ollama
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
# Primary: Qwen3.5 2B q4_K_M (~2.0 GB RAM measured). Fallback: qwen3.5:0.8b.
MODEL_NAME = os.getenv("MODEL_NAME", "qwen3.5:2b-q4_K_M")
FALLBACK_MODEL_NAME = os.getenv("FALLBACK_MODEL_NAME", "qwen3.5:0.8b")
TEMPERATURE = 0.1            # low = repeatable classifications
KEEP_ALIVE = "10m"           # keep the model loaded between chunks, free RAM after a run
REQUEST_TIMEOUT_S = 180      # one chunk takes ~20-30 s on CPU; generous for cold loads
MAX_ATTEMPTS = 3             # per chunk: first try + 2 retries
RETRY_BACKOFF_S = 2.0        # wait 2 s, then 4 s between attempts
MAX_FINDINGS_PER_CHUNK = 3   # keeps the JSON answer inside OUTPUT_TOKENS

# ---------------------------------------------------------------- token budget
# Hard cap for ONE model call, prompt + output together (num_ctx).
MAX_TOKENS_PER_CALL = 2048
SYSTEM_PROMPT_TOKENS = 350   # fixed instructions + output schema
CONTEXT_TOKENS = 250         # carried per-IP summary from earlier chunks
CHUNK_TOKENS = 850           # the log lines themselves
OUTPUT_TOKENS = 500          # reserved for the model's JSON answer (num_predict)
SAFETY_MARGIN_TOKENS = MAX_TOKENS_PER_CALL - (
    SYSTEM_PROMPT_TOKENS + CONTEXT_TOKENS + CHUNK_TOKENS + OUTPUT_TOKENS
)  # = 98, absorbs chat-template tokens and estimation error

# Fail fast if someone edits the numbers above into an impossible budget.
assert SAFETY_MARGIN_TOKENS >= 50, "token budget leaves no safety margin"

# Token counting: the real Qwen tokenizer is not available offline without an
# extra download, so we use a deliberately pessimistic estimate.
# Measured against Ollama's own prompt_eval_count (qwen3.5:2b) on the compact
# chunk text of the sample log: 2.09-2.28 chars per token (IPs, timestamps and
# symbols tokenize poorly). An earlier value of 3.0 UNDER-counted by ~35%.
# 1.8 over-counts by ~15-25%, which is the safe side.
CHARS_PER_TOKEN = 1.8
TRUNCATION_MARKER = " [truncated]"

# ---------------------------------------------------------------- uploads / storage
ALLOWED_EXTENSIONS = (".log", ".txt")
MAX_UPLOAD_MB = 50
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("DATA_DIR", BASE_DIR / "data"))
CORS_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]  # Vite dev server

# ---------------------------------------------------------------- correlation thresholds
BRUTE_FORCE_MIN_FAILURES = 5     # rule-based Brute Force finding
COMPROMISE_MIN_FAILURES = 3      # failures -> success -> privileged access sequence
SCAN_MIN_PATHS = 3               # rule-based Scanning finding
RATE_MIN_EVENTS = 3              # 429s or rate-window lines for Unusual Request Rate

# ---------------------------------------------------------------- pre-filter
# Successful GETs to these paths are routine and never sent to the model.
HEALTH_PATHS = ("/health", "/healthz", "/ready", "/livez")
# Responses at least this large are reported as a signal (possible data export).
LARGE_RESPONSE_BYTES = 1_000_000
