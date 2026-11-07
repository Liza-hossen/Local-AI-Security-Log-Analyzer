"""Token estimation.

We do not ship the Qwen tokenizer (it would need an online download), so we use a
pessimistic chars-per-token ratio from config. Over-counting wastes a little
budget; under-counting would overflow the 2,048-token window, which is worse.
"""
import math

import config


def estimate_tokens(text: str) -> int:
    return math.ceil(len(text) / config.CHARS_PER_TOKEN)


def truncate_to_tokens(text: str, max_tokens: int) -> str:
    """Cut text so it (plus the truncation marker) fits in max_tokens."""
    if estimate_tokens(text) <= max_tokens:
        return text
    max_chars = int(max_tokens * config.CHARS_PER_TOKEN) - len(config.TRUNCATION_MARKER)
    return text[: max(max_chars, 0)] + config.TRUNCATION_MARKER
