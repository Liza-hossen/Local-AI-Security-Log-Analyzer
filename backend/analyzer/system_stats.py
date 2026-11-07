"""RAM measurement for the status endpoint and benchmarks.

Ollama runs the model in a separate process (`llama-server` on this install,
`ollama_llama_server`/`ollama runner` on others), so we sum all of them.
"""
import os

import psutil

_MODEL_PROCESS_NAMES = ("ollama", "llama-server", "llama_server")


def backend_ram_mb() -> int:
    return psutil.Process(os.getpid()).memory_info().rss // 2**20


def model_ram_mb() -> int:
    total = 0
    for proc in psutil.process_iter(["name", "memory_info"]):
        name = (proc.info["name"] or "").lower()
        if name.startswith(_MODEL_PROCESS_NAMES) and proc.info["memory_info"]:
            total += proc.info["memory_info"].rss
    return total // 2**20
