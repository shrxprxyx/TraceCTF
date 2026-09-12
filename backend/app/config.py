"""
Central configuration for TraceCTF backend.
Values can be overridden via a `.env` file placed in backend/ (optional).
"""

from pydantic_settings import BaseSettings
from pathlib import Path


class Settings(BaseSettings):
    # ---------- Project paths ----------
    project_root: Path = Path(__file__).resolve().parent.parent.parent
    data_dir: Path = project_root / "data"
    screenshots_dir: Path = data_dir / "screenshots"
    exports_dir: Path = data_dir / "exports"
    db_path: Path = data_dir / "tracectf.db"

    # ---------- Ollama / LLM settings ----------
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"          # fallback: "qwen2.5:3b" on low-RAM machines
    ollama_timeout_seconds: int = 30
    llm_max_retries: int = 2

    # ---------- Pipeline behavior ----------
    analysis_batch_interval_seconds: int = 8    # how often the background worker processes queued events
    analysis_batch_size: int = 20                # max events processed per batch
    use_rule_based_fallback: bool = True         # if LLM fails/unavailable, fall back to rule classifier

    # ---------- Capture settings ----------
    screenshot_auto_interval_seconds: int = 120  # periodic auto screenshot, 0 disables
    fs_watch_directory: str = ""                 # set per-session at runtime (working dir being watched)

    # ---------- Sensitive data masking ----------
    # Patterns are matched case-insensitively