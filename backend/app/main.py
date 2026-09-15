"""
TraceCTF FastAPI application entrypoint.

Startup sequence:
  1. Initialize the database (create tables if not present)
  2. Check Ollama availability (log a warning, not a hard failure, if down)
  3. Start the background QueueWorker (batch + catch-up sweep loops)

Shutdown sequence:
  1. Stop the QueueWorker cleanly

Routers are included at the bottom as they're built in upcoming steps —
each new router file gets one `app.include_router(...)` line here.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.db.database import init_db
from app.pipeline.queue_worker import queue_worker
from app.pipeline.llm_client import OllamaClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("tracectf.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ---------- Startup ----------
    logger.info("Initializing database...")
    await init_db()

    llm_client = OllamaClient()
    if await llm_client.is_available():
        logger.info(f"Ollama is reachable — using model '{settings.ollama_model}'")
    else:
        logger.warning(
            "Ollama is NOT reachable at %s — pipeline will rely on rule-based "
            "fallback until Ollama is available.",
            settings.ollama_base_url,
        )

    queue_worker.start()
    logger.info("TraceCTF backend startup complete.")

    yield

    # ---------- Shutdown ----------
    logger.info("Shutting down QueueWorker...")
    await queue_worker.stop()
    logger.info("TraceCTF backend shutdown complete.")


app = FastAPI(
    title="TraceCTF",
    description="Evidence-grounded automatic CTF attack reconstruction and write-up system",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health_check():
    """
    Basic health check — also reports live Ollama reachability, so the
    frontend dashboard can show a warning banner if the LLM is down
    without needing a separate endpoint.
    """
    llm_client = OllamaClient()
    ollama_up = await llm_client.is_available()
    return {
        "status": "ok",
        "ollama_available": ollama_up,
        "ollama_model": settings.ollama_model,
    }


# ---------------------------------------------------------------------
# Routers — added incrementally as each is built in upcoming steps:
#
# from app.api.routes_session import router as session_router
# app.include_router(session_router)
#
# from app.api.routes_events import router as events_router
# app.include_router(events_router)
#
# from app.api.routes_findings import router as findings_router
# app.include_router(findings_router)
#
# from app.api.routes_writeup import router as writeup_router
# app.include_router(writeup_router)
#
# from app.api.ws_live import router as ws_router
# app.include_router(ws_router)
# ---------------------------------------------------------------------