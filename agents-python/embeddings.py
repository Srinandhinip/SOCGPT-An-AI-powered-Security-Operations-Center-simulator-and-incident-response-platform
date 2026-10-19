"""
Embeddings for RAG over past incidents. The Java backend sends a short text describing an incident
and stores the returned 768 numbers in Postgres (pgvector).

Two providers (env EMBED_PROVIDER):
  gemini  (default) - Google's gemini-embedding-001 on the free tier, truncated to 768 dimensions
  local             - a deterministic hashing embedder: no network, no API key, no quota.
                      Good enough because the texts are short and structured.

If you change the provider (or model), call POST /api/rag/reindex on the Java backend as admin so
every stored incident is embedded the same way. Vectors from different providers must not be mixed.
"""

import hashlib
import math
import os
import re
import time

DIMENSIONS = 768


def provider() -> str:
    return os.getenv("EMBED_PROVIDER", "gemini").strip().lower()


def model_name() -> str:
    if provider() == "local":
        return "local-hash-768"
    return os.getenv("GEMINI_EMBED_MODEL", "gemini-embedding-001")


def _normalize(vec):
    norm = math.sqrt(sum(v * v for v in vec))
    if norm == 0:
        return vec
    return [v / norm for v in vec]


def local_embed(text: str):
    """Hashing trick over words and word pairs. Same text -> same vector, similar text -> close vector."""
    vec = [0.0] * DIMENSIONS
    tokens = re.findall(r"[a-z0-9]+", text.lower())
    features = tokens + [a + "_" + b for a, b in zip(tokens, tokens[1:])]
    for feature in features:
        digest = hashlib.sha256(feature.encode("utf-8")).digest()
        index = int.from_bytes(digest[:4], "big") % DIMENSIONS
        vec[index] += 1.0 if digest[4] & 1 else -1.0
    return _normalize(vec)


def gemini_embed(text: str, client, attempts: int = 2):
    """Embeds with Gemini. Raises RuntimeError when every attempt fails."""
    from google.genai import types

    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            response = client.models.embed_content(
                model=model_name(),
                contents=text,
                config=types.EmbedContentConfig(
                    task_type="SEMANTIC_SIMILARITY",
                    output_dimensionality=DIMENSIONS,
                ),
            )
            values = list(response.embeddings[0].values)
            if len(values) != DIMENSIONS:
                raise RuntimeError(f"expected {DIMENSIONS} dimensions, got {len(values)}")
            return _normalize(values)
        except Exception as e:  # noqa: BLE001
            last_error = e
            if attempt < attempts:
                time.sleep(2 * attempt)
    raise RuntimeError(f"Gemini embedding failed after {attempts} attempts: {last_error}")
