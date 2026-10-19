"""
Thin wrapper around the Gemini API. The rest of the agent only calls
complete_json() and embed() and never needs to know which provider is behind them.
"""

import json
import os
import time

from dotenv import load_dotenv

import embeddings
from prompts import SYSTEM_PROMPT

load_dotenv()

# "gemini-flash-latest" is an alias Google keeps pointing at its current Flash model.
MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-flash-latest")

FALLBACK_MODEL = os.getenv("GEMINI_FALLBACK_MODEL", "gemini-flash-lite-latest")

_client = None


def _get_client():
    """Created on first use, so the local embedder works without any API key."""
    global _client
    if _client is None:
        from google import genai

        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY is not set (put it in agents-python/.env)")
        _client = genai.Client(api_key=api_key)
    return _client


def complete_json(prompt: str, attempts: int = 4) -> dict:
    """Send a prompt to Gemini and return the parsed JSON object.
    Retries a few times (the free tier sometimes returns 503 'busy').
    Raises RuntimeError if every attempt fails."""
    from google.genai import types

    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            # the free tier's main model is sometimes overloaded: use the lighter one for later attempts
            response = _get_client().models.generate_content(
                model=MODEL_NAME if attempt <= 2 or not FALLBACK_MODEL else FALLBACK_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT,
                    response_mime_type="application/json",
                    temperature=0.2,
                ),
            )
            return json.loads(response.text)
        except Exception as e:  # noqa: BLE001
            last_error = e
            if attempt < attempts:
                time.sleep(4 * attempt)
    raise RuntimeError(f"Gemini failed after {attempts} attempts: {last_error}")


def embed(text: str):
    """Returns a normalised 768-number embedding of the text (provider chosen by EMBED_PROVIDER)."""
    if embeddings.provider() == "local":
        return embeddings.local_embed(text)
    return embeddings.gemini_embed(text, _get_client())
