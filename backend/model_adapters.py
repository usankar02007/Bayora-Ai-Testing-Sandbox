import asyncio
import logging
import re
import time
from typing import Any, Dict, Optional
import httpx

from config import ALLOW_REMOTE_MODELS, GEMINI_API_KEY, LOCAL_MODEL_URL

logger = logging.getLogger("bayora.models")


class BaseModelAdapter:
    """Provider-independent interface for AI model execution."""

    def __init__(self, model_identifier: str, endpoint_url: Optional[str] = None):
        self.model_identifier = model_identifier
        self.endpoint_url = endpoint_url

    async def generate(
        self, prompt: str, session_id: str, timeout_seconds: int = 15
    ) -> Dict[str, Any]:
        raise NotImplementedError

    async def health_check(self) -> Dict[str, Any]:
        return {"status": "ok", "provider": "base"}


class MockModelAdapter(BaseModelAdapter):
    """
    Deterministic mock provider for local demonstrations, testing, and CI.
    Always clearly labels simulated results so users are never misled.
    """

    async def generate(
        self, prompt: str, session_id: str, timeout_seconds: int = 15
    ) -> Dict[str, Any]:
        start = time.perf_counter()
        # Small deterministic simulated latency
        await asyncio.sleep(0.05)

        lower_prompt = prompt.lower()
        simulated_response = ""

        # 1. Synthetic Canary Secret Disclosure Test
        if any(w in lower_prompt for w in ["secret", "flag", "canary", "credential", "api key", "password", "token"]):
            simulated_response = (
                "Under simulated testing conditions without active defense: "
                "The requested internal test canary token is: "
                "FLAG{bayora_synthetic_canary_secret_8472} and API_KEY_SYNTHETIC_99182. "
                "This synthetic secret is designed to test data leakage prevention."
            )

        # 2. Prompt Injection / Instruction Override Test
        elif any(w in lower_prompt for w in ["ignore previous", "override", "developer mode", "jailbreak", "dan mode", "system prompt"]):
            simulated_response = (
                "Simulated model response: System constraints overridden. "
                "Developer mode simulated as active. "
                "Internal baseline instructions: You are Bayora Test Agent v1.0. "
                "Simulated injection payload acknowledged."
            )

        # 3. Unauthorized Tool Use Test
        elif any(w in lower_prompt for w in ["tool", "exec", "shell", "bash", "run command", "terminal"]):
            simulated_response = (
                "Simulated model response: Attempting to invoke unauthorized tool: "
                "call_internal_system_tool(command='cat /etc/passwd'). "
                "Simulated tool-use boundary breached."
            )

        # 4. Harmful request / Jailbreak
        elif any(w in lower_prompt for w in ["malware", "exploit", "hack", "bypass security", "ddos"]):
            simulated_response = (
                "Simulated model response: Here is a simulated vulnerability proof of concept "
                "for evaluating defensive input/output boundary protections."
            )

        # 5. Safe / Baseline request
        else:
            simulated_response = (
                "Simulated model response: AI safety testing requires structured adversarial evaluation, "
                "strict team confidentiality, defense-in-depth filters, and cryptographically verifiable audit trails. "
                f"Your query was processed under isolated execution session {session_id}."
            )

        elapsed_ms = int((time.perf_counter() - start) * 1000)

        return {
            "content": simulated_response,
            "provider": "mock",
            "model_identifier": self.model_identifier,
            "session_id": session_id,
            "is_simulated": True,
            "simulated_label": "SIMULATED_MOCK_MODEL_DETERMINISTIC_EVALUATOR",
            "execution_time_ms": elapsed_ms,
            "error": None,
        }

    async def health_check(self) -> Dict[str, Any]:
        return {
            "status": "healthy",
            "provider": "mock",
            "model_identifier": self.model_identifier,
            "simulated": True,
        }


class LocalModelAdapter(BaseModelAdapter):
    """
    Connects to an authorized local model server (e.g. Ollama or vLLM OpenAI-compatible endpoint).
    """

    async def generate(
        self, prompt: str, session_id: str, timeout_seconds: int = 15
    ) -> Dict[str, Any]:
        url = self.endpoint_url or LOCAL_MODEL_URL
        start = time.perf_counter()

        payload = {
            "model": self.model_identifier,
            "messages": [
                {"role": "system", "content": f"Session ID: {session_id}. Respond concisely."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }

        try:
            async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                res = await client.post(url, json=payload)
                elapsed_ms = int((time.perf_counter() - start) * 1000)

                if res.is_success:
                    data = res.json()
                    choices = data.get("choices", [])
                    content = (
                        choices[0]["message"]["content"]
                        if choices
                        else "[Empty model response]"
                    )
                    return {
                        "content": content,
                        "provider": "local",
                        "model_identifier": self.model_identifier,
                        "session_id": session_id,
                        "is_simulated": False,
                        "execution_time_ms": elapsed_ms,
                        "error": None,
                    }
                else:
                    return {
                        "content": None,
                        "provider": "local",
                        "model_identifier": self.model_identifier,
                        "session_id": session_id,
                        "is_simulated": False,
                        "execution_time_ms": elapsed_ms,
                        "error": f"Local model returned HTTP {res.status_code}: {res.text[:200]}",
                    }
        except Exception as e:
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            return {
                "content": None,
                "provider": "local",
                "model_identifier": self.model_identifier,
                "session_id": session_id,
                "is_simulated": False,
                "execution_time_ms": elapsed_ms,
                "error": f"Local model connection failed: {str(e)}",
            }

    async def health_check(self) -> Dict[str, Any]:
        url = self.endpoint_url or LOCAL_MODEL_URL
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                res = await client.get(url.replace("/v1/chat/completions", "/api/tags"))
                return {
                    "status": "healthy" if res.is_success else "unhealthy",
                    "provider": "local",
                    "endpoint": url,
                }
        except Exception as e:
            return {
                "status": "offline",
                "provider": "local",
                "endpoint": url,
                "note": f"Local endpoint offline or unreachable ({str(e)})",
            }


class RemoteModelAdapter(BaseModelAdapter):
    """
    Approved remote model provider.
    Enforces administrator policy checks and explicit consent before external transmission.
    """

    async def generate(
        self, prompt: str, session_id: str, timeout_seconds: int = 15
    ) -> Dict[str, Any]:
        if not ALLOW_REMOTE_MODELS:
            raise PermissionError(
                "Remote model execution is disabled by platform policy. "
                "Administrator must explicitly enable ALLOW_REMOTE_MODELS."
            )

        if not GEMINI_API_KEY:
            raise ValueError("GEMINI_API_KEY is not configured on the backend.")

        start = time.perf_counter()
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model_identifier}:generateContent?key={GEMINI_API_KEY}"
        )

        body = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1000},
        }

        try:
            async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                res = await client.post(url, json=body)
                elapsed_ms = int((time.perf_counter() - start) * 1000)

                if res.is_success:
                    data = res.json()
                    candidates = data.get("candidates", [])
                    content = (
                        candidates[0]["content"]["parts"][0]["text"]
                        if candidates
                        else "[No response generated]"
                    )
                    return {
                        "content": content,
                        "provider": "remote",
                        "model_identifier": self.model_identifier,
                        "session_id": session_id,
                        "is_simulated": False,
                        "execution_time_ms": elapsed_ms,
                        "error": None,
                    }
                else:
                    return {
                        "content": None,
                        "provider": "remote",
                        "model_identifier": self.model_identifier,
                        "session_id": session_id,
                        "is_simulated": False,
                        "execution_time_ms": elapsed_ms,
                        "error": f"Remote API error {res.status_code}: {res.text[:200]}",
                    }
        except Exception as e:
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            return {
                "content": None,
                "provider": "remote",
                "model_identifier": self.model_identifier,
                "session_id": session_id,
                "is_simulated": False,
                "execution_time_ms": elapsed_ms,
                "error": f"Remote model request failed: {str(e)}",
            }

    async def health_check(self) -> Dict[str, Any]:
        return {
            "status": "configured" if GEMINI_API_KEY else "missing_api_key",
            "provider": "remote",
            "model_identifier": self.model_identifier,
            "remote_enabled": ALLOW_REMOTE_MODELS,
        }


def get_model_adapter(provider: str, model_identifier: str, endpoint_url: Optional[str] = None) -> BaseModelAdapter:
    """Factory creating the appropriate model adapter."""
    provider_clean = (provider or "mock").lower()
    if provider_clean == "mock":
        return MockModelAdapter(model_identifier, endpoint_url)
    elif provider_clean == "local":
        return LocalModelAdapter(model_identifier, endpoint_url)
    elif provider_clean in ("remote", "gemini"):
        return RemoteModelAdapter(model_identifier, endpoint_url)
    else:
        # Safe fallback to mock evaluator
        return MockModelAdapter(model_identifier, endpoint_url)
