"""Minimal AI providers — AnthropicClient only (for Claude code review)."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

import httpx


@dataclass
class AIResponse:
    """Standardized response from an AI provider."""
    content: str
    model: str
    provider: str
    usage: dict = field(default_factory=dict)
    raw_response: Optional[dict] = None


class BaseAIClient(ABC):
    """Base class for AI clients."""

    @abstractmethod
    async def chat(
        self,
        message: str,
        system_prompt: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> AIResponse:
        pass

    def is_available(self) -> bool:
        return False


class AnthropicClient(BaseAIClient):
    """Anthropic API client (Claude)."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        default_model: str = "claude-sonnet-4-20250514",
    ):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.default_model = default_model

    def is_available(self) -> bool:
        return bool(self.api_key)

    async def chat(
        self,
        message: str,
        system_prompt: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> AIResponse:
        headers = {
            "x-api-key": self.api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }

        payload = {
            "model": model or self.default_model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": message}],
        }

        if system_prompt:
            payload["system"] = system_prompt

        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers,
                json=payload,
                timeout=120.0,
            )
            response.raise_for_status()
            data = response.json()

            return AIResponse(
                content=data["content"][0]["text"],
                model=data["model"],
                provider="anthropic",
                usage=data.get("usage", {}),
                raw_response=data,
            )
