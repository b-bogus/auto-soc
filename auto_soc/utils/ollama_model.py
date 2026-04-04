"""
Patched Ollama model that fixes the empty role bug in Ollama's OpenAI-compat layer.

Ollama sometimes returns `role: ""` instead of `role: "assistant"` for tool-call
response messages. PydanticAI's _validate_completion is an explicitly documented
override hook (see pydantic_ai/models/openai.py:746) designed for exactly this.
"""
import openai.types.chat as chat
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.ollama import OllamaProvider

from auto_soc.config import settings


class _OllamaCompatModel(OpenAIChatModel):
    """Subclass of OpenAIChatModel that patches two Ollama OpenAI-compat bugs:

    1. Ollama returns role='' in tool-call responses instead of 'assistant'.
       Fixed in _validate_completion.

    2. Ollama rejects content: null in assistant messages with tool_calls.
       PydanticAI sets content=None when the model makes a tool call with no text.
       Fixed in _map_model_response by replacing None with ''.
    """

    def _validate_completion(self, response: chat.ChatCompletion) -> chat.ChatCompletion:
        dumped = response.model_dump()
        # Fix 1: Ollama sometimes returns role='' instead of 'assistant'
        for choice in dumped.get("choices", []):
            msg = choice.get("message", {})
            if msg.get("role") == "":
                msg["role"] = "assistant"
        return chat.ChatCompletion.model_validate(dumped)

    def _map_model_response(self, message) -> chat.ChatCompletionMessageParam:  # type: ignore[override]
        result = super()._map_model_response(message)
        # Fix 2: Ollama rejects content: null — replace with empty string
        if result.get("content") is None:
            result = {**result, "content": ""}
        return result


def make_model():
    """Return the configured LLM model — Azure or Ollama based on LLM_PROVIDER setting."""
    if settings.llm_provider == "azure":
        from auto_soc.utils.azure_model import make_azure_model
        return make_azure_model()
    return make_ollama_model()


def make_ollama_model() -> _OllamaCompatModel:
    """Return a patched Ollama model using settings from config/env.

    OllamaProvider passes base_url directly to AsyncOpenAI without modification,
    so settings.ollama_host must already include /v1 (e.g. http://host:11434/v1).
    """
    provider = OllamaProvider(base_url=settings.ollama_host)
    return _OllamaCompatModel(settings.ollama_model, provider=provider)  # type: ignore[arg-type]
