from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.azure import AzureProvider

from auto_soc.config import settings


def make_azure_model() -> OpenAIChatModel:
    """Return an OpenAIChatModel pointed at Azure Foundry via APIM.

    AzureProvider constructs: {azure_endpoint}/openai/deployments/{deployment}/chat/completions
    Our APIM path is: /openai/openai/deployments/{deployment}/chat/completions
    So apim_endpoint must be https://bbapim.azure-api.net/openai (AzureProvider appends /openai/...)
    """
    provider = AzureProvider(
        azure_endpoint=settings.apim_endpoint,
        api_key=settings.apim_key,
        api_version=settings.apim_api_version,
    )
    return OpenAIChatModel(
        settings.apim_deployment,
        provider=provider,
    )
