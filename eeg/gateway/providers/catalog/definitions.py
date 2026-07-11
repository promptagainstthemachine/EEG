"""EEG gateway provider catalog — 75+ vendors with capability metadata."""
from __future__ import annotations

from eeg.gateway.providers.catalog.types import (
    CHAT_CAPS,
    CHAT_EMBED_CAPS,
    FULL_OPENAI_CAPS,
    ProviderDefinition,
)


def _oa(
    pid: str,
    name: str,
    base_url: str,
    caps: frozenset[str] = CHAT_CAPS,
    *,
    auth_style: str = "bearer",
) -> ProviderDefinition:
    return ProviderDefinition(
        id=pid,
        name=name,
        family="openai",
        base_url=base_url.rstrip("/"),
        capabilities=caps,
        auth_style=auth_style,  # type: ignore[arg-type]
    )


def _embed(pid: str, name: str, base_url: str) -> ProviderDefinition:
    return _oa(pid, name, base_url, frozenset({"embed"}))


def _image(pid: str, name: str, base_url: str) -> ProviderDefinition:
    return _oa(pid, name, base_url, frozenset({"image"}))


PROVIDER_DEFINITIONS: tuple[ProviderDefinition, ...] = (
    # --- Full OpenAI surface ---
    _oa("openai", "OpenAI", "https://api.openai.com/v1", FULL_OPENAI_CAPS),
    _oa("azure-openai", "Azure OpenAI", "https://{resource}.openai.azure.com/openai/deployments/{deployment}", CHAT_EMBED_CAPS),
    # --- Enterprise (handled by dedicated adapters) ---
    ProviderDefinition("anthropic", "Anthropic", "anthropic", "https://api.anthropic.com/v1", CHAT_CAPS | frozenset({"mcp_toolsets"}), "x-api-key"),
    ProviderDefinition("bedrock", "Amazon Bedrock", "bedrock", "", CHAT_CAPS | frozenset({"embed", "image", "speech"})),
    ProviderDefinition("vertex", "Google Vertex AI", "vertex", "", CHAT_CAPS | frozenset({"embed", "image"})),
    ProviderDefinition("azure_foundry", "Azure AI Foundry", "azure_foundry", "", CHAT_CAPS | frozenset({"embed", "image", "speech", "transcription"})),
    ProviderDefinition("google", "Google Gemini", "google", "https://generativelanguage.googleapis.com/v1beta", CHAT_CAPS | frozenset({"embed", "image"})),
    ProviderDefinition("vertex-ai", "Google Vertex (OpenAI compat)", "vertex", "", CHAT_CAPS | frozenset({"embed", "image"})),
    ProviderDefinition("cohere", "Cohere", "cohere", "https://api.cohere.com/v2", CHAT_EMBED_CAPS, "bearer"),
    # --- High-volume OpenAI-compatible inference ---
    _oa("groq", "Groq", "https://api.groq.com/openai/v1"),
    _oa("together-ai", "Together AI", "https://api.together.xyz/v1", CHAT_EMBED_CAPS | frozenset({"image"})),
    _oa("deepseek", "DeepSeek", "https://api.deepseek.com/v1"),
    _oa("mistral-ai", "Mistral AI", "https://api.mistral.ai/v1", CHAT_EMBED_CAPS),
    _oa("fireworks-ai", "Fireworks AI", "https://api.fireworks.ai/inference/v1", CHAT_EMBED_CAPS),
    _oa("perplexity-ai", "Perplexity", "https://api.perplexity.ai"),
    _oa("openrouter", "OpenRouter", "https://openrouter.ai/api/v1", CHAT_EMBED_CAPS),
    _oa("anyscale", "Anyscale Endpoints", "https://api.endpoints.anyscale.com/v1"),
    _oa("deepinfra", "DeepInfra", "https://api.deepinfra.com/v1/openai", CHAT_EMBED_CAPS | frozenset({"image"})),
    _oa("siliconflow", "SiliconFlow", "https://api.siliconflow.cn/v1", CHAT_EMBED_CAPS | frozenset({"image"})),
    _oa("novita-ai", "Novita AI", "https://api.novita.ai/v3/openai", CHAT_CAPS | frozenset({"image"})),
    _oa("monsterapi", "MonsterAPI", "https://api.monsterapi.ai/v1"),
    _oa("predibase", "Predibase", "https://serving.app.predibase.com/v1"),
    _oa("lepton", "Lepton AI", "https://api.lepton.ai/api/v1", CHAT_EMBED_CAPS | frozenset({"transcription"})),
    _oa("hyperbolic", "Hyperbolic", "https://api.hyperbolic.xyz/v1", CHAT_CAPS | frozenset({"image"})),
    _oa("nebius", "Nebius", "https://api.studio.nebius.ai/v1", CHAT_EMBED_CAPS),
    _oa("nscale", "Nscale", "https://inference.api.nscale.com/v1"),
    _oa("kluster-ai", "Kluster AI", "https://api.kluster.ai/v1"),
    _oa("featherless-ai", "Featherless AI", "https://api.featherless.ai/v1"),
    _oa("inference-net", "Inference.net", "https://api.inference.net/v1"),
    _oa("lemonfox-ai", "Lemonfox AI", "https://api.lemonfox.ai/v1", CHAT_CAPS | frozenset({"speech", "transcription"})),
    _oa("modal", "Modal", "https://api.modal.com/v1"),
    _oa("cometapi", "CometAPI", "https://api.cometapi.com/v1"),
    _oa("matterai", "Matter AI", "https://api.matterai.ai/v1"),
    _oa("nextbit", "Nextbit", "https://api.nextbit.ai/v1"),
    _oa("bytez", "Bytez", "https://api.bytez.com/v1"),
    _oa("krutrim", "Krutrim", "https://api.krutrim.com/v1"),
    _oa("302ai", "302.AI", "https://api.302.ai/v1"),
    _oa("aibadgr", "AI Badgr", "https://api.aibadgr.com/v1"),
    _oa("iointelligence", "IO Intelligence", "https://api.iointelligence.io/v1"),
    _oa("ovhcloud", "OVHcloud AI", "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1"),
    _oa("lambda", "Lambda Labs", "https://api.lambdalabs.com/v1"),
    _oa("deepbricks", "DeepBricks", "https://api.deepbricks.ai/v1"),
    _oa("cerebras", "Cerebras", "https://api.cerebras.ai/v1"),
    _oa("sambanova", "SambaNova", "https://api.sambanova.ai/v1"),
    _oa("x-ai", "xAI", "https://api.x.ai/v1"),
    _oa("upstage", "Upstage", "https://api.upstage.ai/v1/solar"),
    _oa("lingyi", "Lingyi Wanwu", "https://api.lingyiwanwu.com/v1"),
    _oa("zhipu", "Zhipu AI", "https://open.bigmodel.cn/api/paas/v4"),
    _oa("moonshot", "Moonshot", "https://api.moonshot.cn/v1"),
    _oa("z-ai", "Z.AI", "https://api.z.ai/api/paas/v4"),
    _oa("dashscope", "Alibaba DashScope", "https://dashscope.aliyuncs.com/compatible-mode/v1", CHAT_EMBED_CAPS),
    _oa("ollama", "Ollama", "http://127.0.0.1:11434/v1", CHAT_EMBED_CAPS, auth_style="none"),
    _oa("github", "GitHub Models", "https://models.inference.ai.azure.com"),
    _oa("azure-ai", "Azure AI Inference", "https://models.inference.ai.azure.com"),
    _oa("huggingface", "Hugging Face Inference", "https://api-inference.huggingface.co/v1"),
    _oa("reka-ai", "Reka AI", "https://api.reka.ai/v1"),
    _oa("ncompass", "NCompass", "https://api.ncompass.tech/v1"),
    _oa("ai21", "AI21 Labs", "https://api.ai21.com/studio/v1"),
    _oa("palm", "Google PaLM", "https://generativelanguage.googleapis.com/v1beta", CHAT_CAPS),
    _oa("triton", "NVIDIA Triton", "http://127.0.0.1:8000/v1"),
    _oa("workers-ai", "Cloudflare Workers AI", "https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/v1"),
    _oa("sagemaker", "AWS SageMaker", "https://runtime.sagemaker.{region}.amazonaws.com/endpoints/{endpoint}/invocations"),
    _oa("oracle", "Oracle GenAI", "https://inference.generativeai.{region}.oci.oraclecloud.com"),
    _oa("baseten", "Baseten", "https://model-{model_id}.api.baseten.co/v1"),
    _oa("friendli", "FriendliAI", "https://api.friendli.ai/v1"),
    _oa("watsonx", "IBM watsonx", "https://{region}.ml.cloud.ibm.com/ml/v1"),
    _oa("aleph-alpha", "Aleph Alpha", "https://api.aleph-alpha.com/v1"),
    _oa("clarifai", "Clarifai", "https://api.clarifai.com/v2"),
    _oa("novita", "Novita", "https://api.novita.ai/v3/openai"),
    _oa("fireworks", "Fireworks", "https://api.fireworks.ai/inference/v1", CHAT_EMBED_CAPS),
    _oa("mistral", "Mistral", "https://api.mistral.ai/v1", CHAT_EMBED_CAPS),
    _oa("groq-cloud", "Groq Cloud", "https://api.groq.com/openai/v1"),
    _oa("openai-compatible", "OpenAI Compatible", "https://api.openai.com/v1", FULL_OPENAI_CAPS),
    # --- Embed specialists ---
    _embed("jina", "Jina AI", "https://api.jina.ai/v1"),
    _embed("voyage", "Voyage AI", "https://api.voyageai.com/v1"),
    _embed("nomic", "Nomic", "https://api.nomic.ai/v1"),
    _embed("qdrant", "Qdrant Cloud", "https://{cluster}.qdrant.io"),
    _embed("milvus", "Milvus", "https://api.zillizcloud.com/v1"),
    # --- Image / media ---
    _image("stability-ai", "Stability AI", "https://api.stability.ai/v2beta"),
    _image("segmind", "Segmind", "https://api.segmind.com/v1"),
    _image("recraft-ai", "Recraft AI", "https://external.api.recraft.ai/v1"),
    _image("replicate", "Replicate", "https://api.replicate.com/v1"),
    _image("meshy", "Meshy", "https://api.meshy.ai/v2"),
    _image("tripo3d", "Tripo3D", "https://api.tripo3d.ai/v2/openapi"),
    _image("nscale-image", "Nscale Image", "https://inference.api.nscale.com/v1/images"),
)

PROVIDER_BY_ID: dict[str, ProviderDefinition] = {p.id: p for p in PROVIDER_DEFINITIONS}

ENTERPRISE_PROVIDER_IDS: frozenset[str] = frozenset(
    {"anthropic", "bedrock", "vertex", "vertex-ai", "azure_foundry"}
)

BACKEND_TO_PROVIDER: dict[str, str] = {
    "openai": "openai",
    "anthropic": "anthropic",
    "bedrock": "bedrock",
    "vertex": "vertex",
    "azure_foundry": "azure_foundry",
}
