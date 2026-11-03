"""Detect which AI components a target uses, so requirements can be marked N/A when irrelevant."""
from __future__ import annotations

import re
from typing import Dict, Iterable, List

from .walker import FileCtx, CODE_LANGS

# feature -> list of (regex, optional restrict-to-langs)
_CODE_AND_DEPS = CODE_LANGS | {"requirements", "toml", "json", "yaml", "config", "dockerfile", "gradle"}

FEATURE_PATTERNS: Dict[str, List[str]] = {
    "llm": [
        r"\b(?:from|import)\s+(?:openai|anthropic|litellm|cohere|mistralai|ollama|groq|together|replicate|"
        r"google\.generativeai|google\.genai|vertexai|langchain\w*|llama_index|llama_cpp|vllm|"
        r"transformers|huggingface_hub|openllm|guidance|dspy|instructor|semantic_kernel|haystack|"
        r"autogen\w*|crewai|pydantic_ai|smolagents|agents)\b",
        r"""require\(['"](?:openai|@anthropic-ai/sdk|langchain|@langchain/[\w-]+|ollama|@google/generative-ai|ai)['"]\)""",
        r"""from\s+['"](?:openai|@anthropic-ai/sdk|langchain|@langchain/[\w-]+|ollama|@google/generative-ai|ai|@ai-sdk/[\w-]+)['"]""",
        r"\b(?:chat\.completions|messages|responses)\.create\s*\(",
        r"\bbedrock-runtime\b|\binvoke_model\b|\bconverse\s*\(",
        r"\bgenerativeai\b|\bGenerativeModel\s*\(",
        r"\b(?:ChatOpenAI|ChatAnthropic|AzureChatOpenAI|OpenAI|Anthropic|AsyncOpenAI|AsyncAnthropic|ChatOllama)\s*\(",
        r"^\s*(?:openai|anthropic|litellm|langchain[\w-]*|llama[-_]index[\w-]*|transformers|vllm|cohere|"
        r"google-generativeai|ollama|mistralai|huggingface[-_]hub)\b",
        r"\"(?:openai|@anthropic-ai/sdk|langchain|ai|ollama|@langchain/\w+)\"\s*:",
        r"api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.mistral\.ai",
    ],
    "rag": [
        r"\b(?:chromadb|pinecone|weaviate|qdrant_client|faiss|pgvector|pymilvus|lancedb|elasticsearch_dsl|"
        r"opensearchpy|redisvl|vecs|annoy|hnswlib|sentence_transformers)\b",
        r"\b(?:VectorStoreIndex|VectorStore|similarity_search|as_retriever|RetrievalQA|ConversationalRetrievalChain|"
        r"create_retrieval_chain|OpenAIEmbeddings|HuggingFaceEmbeddings|embeddings\.create|embed_documents|"
        r"embed_query|SentenceTransformer|RecursiveCharacterTextSplitter|knn_search|vector_search)\b",
        r"\b(?:qdrant|chroma|weaviate|milvus|pinecone|pgvector)\b",
    ],
    "agent": [
        r"\b(?:langgraph|autogen|crewai|smolagents|pydantic_ai|llama_index\.core\.agent|AgentExecutor|"
        r"create_react_agent|create_tool_calling_agent|initialize_agent|ReActAgent|FunctionTool|"
        r"function_tool|StructuredTool|BaseTool|AssistantAgent|UserProxyAgent|openai_agents|Swarm)\b",
        r"^\s*@(?:tool|function_tool|mcp\.tool|server\.tool|\w+\.tool)\b",
        r"\btools\s*=\s*\[",
        r"""\btool_choice\b|\btool_calls\b|\bfunction_call\b|\btool_use\b""",
        r"\bAgent\s*\(\s*(?:name|instructions|model)\b",
    ],
    "mcp_server": [
        r"\b(?:from|import)\s+mcp(?:\.server)?\b.*\b(?:FastMCP|Server|fastmcp)\b|\bFastMCP\s*\(",
        r"\bfrom\s+fastmcp\b|\bimport\s+fastmcp\b",
        r"@modelcontextprotocol/sdk/server|new\s+McpServer\s*\(|\bserver\.(?:tool|registerTool|setRequestHandler)\s*\(",
        r"\bmcp\.server\b|\bStdioServerTransport\b|\bStreamableHTTPServerTransport\b|\bSSEServerTransport\b",
        r"\bmcp-go\b|\bmcp_server\b|\bMCPServer\b",
    ],
    "mcp_client": [
        r"\bClientSession\b|\bstdio_client\b|\bsse_client\b|\bstreamablehttp_client\b|\bMCPClient\b",
        r"@modelcontextprotocol/sdk/client|new\s+Client\s*\(\s*\{[^}]*name",
        r"\bMultiServerMCPClient\b|\bMCPServerStdio\b|\bMCPServerSse\b|\bMCPToolset\b|\bmcp_servers\b",
        r"\"mcpServers\"\s*:|\"mcp\.servers\"\s*:|\bmcpServers\b",
    ],
    "model_loading": [
        r"\b(?:torch\.load|pickle\.load|joblib\.load|from_pretrained|load_model|keras\.models\.load_model|"
        r"onnxruntime|InferenceSession|safetensors|load_file|AutoModel\w*|pipeline\s*\(|"
        r"hf_hub_download|snapshot_download|Llama\s*\(|llama_cpp|tf\.saved_model\.load|mlflow\.\w+\.load_model|"
        r"cloudpickle\.load|dill\.load|joblib\.dump|torch\.save|model\.save)\b",
    ],
    "training": [
        r"\b(?:Trainer|SFTTrainer|DPOTrainer|PPOTrainer|RewardTrainer|TrainingArguments|get_peft_model|LoraConfig|"
        r"model\.fit|optimizer\.step|loss\.backward|\.train\(\)|fine_tune|finetune|fine-tune|"
        r"fine_tuning\.jobs\.create|load_dataset|DataLoader|accelerate)\b",
        r"\bdvc\b|\bmlflow\.log_|\bwandb\.init\b",
    ],
    "rlhf": [r"\b(?:PPOTrainer|DPOTrainer|RewardTrainer|GRPOTrainer|KTOTrainer|ORPOTrainer|RLHF|rlhf|reward_model|trl)\b"],
    "quantization": [
        r"\b(?:BitsAndBytesConfig|bitsandbytes|load_in_4bit|load_in_8bit|AutoGPTQ|auto_gptq|AutoAWQ|awq|"
        r"quantize_dynamic|quantize_static|llama-quantize|optimum\.onnxruntime|post_training_quantiz\w*|"
        r"quantization_config|ctranslate2)\b",
    ],
    "edge": [
        r"\b(?:tflite|TensorFlowLite|coremltools|CoreML|ExecuTorch|executorch|onnxruntime-mobile|react-native-fast-tflite|"
        r"MLKit|mediapipe|llama\.rn|mlc-llm|MLCEngine)\b",
    ],
    "multimodal": [
        r"\b(?:image_url|input_audio|PIL\.Image|whisper|CLIP|vision|image_input|gpt-4o|gpt-4-vision|llava|"
        r"BlipProcessor|AutoProcessor|speech_to_text|text_to_speech|dall-e|stable-diffusion|diffusers)\b",
    ],
    "serving": [
        r"\b(?:FastAPI|APIRouter|Flask|flask|express|fastify|aiohttp\.web|starlette|uvicorn|gunicorn|django|"
        r"BentoML|bentoml|ray\.serve|TorchServe|triton|tritonclient|vllm\.entrypoints|text-generation-inference|"
        r"gradio|streamlit|chainlit|litserve)\b",
    ],
    "media_generation": [r"\b(?:diffusers|StableDiffusion\w*|dall-e|images\.generate|text-to-image|text_to_image|tts|TTS)\b"],
}

_COMPILED = {k: [re.compile(p, re.I | re.M) if k != "quantization" else re.compile(p, re.M) for p in v] for k, v in FEATURE_PATTERNS.items()}

# Files whose existence alone implies a feature.
FILENAME_FEATURES = {
    "mcp_client": {"mcp.json", ".mcp.json", "claude_desktop_config.json", "mcp_config.json", "cline_mcp_settings.json"},
    "agent": {"agents.md", "claude.md", ".cursorrules", ".windsurfrules", "copilot-instructions.md", "gemini.md"},
}


def detect(files: Iterable[FileCtx], max_samples: int = 3) -> Dict[str, List[str]]:
    found: Dict[str, List[str]] = {}
    for f in files:
        lname = f.name.lower()
        for feat, names in FILENAME_FEATURES.items():
            if lname in names:
                found.setdefault(feat, [])
                if len(found[feat]) < max_samples:
                    found[feat].append(f"{f.rel}")
        if f.lang == "artifact":
            if f.ext in {".tflite", ".mlmodel", ".mlpackage", ".pte"}:
                found.setdefault("edge", []).append(f.rel)
            found.setdefault("model_loading", [])
            if len(found["model_loading"]) < max_samples:
                found["model_loading"].append(f.rel)
            continue
        if f.lang not in _CODE_AND_DEPS or f.size > 1_500_000:
            continue
        text = f.text
        for feat, pats in _COMPILED.items():
            if feat in found and len(found[feat]) >= max_samples:
                continue
            for p in pats:
                m = p.search(text)
                if m:
                    found.setdefault(feat, [])
                    if len(found[feat]) < max_samples:
                        found[feat].append(f"{f.rel}:{f.line_of(m.start())}")
                    break
    return found
