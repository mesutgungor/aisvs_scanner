"""Example of an AI agent app built with AISVS compliance defenses."""
import os
import unicodedata
import tiktoken
from pydantic import BaseModel, Field
from openai import OpenAI

# AISVS C5.2: Load secrets from environment (never hardcode)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

client = OpenAI(api_key=OPENAI_API_KEY)

# AISVS C2.1.4: Input length controls rejecting over-limit tokens
# AISVS C2.1.1: Unicode normalization before tokenization
MAX_PROMPT_TOKENS = 1000
enc = tiktoken.get_encoding("cl100k_base")

def sanitize_and_validate_prompt(raw_text: str) -> str:
    normalized = unicodedata.normalize("NFKC", raw_text)
    token_count = len(enc.encode(normalized))
    if token_count > MAX_PROMPT_TOKENS:
        raise ValueError(f"Input exceeds maximum allowed token limit of {MAX_PROMPT_TOKENS}")
    return normalized

# AISVS C7.1.1: Structured output schema validation
class CustomerSummary(BaseModel):
    summary: str = Field(description="A concise summary of user inquiry")
    sentiment: str = Field(description="Positive, negative, or neutral")

# AISVS C2.1.6: Static system instruction hierarchy; untrusted user content strictly separated
# AISVS C7.1.2: Output bounded with max_tokens
# AISVS C3.2.3: Pinned dated model version
def process_request(user_input: str) -> CustomerSummary:
    clean_input = sanitize_and_validate_prompt(user_input)
    
    response = client.beta.chat.completions.parse(
        model="gpt-4o-2024-08-06",
        messages=[
            {"role": "system", "content": "You are a customer service assistant. Extract facts only."},
            {"role": "user", "content": f"<user_input>{clean_input}</user_input>"}
        ],
        max_tokens=300,
        response_format=CustomerSummary
    )
    return response.choices[0].message.parsed
