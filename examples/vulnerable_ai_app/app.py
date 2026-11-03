"""Example of an AI agent app with common AISVS security anti-patterns."""
import os
import pickle
from openai import OpenAI

# AISVS C5 / C9 Anti-pattern: Hard-coded secret
OPENAI_API_KEY = "sk-proj-999888777666555444333222111000aaabbbcccdddeee"

client = OpenAI(api_key=OPENAI_API_KEY)

# AISVS C2.1 Anti-pattern: Untrusted user input concatenated into developer/system prompt
def generate_answer(user_input: str):
    system_prompt = f"You are a helpful banking assistant. Context: {user_input}"
    # AISVS C7.1 Anti-pattern: No output max-tokens or length bounding
    # AISVS C3.2 Anti-pattern: Unpinned moving model alias
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "system", "content": system_prompt}]
    )
    # AISVS C7.1 / C9.3 Anti-pattern: Model output passed straight to shell execution sink
    output_text = response.choices[0].message.content
    os.system(output_text)
    return output_text

# AISVS C4.1 / C6.1 Anti-pattern: Deserializing untrusted pickle model weights
def load_cached_model(path: str):
    with open(path, "rb") as f:
        return pickle.load(f)
