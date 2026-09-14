"""Reproduce the pilot's failing OpenRouter request and print the exact error.

Sends the same payload shape the harness sends (chimera/models.py ~line 295),
with a one-token prompt and a one-token completion cap so a successful reply
costs well under $0.0001. Tries up to three variants and stops at the first
success, so the cost is bounded. Prints HTTP status and the response body.
"""

import json
import os
import sys

import httpx

KEY = os.environ.get("OPENROUTER_API_KEY")
if not KEY:
    sys.exit("OPENROUTER_API_KEY not set")

BASE = {
    "model": "z-ai/glm-5.3",
    "messages": [
        {"role": "system", "content": "Reply with the single word OK."},
        {"role": "user", "content": "OK"},
    ],
    "provider": {
        "only": ["reka/fp8"],
        "order": ["reka/fp8"],
        "allow_fallbacks": False,
        "require_parameters": True,
        "sort": "price",
        "max_price": {"prompt": 0.936, "completion": 3.168},
    },
    "reasoning": {"effort": "low"},
}

VARIANTS = [
    ("exact-harness-shape", {"max_completion_tokens": 1}, {}),
    ("max_tokens-instead", {"max_tokens": 1}, {}),
    ("no-require_parameters", {"max_completion_tokens": 1}, {"require_parameters": False}),
]

with httpx.Client(base_url="https://openrouter.ai", timeout=30, trust_env=False) as client:
    for name, token_field, provider_override in VARIANTS:
        payload = json.loads(json.dumps(BASE))
        payload.update(token_field)
        payload["provider"].update(provider_override)
        print(f"\n=== variant: {name} ===")
        print("payload:", json.dumps({k: v for k, v in payload.items() if k != "messages"}))
        response = client.post(
            "/api/v1/chat/completions",
            headers={
                "authorization": f"Bearer {KEY}",
                "content-type": "application/json",
                "x-openrouter-metadata": "enabled",
            },
            json=payload,
        )
        print("status:", response.status_code)
        text = response.text
        print("body:", text[:1500])
        if response.is_success:
            print("\nFIRST SUCCESS:", name)
            break
