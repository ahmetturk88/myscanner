"""Check the AI assistant configuration from inside the web container.

    docker compose ... exec web python scripts/ai_selfcheck.py

Prints which providers have a key, whether the configured model exists, and
whether a tiny explanation request succeeds. Keys are never printed.
"""
import json
import os
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from services import ai_assistant  # noqa: E402


def models(name, key):
    if name == 'gemini':
        response = requests.get('https://generativelanguage.googleapis.com/v1beta/models', headers={'x-goog-api-key': key},
                                params={'pageSize': 200}, timeout=20)
        return response.status_code, [m.get('name', '').removeprefix('models/') for m in response.json().get('models', [])] if response.ok else []
    response = requests.get('https://api.groq.com/openai/v1/models', headers={'Authorization': f'Bearer {key}'}, timeout=20)
    return response.status_code, [m.get('id', '') for m in response.json().get('data', [])] if response.ok else []


def main():
    configured = ai_assistant.providers()
    if not configured:
        print('FAIL: no AI provider key is configured (gemini_api_key / groq_api_key are empty).')
        return 1
    ok = True
    for name, key, model in configured:
        status, available = models(name, key)
        print(f'{name}: key accepted={status == 200} (HTTP {status}), configured model={model}')
        if status != 200:
            ok = False
            continue
        if model not in available and not (name == 'gemini' and model.endswith('-latest')):
            ok = False
            suggestions = [m for m in available if ('flash' in m if name == 'gemini' else 'gpt-oss' in m or 'llama' in m)][:8]
            print(f'  model not listed. Some available models: {", ".join(suggestions)}')
        try:
            explanation = ai_assistant.parse_explanation(ai_assistant.CALLERS[name](
                key, model, ai_assistant.SYSTEM_PROMPT,
                [{'role': 'user', 'text': ai_assistant._evidence_turn('ip', json.dumps({'ip': '1.1.1.1', 'verdict': 'not_found'}))
                  + '\n\nExplain this report. Write every text value in clear English.\n\n' + ai_assistant.EXPLAIN_FORMAT}],
                True, 2048))
            print(f'  PASS: sample explanation -> {explanation["headline"][:90]}')
        except Exception as error:  # report every provider, never stop at the first
            ok = False
            print(f'  FAIL: sample explanation ({type(error).__name__}: {str(error)[:120]})')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
