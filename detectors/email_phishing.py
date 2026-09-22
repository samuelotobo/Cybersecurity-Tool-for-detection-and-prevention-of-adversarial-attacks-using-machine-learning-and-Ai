import json
import logging
import re

import requests

logger = logging.getLogger(__name__)

SUSPICIOUS_KEYWORDS = [
    "account verification", "billing", "payment", "invoice", "refund",
    "transaction", "credit card", "bank", "financial", "wire transfer",
    "unusual activity", "cryptocurrency", "bitcoin", "paypal", "visa",
    "mastercard", "security alert", "suspicious activity", "password reset",
    "verify your account", "unauthorized login", "data breach",
    "malware detected", "virus scan", "account suspended",
    "your account is locked", "microsoft support", "apple id",
    "google security", "amazon support", "facebook security",
    "urgent", "action required", "immediately", "critical update",
    "expiration", "congratulations", "you have won", "claim your prize",
    "free gift", "click here", "download now", "confirm your identity",
]

_GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


def _parse_email(content: str) -> dict:
    sender_m  = re.search(r"From:\s*(.*?)\n",    content, re.IGNORECASE)
    subject_m = re.search(r"Subject:\s*(.*?)\n", content, re.IGNORECASE)
    body  = content.split("\n\n", 1)[-1] if "\n\n" in content else content
    links = re.findall(r"https?://[^\s<>\"']+", body)
    return {
        "sender":  sender_m.group(1).strip()  if sender_m  else "N/A",
        "subject": subject_m.group(1).strip() if subject_m else "N/A",
        "body":    body,
        "links":   links,
    }


def _keyword_scan(text: str) -> list[str]:
    lowered = text.lower()
    return [kw for kw in SUSPICIOUS_KEYWORDS if kw in lowered]


def _call_groq(parsed: dict, matched: list[str], api_key: str, model: str) -> str:
    prompt = (
        "Analyze this email for phishing. Give a verdict (SAFE / LOW RISK / HIGH RISK) "
        "and a numbered list of reasons. Be concise.\n\n"
        f"From: {parsed['sender']}\n"
        f"Subject: {parsed['subject']}\n"
        f"Links: {', '.join(parsed['links']) or 'None'}\n"
        f"Local keywords matched: {', '.join(matched) or 'None'}\n"
        f"Body:\n{parsed['body'][:3000]}"
    )
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a cybersecurity analyst specialising in phishing detection. "
                    "Respond only with a structured analysis — verdict first, then numbered reasons. "
                    "No conversational filler."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 600,
    }
    resp = requests.post(
        _GROQ_URL,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json=payload,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


def _call_gemini(parsed: dict, matched: list[str], api_key: str, api_url: str) -> str:
    prompt = (
        "Analyze this email for phishing. Give a verdict (SAFE / LOW RISK / HIGH RISK) "
        "and a numbered list of reasons. Be concise.\n\n"
        f"From: {parsed['sender']}\n"
        f"Subject: {parsed['subject']}\n"
        f"Links: {', '.join(parsed['links']) or 'None'}\n"
        f"Local keywords matched: {', '.join(matched) or 'None'}\n"
        f"Body:\n{parsed['body'][:3000]}"
    )
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "systemInstruction": {
            "parts": [{
                "text": (
                    "You are a cybersecurity analyst specialising in phishing detection. "
                    "Respond only with a structured analysis — no conversational filler."
                )
            }]
        },
    }
    resp = requests.post(f"{api_url}?key={api_key}", json=payload, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return (
        data.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "No analysis returned.")
    )


def analyze_email(
    content: str,
    api_key: str = "",
    api_url: str = "",
    groq_api_key: str = "",
    groq_model: str = "openai/gpt-oss-120b",
) -> dict:
    """
    Analyse email content for phishing indicators.

    Runs a local keyword scan first. Then calls Groq (preferred) or
    Gemini (fallback) for AI analysis if a key is available.
    """
    parsed  = _parse_email(content)
    matched = _keyword_scan(content)

    result: dict = {
        "sender":             parsed["sender"],
        "subject":            parsed["subject"],
        "links_found":        parsed["links"],
        "suspicious_keywords": matched,
        "keyword_risk": (
            "HIGH"   if len(matched) >= 3
            else "MEDIUM" if matched
            else "LOW"
        ),
        "ai_analysis": None,
        "ai_provider":  None,
        "error":        None,
    }

    # ── Groq (preferred — free, fast) ────────────────────────────────────────
    if groq_api_key:
        try:
            result["ai_analysis"] = _call_groq(parsed, matched, groq_api_key, groq_model)
            result["ai_provider"] = f"Groq / {groq_model}"
            return result
        except requests.RequestException as e:
            result["error"] = f"Groq request failed: {e}"
        except (KeyError, IndexError, json.JSONDecodeError) as e:
            result["error"] = f"Groq response parse error: {e}"

    # ── Gemini (fallback) ─────────────────────────────────────────────────────
    if api_key and api_url:
        try:
            result["ai_analysis"] = _call_gemini(parsed, matched, api_key, api_url)
            result["ai_provider"] = "Gemini"
            result["error"] = None
            return result
        except requests.RequestException as e:
            result["error"] = f"Gemini request failed: {e}"
        except (KeyError, IndexError, json.JSONDecodeError) as e:
            result["error"] = f"Gemini response parse error: {e}"

    if not groq_api_key and not api_key:
        result["error"] = "No AI API key set — add GROQ_API_KEY to .env for AI analysis."

    return result
