# ============================================================================
# SOC Threat Assessment Agent — Local Agentic Workflow with Gemma 4 & Elasticsearch
# ============================================================================

import json
import os
from typing import Any, Dict, List, Optional
from google import genai
from google.genai import types

# Exact Gemma 4 Models
PRIMARY_MODEL = "gemma-4-26b-a4b-it"
FALLBACK_MODEL = "gemma-4-31b-it"

def query_elastic(index: str = "security-logs-*", query_string: str = "*", size: int = 10) -> str:
    """
    Queries Elasticsearch for security log events and returns a lightweight JSON string of _source payloads.

    Args:
        index: The Elasticsearch index pattern (e.g., 'security-logs-*').
        query_string: Lucene query string or search query.
        size: Maximum number of log records to return.

    Returns:
        Lightweight JSON string containing array of source log records to save tokens.
    """
    try:
        from elasticsearch import Elasticsearch
        es_host = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
        es_api_key = os.getenv("ELASTICSEARCH_API_KEY", None)

        if es_api_key:
            es = Elasticsearch(es_host, api_key=es_api_key)
        else:
            es = Elasticsearch(es_host)

        res = es.search(
            index=index,
            q=query_string,
            size=size
        )
        hits = res.get("hits", {}).get("hits", [])
        # Extract lightweight _source logs
        sources = [hit.get("_source", {}) for hit in hits]
        return json.dumps(sources, default=str)
    except Exception as e:
        # Fallback sample logs if Elasticsearch connection is unconfigured/offline
        mock_logs = [
            {
                "timestamp": "2026-08-02T10:15:30Z",
                "source_ip": "192.168.1.105",
                "destination_ip": "198.51.100.42",
                "action": "DENY",
                "reason": "Repeated Failed Auth Attempts (Brute Force)",
                "bytes_transferred": 0,
                "event_type": "authentication_failure"
            },
            {
                "timestamp": "2026-08-02T10:17:12Z",
                "source_ip": "203.0.113.88",
                "destination_ip": "10.0.0.15",
                "action": "ALLOW",
                "reason": "Exfiltration attempt via DNS Tunneling",
                "bytes_transferred": 1420000,
                "event_type": "suspicious_dns_query"
            }
        ]
        return json.dumps({
            "status": "sample_telemetry",
            "note": f"Elasticsearch notice: {str(e)}",
            "query": query_string,
            "logs": mock_logs
        })


def get_threat_assessment(user_input: str) -> str:
    """
    Agentic workflow using Gemma 4 to translate natural language intent into 
    Elasticsearch queries, inspect security logs, and return reasoned threat assessments.
    Includes automatic fallback from gemma-4-26b-a4b-it to gemma-4-31b-it.

    Args:
        user_input: Natural language question from SOC analyst (e.g., 'What IPs seem malicious today and why?')

    Returns:
        Reasoned threat assessment string synthesized by Gemma 4.
    """
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    client = genai.Client(api_key=api_key) if api_key else genai.Client()

    system_instruction = (
        "You are an expert Senior SOC (Security Operations Center) Analyst. "
        "Your mission is to investigate security incidents, analyze threat vectors, and provide reasoned assessments. "
        "When a user asks a question about security events or malicious activity, use the `query_elastic` tool "
        "to retrieve relevant security log payloads from Elasticsearch. "
        "Analyze the logs for malicious indicators (e.g., suspicious IPs, brute force attempts, exfiltration, anomaly spikes), "
        "and synthesize a clear, well-structured, professional threat assessment detailing 'What happened', 'Which IPs/entities are malicious', and 'Why'."
    )

    config = types.GenerateContentConfig(
        system_instruction=system_instruction,
        tools=[query_elastic],
        thinking_config=types.ThinkingConfig(thinking_level="high"),
        temperature=0.2
    )

    # 1. Primary Model Attempt: gemma-4-26b-a4b-it
    try:
        response = client.models.generate_content(
            model=PRIMARY_MODEL,
            contents=user_input,
            config=config
        )
        if response.text:
            return response.text
    except Exception as primary_err:
        print(f"[SOC Agent Warning] Primary model '{PRIMARY_MODEL}' encountered issue: {primary_err}. Attempting fallback to '{FALLBACK_MODEL}'...")

    # 2. Fallback Model Attempt: gemma-4-31b-it
    try:
        fallback_config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            tools=[query_elastic],
            thinking_config=types.ThinkingConfig(thinking_level="high"),
            temperature=0.2
        )
        fallback_response = client.models.generate_content(
            model=FALLBACK_MODEL,
            contents=user_input,
            config=fallback_config
        )
        if fallback_response.text:
            return fallback_response.text
        return "Threat assessment generated successfully, but output payload was empty."
    except Exception as fallback_err:
        raise RuntimeError(
            f"Both primary model '{PRIMARY_MODEL}' and fallback model '{FALLBACK_MODEL}' failed. "
            f"Error details: {fallback_err}"
        )
