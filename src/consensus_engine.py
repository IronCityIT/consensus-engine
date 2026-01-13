#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    IRON CITY AI CONSENSUS ENGINE™ v3.0                        ║
║                    10 Models | 7 Providers | Real Consensus                   ║
║                    © Iron City IT Advisors                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

This module queries 10 AI models across 7 providers to analyze security findings
and return consensus-based severity ratings, remediation steps, and confidence scores.

CONFIRMED WORKING (Jan 6, 2026):
    1. Llama 3.3 70B (Groq)
    2. Llama 3.1 8B (Groq)
    3. Gemini 2.5 Flash (Google)
    4. Claude 3 Haiku (OpenRouter)
    5. GPT-4o-mini (OpenRouter)
    6. Llama 3.1 70B (OpenRouter)
    7. Mistral Large (OpenRouter)
    8. Gemma 2 27B (OpenRouter)
    9. Qwen 2.5 72B (OpenRouter)
    10. DeepSeek V3 (OpenRouter)
"""

import os
import sys
import json
import argparse
import re
from dataclasses import dataclass, field, asdict
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import requests

# =============================================================================
# CONFIGURATION
# =============================================================================

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

# Model weights for consensus voting
# Higher weight = more influence on final decision
MODEL_WEIGHTS = {
    "claude-3-haiku": 1.5,      # Claude gets highest weight
    "gpt-4o-mini": 1.3,         # GPT gets second highest
    "llama-3.3-70b": 1.2,       # Large Llama
    "llama-3.1-70b": 1.2,       # Large Llama via OpenRouter
    "mistral-large": 1.1,       # Mistral Large
    "qwen-2.5-72b": 1.1,        # Qwen large
    "deepseek-v3": 1.0,         # DeepSeek
    "gemini-flash": 1.0,        # Gemini
    "gemma-2-27b": 0.9,         # Gemma medium
    "llama-3.1-8b": 0.7,        # Small model gets lower weight
}

# Severity order for comparison
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class ModelResponse:
    """Response from a single AI model."""
    model_name: str
    provider: str
    severity: str
    confidence: float
    remediation: list[str]
    reasoning: str
    weight: float
    success: bool = True
    error: Optional[str] = None


@dataclass
class ConsensusResult:
    """Final consensus result from all models."""
    consensus_severity: str
    confidence_percent: float
    total_models: int
    successful_models: int
    failed_models: int
    severity_distribution: dict
    weighted_scores: dict
    aggregated_remediation: list[str]
    compliance_mapping: dict
    model_responses: list[dict]
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


# =============================================================================
# PROMPT TEMPLATE
# =============================================================================

ANALYSIS_PROMPT = """You are a senior cybersecurity analyst. Analyze this security finding and provide your assessment.

FINDING:
{finding_json}

Respond in this EXACT JSON format only (no markdown, no explanation outside JSON):
{{
    "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
    "confidence": 0.0-1.0,
    "remediation": ["step 1", "step 2", "step 3"],
    "reasoning": "Brief explanation of your severity rating"
}}

Consider:
- Exploitability and attack complexity
- Potential business impact
- Data exposure risk
- Compliance implications
- Whether this is internet-facing or internal

Respond with JSON only."""


# =============================================================================
# API QUERY FUNCTIONS
# =============================================================================

def query_groq(model_id: str, model_name: str, prompt: str) -> ModelResponse:
    """Query Groq API."""
    if not GROQ_API_KEY:
        return ModelResponse(
            model_name=model_name, provider="Groq", severity="", confidence=0,
            remediation=[], reasoning="", weight=MODEL_WEIGHTS.get(model_name, 1.0),
            success=False, error="GROQ_API_KEY not set"
        )
    
    try:
        response = requests.post(
            GROQ_URL,
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": model_id,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 1000
            },
            timeout=30
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        return parse_model_response(content, model_name, "Groq")
    except Exception as e:
        return ModelResponse(
            model_name=model_name, provider="Groq", severity="", confidence=0,
            remediation=[], reasoning="", weight=MODEL_WEIGHTS.get(model_name, 1.0),
            success=False, error=str(e)
        )


def query_openrouter(model_id: str, model_name: str, prompt: str) -> ModelResponse:
    """Query OpenRouter API."""
    if not OPENROUTER_API_KEY:
        return ModelResponse(
            model_name=model_name, provider="OpenRouter", severity="", confidence=0,
            remediation=[], reasoning="", weight=MODEL_WEIGHTS.get(model_name, 1.0),
            success=False, error="OPENROUTER_API_KEY not set"
        )
    
    try:
        response = requests.post(
            OPENROUTER_URL,
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://ironcityit.com",
                "X-Title": "Iron City Consensus Engine"
            },
            json={
                "model": model_id,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 1000
            },
            timeout=60
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        return parse_model_response(content, model_name, "OpenRouter")
    except Exception as e:
        return ModelResponse(
            model_name=model_name, provider="OpenRouter", severity="", confidence=0,
            remediation=[], reasoning="", weight=MODEL_WEIGHTS.get(model_name, 1.0),
            success=False, error=str(e)
        )


def query_gemini(prompt: str) -> ModelResponse:
    """Query Google Gemini API."""
    model_name = "gemini-flash"
    if not GEMINI_API_KEY:
        return ModelResponse(
            model_name=model_name, provider="Google", severity="", confidence=0,
            remediation=[], reasoning="", weight=MODEL_WEIGHTS.get(model_name, 1.0),
            success=False, error="GEMINI_API_KEY not set"
        )
    
    try:
        response = requests.post(
            f"{GEMINI_URL}?key={GEMINI_API_KEY}",
            headers={"Content-Type": "application/json"},
            json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.1,
                    "maxOutputTokens": 1000
                }
            },
            timeout=30
        )
        response.raise_for_status()
        content = response.json()["candidates"][0]["content"]["parts"][0]["text"]
        return parse_model_response(content, model_name, "Google")
    except Exception as e:
        return ModelResponse(
            model_name=model_name, provider="Google", severity="", confidence=0,
            remediation=[], reasoning="", weight=MODEL_WEIGHTS.get(model_name, 1.0),
            success=False, error=str(e)
        )


def parse_model_response(content: str, model_name: str, provider: str) -> ModelResponse:
    """Parse JSON response from model."""
    weight = MODEL_WEIGHTS.get(model_name, 1.0)
    
    try:
        # Clean up response - extract JSON from markdown if needed
        content = content.strip()
        if content.startswith("```"):
            content = re.sub(r"```json?\s*", "", content)
            content = re.sub(r"```\s*$", "", content)
        
        # Find JSON object
        match = re.search(r'\{[\s\S]*\}', content)
        if not match:
            raise ValueError("No JSON object found in response")
        
        data = json.loads(match.group())
        
        severity = data.get("severity", "MEDIUM").upper()
        if severity not in SEVERITY_ORDER:
            severity = "MEDIUM"
        
        return ModelResponse(
            model_name=model_name,
            provider=provider,
            severity=severity,
            confidence=float(data.get("confidence", 0.8)),
            remediation=data.get("remediation", []),
            reasoning=data.get("reasoning", ""),
            weight=weight,
            success=True
        )
    except Exception as e:
        return ModelResponse(
            model_name=model_name, provider=provider, severity="", confidence=0,
            remediation=[], reasoning="", weight=weight,
            success=False, error=f"Parse error: {str(e)}"
        )


# =============================================================================
# CONSENSUS CALCULATION
# =============================================================================

def calculate_consensus(responses: list[ModelResponse]) -> ConsensusResult:
    """Calculate weighted consensus from all model responses."""
    
    successful = [r for r in responses if r.success]
    failed = [r for r in responses if not r.success]
    
    if not successful:
        return ConsensusResult(
            consensus_severity="UNKNOWN",
            confidence_percent=0,
            total_models=len(responses),
            successful_models=0,
            failed_models=len(failed),
            severity_distribution={},
            weighted_scores={},
            aggregated_remediation=[],
            compliance_mapping={},
            model_responses=[asdict(r) for r in responses]
        )
    
    # Calculate weighted severity scores
    severity_weights = {s: 0.0 for s in SEVERITY_ORDER}
    total_weight = 0.0
    
    for r in successful:
        if r.severity in severity_weights:
            severity_weights[r.severity] += r.weight * r.confidence
            total_weight += r.weight
    
    # Normalize weights
    if total_weight > 0:
        for s in severity_weights:
            severity_weights[s] /= total_weight
    
    # Find consensus severity (highest weighted)
    consensus_severity = max(severity_weights, key=severity_weights.get)
    
    # Calculate confidence as percentage of agreement
    agreement_count = sum(1 for r in successful if r.severity == consensus_severity)
    base_confidence = (agreement_count / len(successful)) * 100
    
    # Boost confidence based on weighted agreement
    weighted_agreement = severity_weights[consensus_severity] * 100
    confidence_percent = round((base_confidence + weighted_agreement) / 2, 1)
    
    # Severity distribution
    severity_distribution = {}
    for r in successful:
        severity_distribution[r.severity] = severity_distribution.get(r.severity, 0) + 1
    
    # Aggregate remediation steps (deduplicated)
    seen_remediation = set()
    aggregated_remediation = []
    for r in successful:
        for step in r.remediation:
            normalized = step.lower().strip()
            if normalized not in seen_remediation and len(step) > 10:
                seen_remediation.add(normalized)
                aggregated_remediation.append(step)
    
    # Compliance mapping based on severity
    compliance_mapping = get_compliance_mapping(consensus_severity)
    
    return ConsensusResult(
        consensus_severity=consensus_severity,
        confidence_percent=confidence_percent,
        total_models=len(responses),
        successful_models=len(successful),
        failed_models=len(failed),
        severity_distribution=severity_distribution,
        weighted_scores={k: round(v * 100, 1) for k, v in severity_weights.items()},
        aggregated_remediation=aggregated_remediation[:10],  # Top 10
        compliance_mapping=compliance_mapping,
        model_responses=[asdict(r) for r in responses]
    )


def get_compliance_mapping(severity: str) -> dict:
    """Map severity to compliance framework controls."""
    mappings = {
        "CRITICAL": {
            "NIST": ["SI-2", "SI-3", "SC-7", "AC-6"],
            "CIS": ["4.1", "5.1", "9.4", "16.1"],
            "PCI-DSS": ["6.1", "6.2", "11.2"],
            "HIPAA": ["164.308(a)(1)", "164.312(a)(1)"],
            "SOC2": ["CC6.1", "CC7.1", "CC7.2"]
        },
        "HIGH": {
            "NIST": ["SI-2", "CM-6", "AC-3"],
            "CIS": ["4.1", "5.2", "9.1"],
            "PCI-DSS": ["6.1", "6.5", "11.2"],
            "HIPAA": ["164.308(a)(5)"],
            "SOC2": ["CC6.1", "CC7.1"]
        },
        "MEDIUM": {
            "NIST": ["CM-6", "AC-3", "AU-6"],
            "CIS": ["4.2", "5.3", "8.1"],
            "PCI-DSS": ["6.5", "10.6"],
            "HIPAA": ["164.312(b)"],
            "SOC2": ["CC6.1"]
        },
        "LOW": {
            "NIST": ["CM-6", "AU-6"],
            "CIS": ["4.3", "8.2"],
            "PCI-DSS": ["6.5"],
            "HIPAA": [],
            "SOC2": []
        },
        "INFO": {
            "NIST": ["AU-6"],
            "CIS": ["8.3"],
            "PCI-DSS": [],
            "HIPAA": [],
            "SOC2": []
        }
    }
    return mappings.get(severity, {})


# =============================================================================
# MAIN ENGINE
# =============================================================================

def analyze_finding(finding: dict, product: str = "generic", client_id: str = "default") -> ConsensusResult:
    """
    Main entry point: Analyze a security finding using 10 AI models.
    
    Args:
        finding: Security finding as dictionary
        product: Product name (attacksim-pro, threat-inspector, etc.)
        client_id: Client identifier for multi-tenant tracking
    
    Returns:
        ConsensusResult with consensus severity, confidence, and remediation
    """
    
    prompt = ANALYSIS_PROMPT.format(finding_json=json.dumps(finding, indent=2))
    
    # Define all models to query
    models = [
        # Groq models
        ("groq", "llama-3.3-70b-versatile", "llama-3.3-70b"),
        ("groq", "llama-3.1-8b-instant", "llama-3.1-8b"),
        # Gemini
        ("gemini", None, "gemini-flash"),
        # OpenRouter models
        ("openrouter", "anthropic/claude-3-haiku", "claude-3-haiku"),
        ("openrouter", "openai/gpt-4o-mini", "gpt-4o-mini"),
        ("openrouter", "meta-llama/llama-3.1-70b-instruct", "llama-3.1-70b"),
        ("openrouter", "mistralai/mistral-large", "mistral-large"),
        ("openrouter", "google/gemma-2-27b-it", "gemma-2-27b"),
        ("openrouter", "qwen/qwen-2.5-72b-instruct", "qwen-2.5-72b"),
        ("openrouter", "deepseek/deepseek-chat", "deepseek-v3"),
    ]
    
    responses = []
    
    # Query all models in parallel
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {}
        
        for provider, model_id, model_name in models:
            if provider == "groq":
                futures[executor.submit(query_groq, model_id, model_name, prompt)] = model_name
            elif provider == "gemini":
                futures[executor.submit(query_gemini, prompt)] = model_name
            elif provider == "openrouter":
                futures[executor.submit(query_openrouter, model_id, model_name, prompt)] = model_name
        
        for future in as_completed(futures):
            model_name = futures[future]
            try:
                response = future.result()
                responses.append(response)
                status = "✓" if response.success else f"✗ {response.error}"
                print(f"  [{model_name}] {status}", file=sys.stderr)
            except Exception as e:
                print(f"  [{model_name}] ✗ Exception: {e}", file=sys.stderr)
                responses.append(ModelResponse(
                    model_name=model_name, provider="unknown", severity="", confidence=0,
                    remediation=[], reasoning="", weight=1.0, success=False, error=str(e)
                ))
    
    return calculate_consensus(responses)


def analyze_findings_batch(findings: list[dict], product: str = "generic", client_id: str = "default") -> list[ConsensusResult]:
    """Analyze multiple findings."""
    results = []
    for i, finding in enumerate(findings):
        print(f"\n[Finding {i+1}/{len(findings)}]", file=sys.stderr)
        results.append(analyze_finding(finding, product, client_id))
    return results


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Iron City AI Consensus Engine - Analyze security findings with 10 AI models"
    )
    parser.add_argument(
        "findings_json",
        help="JSON file containing findings array OR single finding object"
    )
    parser.add_argument(
        "--product", "-p",
        default="generic",
        help="Product name (attacksim-pro, threat-inspector, dns-guard, etc.)"
    )
    parser.add_argument(
        "--client", "-c",
        default="default",
        help="Client ID for multi-tenant tracking"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file for results JSON (default: stdout)"
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty print JSON output"
    )
    
    args = parser.parse_args()
    
    # Load findings
    if args.findings_json == "-":
        findings_data = json.load(sys.stdin)
    else:
        with open(args.findings_json, "r") as f:
            findings_data = json.load(f)
    
    # Normalize to list
    if isinstance(findings_data, dict):
        findings = [findings_data]
    else:
        findings = findings_data
    
    print(f"\n{'='*60}", file=sys.stderr)
    print("  IRON CITY AI CONSENSUS ENGINE™ v3.0", file=sys.stderr)
    print(f"  Product: {args.product} | Client: {args.client}", file=sys.stderr)
    print(f"  Analyzing {len(findings)} finding(s) with 10 AI models", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)
    
    # Analyze
    results = analyze_findings_batch(findings, args.product, args.client)
    
    # Output
    output_data = [asdict(r) for r in results]
    if len(output_data) == 1:
        output_data = output_data[0]
    
    indent = 2 if args.pretty else None
    json_output = json.dumps(output_data, indent=indent)
    
    if args.output:
        with open(args.output, "w") as f:
            f.write(json_output)
        print(f"\nResults written to: {args.output}", file=sys.stderr)
    else:
        print(json_output)
    
    # Summary
    if results:
        r = results[0] if len(results) == 1 else results
        if isinstance(r, ConsensusResult):
            print(f"\n{'='*60}", file=sys.stderr)
            print(f"  CONSENSUS: {r.consensus_severity} ({r.confidence_percent}% confidence)", file=sys.stderr)
            print(f"  Models: {r.successful_models}/{r.total_models} responded", file=sys.stderr)
            print(f"{'='*60}\n", file=sys.stderr)


if __name__ == "__main__":
    main()
