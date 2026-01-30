#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    IRON CITY AI CONSENSUS ENGINE™ v5.0                        ║
║                    15 Models | 9 Providers | Enterprise-Grade                 ║
║                    © Iron City IT Advisors                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

ENHANCEMENTS IN v5.0:
- Expanded output schema (exploitability, impact, false_positive_likelihood)
- Structured compliance output with control domains and audit risk
- Confidence calibration rules (1.0/0.8/0.5/0.3/0.1)
- Severity tie-breaker logic
- Breach notification risk flagging
- Verification steps for remediation
- Multi-framework compliance mapping

MODEL ROSTER (15 models):
    GROQ (Direct API - FREE):
        1. Llama 3.3 70B (weight 1.2)
        2. Llama 3.1 8B (weight 0.7)
    
    GOOGLE (Direct API - FREE tier):
        3. Gemini 2.0 Flash (weight 1.0)
    
    OPENROUTER (12 models):
        4. Claude 3 Haiku (weight 1.5) - TOP TIER
        5. GPT-4o-mini (weight 1.3) - TOP TIER
        6. Gemini 2 Flash (weight 1.3) - TOP TIER
        7. Grok 2 (weight 1.2) - TOP TIER
        8. Llama 3.1 70B (weight 1.2) - MID TIER
        9. Llama 3.3 70B OR (weight 1.1) - MID TIER
        10. Mistral Large (weight 1.1) - MID TIER
        11. Qwen 2.5 72B (weight 1.1) - MID TIER
        12. DeepSeek V3 (weight 1.0) - BUDGET TIER
        13. Gemma 2 27B (weight 0.9) - BUDGET TIER
        14. Phi-3 Medium (weight 0.9) - BUDGET TIER
        15. Command R (weight 0.9) - BUDGET TIER
"""

import os
import sys
import json
import argparse
import re
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
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

# Model weights for consensus voting (15 models)
MODEL_WEIGHTS = {
    # TOP TIER (1.3-1.5)
    "claude-3-haiku": 1.5,
    "gpt-4o-mini": 1.3,
    "gemini-2-flash": 1.3,
    "grok-2": 1.2,
    # MID TIER (1.1-1.2)
    "llama-3.3-70b": 1.2,
    "llama-3.1-70b": 1.2,
    "llama-3.3-70b-or": 1.1,
    "mistral-large": 1.1,
    "qwen-2.5-72b": 1.1,
    # BUDGET TIER (0.7-1.0)
    "deepseek-v3": 1.0,
    "gemini-flash": 1.0,
    "gemma-2-27b": 0.9,
    "phi-3-medium": 0.9,
    "command-r": 0.9,
    "llama-3.1-8b": 0.7,
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Control domain taxonomy for compliance mapping
CONTROL_DOMAINS = [
    "Access Control",
    "Identity and Authentication",
    "Vulnerability Management",
    "Configuration Management",
    "Logging and Monitoring",
    "Incident Response",
    "Data Protection",
    "Encryption and Key Management",
    "Network Security",
    "Change Management",
    "Vendor Risk",
    "Endpoint Security",
    "Secure SDLC"
]

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
    exploitability: str
    impact: str
    false_positive_likelihood: str
    internet_exposed: bool
    breach_notification_risk: bool
    remediation: List[str]
    verification_steps: List[str]
    compliance_frameworks: List[str]
    control_domains: List[str]
    reasoning: str
    weight: float
    success: bool = True
    error: Optional[str] = None


@dataclass
class ConsensusResult:
    """Final consensus result from all models."""
    # Core severity
    consensus_severity: str
    confidence_percent: float
    
    # Enhanced risk assessment
    exploitability: str
    impact: str
    false_positive_likelihood: str
    internet_exposed: bool
    
    # Structured compliance
    compliance_impact: Dict[str, Any]
    
    # Remediation
    aggregated_remediation: List[str]
    verification_steps: List[str]
    
    # Model statistics
    total_models: int
    successful_models: int
    failed_models: int
    severity_distribution: Dict[str, int]
    weighted_scores: Dict[str, float]
    
    # Raw model responses
    model_responses: List[Dict]
    
    # Metadata
    engine_version: str = "5.0"
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


# =============================================================================
# ENHANCED PROMPT TEMPLATE
# =============================================================================

ANALYSIS_PROMPT = """You are a senior cybersecurity analyst performing vulnerability triage for enterprise security operations.

Analyze the finding and produce a structured risk assessment.

FINDING:
{finding_json}

Respond in this EXACT JSON format only (no markdown, no extra text):

{{
    "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
    "confidence": 0.0-1.0,
    "exploitability": "HIGH|MEDIUM|LOW",
    "impact": "HIGH|MEDIUM|LOW",
    "false_positive_likelihood": "LOW|MEDIUM|HIGH",
    "internet_exposed": true|false,
    "breach_notification_risk": true|false,
    "compliance_frameworks": ["SOC2", "HIPAA", "PCI-DSS", "NIST"],
    "control_domains": ["Vulnerability Management", "Access Control"],
    "remediation": ["specific step 1", "specific step 2", "specific step 3"],
    "verification_steps": ["how to verify fix 1", "how to verify fix 2"],
    "reasoning": "Brief technical justification for severity rating"
}}

EVALUATION FACTORS:

1. Exploitability Assessment:
   - Required privileges (none/low/high)
   - User interaction required
   - Network access requirements
   - Public exploit availability
   - Known active exploitation

2. Impact Assessment:
   - Confidentiality impact
   - Integrity impact
   - Availability impact
   - Data exposure scope

3. Context Factors:
   - Internet vs internal exposure
   - Asset criticality
   - Data sensitivity (PHI, PCI, PII)
   - Compensating controls
   - Environment (prod/dev/staging)

4. Compliance Impact:
   - Frameworks: SOC2, HIPAA, PCI-DSS, NIST CSF, NIST 800-53, ISO 27001, HITRUST, CMMC, FTC Safeguards
   - Control domains: Access Control, Vulnerability Management, Configuration Management, Logging and Monitoring, Data Protection, Network Security, Encryption, Identity and Authentication
   - If exploitation could expose regulated data, set breach_notification_risk=true

CONFIDENCE SCORING:
- 1.0 = Confirmed evidence, verified exploit path
- 0.8 = Strong indicators, known attack pattern
- 0.5 = Partial evidence, theoretical risk
- 0.3 = Weak signal, missing context
- 0.1 = Likely false positive

SEVERITY TIE-BREAKER RULES:
- Exploitability HIGH + Impact HIGH → severity HIGH or CRITICAL
- Exploitability LOW + Impact LOW → severity LOW or INFO
- Internet exposed + data access → bump severity one level
- Compensating controls → may reduce severity one level
- Never rate CRITICAL without realistic compromise path

REMEDIATION REQUIREMENTS:
- Technically specific and actionable
- Ordered by priority
- No vague language like "improve security"

Respond with JSON only."""


# =============================================================================
# API QUERY FUNCTIONS
# =============================================================================

def _error_response(model_name: str, provider: str, error: str) -> ModelResponse:
    """Create an error response."""
    return ModelResponse(
        model_name=model_name,
        provider=provider,
        severity="",
        confidence=0,
        exploitability="",
        impact="",
        false_positive_likelihood="",
        internet_exposed=False,
        breach_notification_risk=False,
        remediation=[],
        verification_steps=[],
        compliance_frameworks=[],
        control_domains=[],
        reasoning="",
        weight=MODEL_WEIGHTS.get(model_name, 1.0),
        success=False,
        error=error
    )


def query_groq(model_id: str, model_name: str, prompt: str) -> ModelResponse:
    """Query Groq API."""
    if not GROQ_API_KEY:
        return _error_response(model_name, "Groq", "GROQ_API_KEY not set")
    
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
                "max_tokens": 1500
            },
            timeout=30
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        return parse_model_response(content, model_name, "Groq")
    except Exception as e:
        return _error_response(model_name, "Groq", str(e))


def query_openrouter(model_id: str, model_name: str, prompt: str) -> ModelResponse:
    """Query OpenRouter API."""
    if not OPENROUTER_API_KEY:
        return _error_response(model_name, "OpenRouter", "OPENROUTER_API_KEY not set")
    
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
                "max_tokens": 1500
            },
            timeout=60
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        return parse_model_response(content, model_name, "OpenRouter")
    except Exception as e:
        return _error_response(model_name, "OpenRouter", str(e))


def query_gemini(prompt: str) -> ModelResponse:
    """Query Google Gemini API."""
    model_name = "gemini-flash"
    if not GEMINI_API_KEY:
        return _error_response(model_name, "Google", "GEMINI_API_KEY not set")
    
    try:
        response = requests.post(
            f"{GEMINI_URL}?key={GEMINI_API_KEY}",
            headers={"Content-Type": "application/json"},
            json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.1,
                    "maxOutputTokens": 1500
                }
            },
            timeout=30
        )
        response.raise_for_status()
        content = response.json()["candidates"][0]["content"]["parts"][0]["text"]
        return parse_model_response(content, model_name, "Google")
    except Exception as e:
        return _error_response(model_name, "Google", str(e))


def parse_model_response(content: str, model_name: str, provider: str) -> ModelResponse:
    """Parse JSON response from model with enhanced fields."""
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
        
        # Parse severity with validation
        severity = data.get("severity", "MEDIUM").upper()
        if severity not in SEVERITY_ORDER:
            severity = "MEDIUM"
        
        # Parse exploitability
        exploitability = data.get("exploitability", "MEDIUM").upper()
        if exploitability not in ["HIGH", "MEDIUM", "LOW"]:
            exploitability = "MEDIUM"
        
        # Parse impact
        impact = data.get("impact", "MEDIUM").upper()
        if impact not in ["HIGH", "MEDIUM", "LOW"]:
            impact = "MEDIUM"
        
        # Parse false positive likelihood
        fp_likelihood = data.get("false_positive_likelihood", "LOW").upper()
        if fp_likelihood not in ["HIGH", "MEDIUM", "LOW"]:
            fp_likelihood = "LOW"
        
        return ModelResponse(
            model_name=model_name,
            provider=provider,
            severity=severity,
            confidence=float(data.get("confidence", 0.8)),
            exploitability=exploitability,
            impact=impact,
            false_positive_likelihood=fp_likelihood,
            internet_exposed=bool(data.get("internet_exposed", False)),
            breach_notification_risk=bool(data.get("breach_notification_risk", False)),
            remediation=data.get("remediation", []),
            verification_steps=data.get("verification_steps", []),
            compliance_frameworks=data.get("compliance_frameworks", []),
            control_domains=data.get("control_domains", []),
            reasoning=data.get("reasoning", ""),
            weight=weight,
            success=True
        )
    except Exception as e:
        return _error_response(model_name, provider, f"Parse error: {str(e)}")


# =============================================================================
# CONSENSUS CALCULATION
# =============================================================================

def calculate_consensus(responses: List[ModelResponse]) -> ConsensusResult:
    """Calculate weighted consensus from all model responses."""
    
    successful = [r for r in responses if r.success]
    failed = [r for r in responses if not r.success]
    
    if not successful:
        return ConsensusResult(
            consensus_severity="UNKNOWN",
            confidence_percent=0,
            exploitability="UNKNOWN",
            impact="UNKNOWN",
            false_positive_likelihood="UNKNOWN",
            internet_exposed=False,
            compliance_impact={},
            aggregated_remediation=[],
            verification_steps=[],
            total_models=len(responses),
            successful_models=0,
            failed_models=len(failed),
            severity_distribution={},
            weighted_scores={},
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
    
    # Find consensus severity
    consensus_severity = max(severity_weights, key=severity_weights.get)
    
    # Calculate confidence percentage
    agreement_count = sum(1 for r in successful if r.severity == consensus_severity)
    base_confidence = (agreement_count / len(successful)) * 100
    weighted_agreement = severity_weights[consensus_severity] * 100
    confidence_percent = round((base_confidence + weighted_agreement) / 2, 1)
    
    # Severity distribution
    severity_distribution = {}
    for r in successful:
        severity_distribution[r.severity] = severity_distribution.get(r.severity, 0) + 1
    
    # Consensus exploitability (majority vote)
    exploitability_votes = {}
    for r in successful:
        if r.exploitability:
            exploitability_votes[r.exploitability] = exploitability_votes.get(r.exploitability, 0) + r.weight
    consensus_exploitability = max(exploitability_votes, key=exploitability_votes.get) if exploitability_votes else "MEDIUM"
    
    # Consensus impact (majority vote)
    impact_votes = {}
    for r in successful:
        if r.impact:
            impact_votes[r.impact] = impact_votes.get(r.impact, 0) + r.weight
    consensus_impact = max(impact_votes, key=impact_votes.get) if impact_votes else "MEDIUM"
    
    # Consensus false positive likelihood (majority vote)
    fp_votes = {}
    for r in successful:
        if r.false_positive_likelihood:
            fp_votes[r.false_positive_likelihood] = fp_votes.get(r.false_positive_likelihood, 0) + r.weight
    consensus_fp = max(fp_votes, key=fp_votes.get) if fp_votes else "LOW"
    
    # Internet exposed (any model says yes = yes)
    internet_exposed = any(r.internet_exposed for r in successful)
    
    # Breach notification risk (majority weighted)
    breach_risk_weight = sum(r.weight for r in successful if r.breach_notification_risk)
    no_breach_weight = sum(r.weight for r in successful if not r.breach_notification_risk)
    breach_notification_risk = breach_risk_weight > no_breach_weight
    
    # Aggregate compliance frameworks
    framework_counts = {}
    for r in successful:
        for fw in r.compliance_frameworks:
            framework_counts[fw] = framework_counts.get(fw, 0) + 1
    # Keep frameworks mentioned by at least 30% of models
    threshold = len(successful) * 0.3
    consensus_frameworks = [fw for fw, count in framework_counts.items() if count >= threshold]
    
    # Aggregate control domains
    domain_counts = {}
    for r in successful:
        for domain in r.control_domains:
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
    consensus_domains = [d for d, count in domain_counts.items() if count >= threshold]
    
    # Determine audit risk based on severity and breach risk
    if consensus_severity in ["CRITICAL", "HIGH"] or breach_notification_risk:
        audit_risk = "HIGH"
    elif consensus_severity == "MEDIUM":
        audit_risk = "MEDIUM"
    else:
        audit_risk = "LOW"
    
    # Build structured compliance impact
    compliance_impact = {
        "frameworks": consensus_frameworks,
        "control_domains": consensus_domains,
        "control_mappings": get_compliance_mapping(consensus_severity),
        "audit_risk": audit_risk,
        "breach_notification_risk": breach_notification_risk
    }
    
    # Aggregate remediation steps (deduplicated)
    seen_remediation = set()
    aggregated_remediation = []
    for r in successful:
        for step in r.remediation:
            normalized = step.lower().strip()
            if normalized not in seen_remediation and len(step) > 10:
                seen_remediation.add(normalized)
                aggregated_remediation.append(step)
    
    # Aggregate verification steps
    seen_verification = set()
    verification_steps = []
    for r in successful:
        for step in r.verification_steps:
            normalized = step.lower().strip()
            if normalized not in seen_verification and len(step) > 10:
                seen_verification.add(normalized)
                verification_steps.append(step)
    
    return ConsensusResult(
        consensus_severity=consensus_severity,
        confidence_percent=confidence_percent,
        exploitability=consensus_exploitability,
        impact=consensus_impact,
        false_positive_likelihood=consensus_fp,
        internet_exposed=internet_exposed,
        compliance_impact=compliance_impact,
        aggregated_remediation=aggregated_remediation[:10],
        verification_steps=verification_steps[:5],
        total_models=len(responses),
        successful_models=len(successful),
        failed_models=len(failed),
        severity_distribution=severity_distribution,
        weighted_scores={k: round(v * 100, 1) for k, v in severity_weights.items()},
        model_responses=[asdict(r) for r in responses]
    )


def get_compliance_mapping(severity: str) -> Dict[str, List[str]]:
    """Map severity to compliance framework controls."""
    mappings = {
        "CRITICAL": {
            "NIST_CSF": ["ID.RA-1", "PR.IP-12", "DE.CM-8", "RS.MI-2"],
            "NIST_800-53": ["SI-2", "SI-3", "SC-7", "AC-6", "IR-4"],
            "SOC2": ["CC6.1", "CC7.1", "CC7.2", "CC7.3", "CC7.4"],
            "PCI-DSS": ["6.1", "6.2", "6.3", "11.2", "11.3"],
            "HIPAA": ["164.308(a)(1)", "164.312(a)(1)", "164.308(a)(6)"],
            "ISO27001": ["A.12.6.1", "A.14.2.2", "A.16.1.5"],
            "HITRUST": ["10.a", "10.m", "09.ab"],
            "CIS": ["4.1", "5.1", "9.4", "16.1", "17.1"],
            "CMMC": ["SI.2.216", "SI.2.217", "SC.3.177"],
            "FTC_Safeguards": ["314.4(b)(3)", "314.4(c)"]
        },
        "HIGH": {
            "NIST_CSF": ["ID.RA-1", "PR.IP-12", "DE.CM-8"],
            "NIST_800-53": ["SI-2", "CM-6", "AC-3", "AU-6"],
            "SOC2": ["CC6.1", "CC7.1", "CC7.2"],
            "PCI-DSS": ["6.1", "6.5", "11.2"],
            "HIPAA": ["164.308(a)(5)", "164.312(b)"],
            "ISO27001": ["A.12.6.1", "A.14.2.2"],
            "HITRUST": ["10.a", "10.m"],
            "CIS": ["4.1", "5.2", "9.1", "12.1"],
            "CMMC": ["SI.2.216", "SC.3.177"],
            "FTC_Safeguards": ["314.4(b)(3)"]
        },
        "MEDIUM": {
            "NIST_CSF": ["PR.IP-12", "DE.CM-8"],
            "NIST_800-53": ["CM-6", "AC-3", "AU-6"],
            "SOC2": ["CC6.1", "CC7.1"],
            "PCI-DSS": ["6.5", "10.6"],
            "HIPAA": ["164.312(b)"],
            "ISO27001": ["A.12.6.1"],
            "HITRUST": ["10.a"],
            "CIS": ["4.2", "5.3", "8.1"],
            "CMMC": ["SI.2.216"],
            "FTC_Safeguards": ["314.4(b)"]
        },
        "LOW": {
            "NIST_CSF": ["PR.IP-12"],
            "NIST_800-53": ["CM-6", "AU-6"],
            "SOC2": ["CC6.1"],
            "PCI-DSS": ["6.5"],
            "HIPAA": [],
            "ISO27001": [],
            "HITRUST": [],
            "CIS": ["4.3", "8.2"],
            "CMMC": [],
            "FTC_Safeguards": []
        },
        "INFO": {
            "NIST_CSF": [],
            "NIST_800-53": ["AU-6"],
            "SOC2": [],
            "PCI-DSS": [],
            "HIPAA": [],
            "ISO27001": [],
            "HITRUST": [],
            "CIS": ["8.3"],
            "CMMC": [],
            "FTC_Safeguards": []
        }
    }
    return mappings.get(severity, {})


# =============================================================================
# MAIN ENGINE
# =============================================================================

def analyze_finding(finding: dict, product: str = "generic", client_id: str = "default") -> ConsensusResult:
    """
    Main entry point: Analyze a security finding using 15 AI models.
    
    Args:
        finding: Security finding as dictionary
        product: Product name (attacksim-pro, threat-inspector, etc.)
        client_id: Client identifier for multi-tenant tracking
    
    Returns:
        ConsensusResult with consensus severity, confidence, and remediation
    """
    
    prompt = ANALYSIS_PROMPT.format(finding_json=json.dumps(finding, indent=2))
    
    # Define all 15 models to query
    models = [
        # ===========================================
        # GROQ (Direct API - FREE) - 2 models
        # ===========================================
        ("groq", "llama-3.3-70b-versatile", "llama-3.3-70b"),
        ("groq", "llama-3.1-8b-instant", "llama-3.1-8b"),
        
        # ===========================================
        # GOOGLE GEMINI (Direct API - FREE tier) - 1 model
        # ===========================================
        ("gemini", None, "gemini-flash"),
        
        # ===========================================
        # OPENROUTER - Top Tier (4 models)
        # ===========================================
        ("openrouter", "anthropic/claude-3-haiku", "claude-3-haiku"),
        ("openrouter", "openai/gpt-4o-mini", "gpt-4o-mini"),
        ("openrouter", "google/gemini-2.0-flash-exp:free", "gemini-2-flash"),
        ("openrouter", "x-ai/grok-2-1212", "grok-2"),
        
        # ===========================================
        # OPENROUTER - Mid Tier (4 models)
        # ===========================================
        ("openrouter", "meta-llama/llama-3.1-70b-instruct", "llama-3.1-70b"),
        ("openrouter", "meta-llama/llama-3.3-70b-instruct", "llama-3.3-70b-or"),
        ("openrouter", "mistralai/mistral-large", "mistral-large"),
        ("openrouter", "qwen/qwen-2.5-72b-instruct", "qwen-2.5-72b"),
        
        # ===========================================
        # OPENROUTER - Budget Tier (4 models)
        # ===========================================
        ("openrouter", "deepseek/deepseek-chat", "deepseek-v3"),
        ("openrouter", "google/gemma-2-27b-it", "gemma-2-27b"),
        ("openrouter", "microsoft/phi-3-medium-128k-instruct", "phi-3-medium"),
        ("openrouter", "cohere/command-r", "command-r"),
    ]
    
    responses = []
    
    # Query all models in parallel
    with ThreadPoolExecutor(max_workers=15) as executor:
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
                responses.append(_error_response(model_name, "unknown", str(e)))
    
    return calculate_consensus(responses)


def analyze_findings_batch(findings: List[dict], product: str = "generic", client_id: str = "default") -> List[ConsensusResult]:
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
        description="Iron City AI Consensus Engine v5.0 - Enterprise-grade security finding analysis with 15 AI models"
    )
    parser.add_argument(
        "findings_json",
        help="JSON file containing findings array OR single finding object (use '-' for stdin)"
    )
    parser.add_argument(
        "--product", "-p",
        default="generic",
        help="Product name (attacksim-pro, threat-inspector, dns-guard, shadowscan, ironsight)"
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
    
    print(f"\n{'='*70}", file=sys.stderr)
    print("  IRON CITY AI CONSENSUS ENGINE™ v5.0", file=sys.stderr)
    print("  15 Models | 9 Providers | Enterprise-Grade Analysis", file=sys.stderr)
    print(f"  Product: {args.product} | Client: {args.client}", file=sys.stderr)
    print(f"  Analyzing {len(findings)} finding(s)", file=sys.stderr)
    print(f"{'='*70}", file=sys.stderr)
    
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
            print(f"\n{'='*70}", file=sys.stderr)
            print(f"  CONSENSUS: {r.consensus_severity} ({r.confidence_percent}% confidence)", file=sys.stderr)
            print(f"  Exploitability: {r.exploitability} | Impact: {r.impact}", file=sys.stderr)
            print(f"  Audit Risk: {r.compliance_impact.get('audit_risk', 'N/A')}", file=sys.stderr)
            print(f"  Models: {r.successful_models}/{r.total_models} responded", file=sys.stderr)
            print(f"{'='*70}\n", file=sys.stderr)


if __name__ == "__main__":
    main()
