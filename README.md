# 🛡️ Iron City AI Consensus Engine™

**Multi-model AI analysis for security findings with weighted consensus voting.**

[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![Models](https://img.shields.io/badge/AI%20Models-10-green.svg)](#models)

---

## Overview

The AI Consensus Engine queries **10 AI models** across **7 providers** to analyze security findings and return:
- **Weighted consensus severity** (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- **Confidence percentage** based on model agreement
- **Aggregated remediation steps** (deduplicated across all models)
- **Compliance mapping** (NIST, CIS, PCI-DSS, HIPAA, SOC2)

This is a **reusable GitHub Actions workflow** - not a hosted service. Other Iron City products call this workflow to get AI-powered analysis.

---

## 🤖 Models

| # | Model | Provider | Weight | Status |
|---|-------|----------|--------|--------|
| 1 | Llama 3.3 70B | Groq | 1.2x | ✅ |
| 2 | Llama 3.1 8B | Groq | 0.7x | ✅ |
| 3 | Gemini 2.5 Flash | Google | 1.0x | ✅ |
| 4 | Claude 3 Haiku | OpenRouter | **1.5x** | ✅ |
| 5 | GPT-4o-mini | OpenRouter | **1.3x** | ✅ |
| 6 | Llama 3.1 70B | OpenRouter | 1.2x | ✅ |
| 7 | Mistral Large | OpenRouter | 1.1x | ✅ |
| 8 | Gemma 2 27B | OpenRouter | 0.9x | ✅ |
| 9 | Qwen 2.5 72B | OpenRouter | 1.1x | ✅ |
| 10 | DeepSeek V3 | OpenRouter | 1.0x | ✅ |

**Weighted voting** means Claude and GPT have more influence on the final consensus than smaller models.

---

## 🚀 Quick Start

### As a Reusable Workflow (Recommended)

Add this to your product's GitHub workflow:

```yaml
jobs:
  scan:
    # ... your scanning job that outputs findings_json ...
    
  consensus:
    needs: scan
    uses: IronCityIT/ICIT-ConsensusEngine/.github/workflows/analyze.yml@main
    with:
      findings_json: ${{ needs.scan.outputs.findings_json }}
      product: 'your-product-name'
      client_id: ${{ inputs.client_id }}
    secrets:
      GROQ_API_KEY: ${{ secrets.GROQ_API_KEY }}
      OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
      GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}

  report:
    needs: consensus
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "Severity: ${{ needs.consensus.outputs.consensus_severity }}"
          echo "Confidence: ${{ needs.consensus.outputs.confidence_percent }}%"
```

### Outputs Available

| Output | Description | Example |
|--------|-------------|---------|
| `consensus_severity` | Overall severity | `CRITICAL` |
| `confidence_percent` | Confidence level | `85.5` |
| `consensus_json` | Full results JSON | `{...}` |

---

## 🔧 Local Usage

### CLI

```bash
# Set API keys
export GROQ_API_KEY="gsk_..."
export OPENROUTER_API_KEY="sk-or-v1-..."
export GEMINI_API_KEY="AIza..."

# Analyze findings
python src/consensus_engine.py findings.json --product attacksim-pro --client acme-corp --pretty

# Read from stdin
cat findings.json | python src/consensus_engine.py - --output results.json
```

### As a Module

```python
from src.consensus_engine import analyze_finding, analyze_findings_batch

finding = {
    "title": "SQL Injection",
    "severity": "HIGH",
    "description": "SQL injection in login form",
    "url": "https://example.com/login"
}

result = analyze_finding(finding, product="attacksim-pro", client_id="acme-corp")

print(f"Consensus: {result.consensus_severity}")
print(f"Confidence: {result.confidence_percent}%")
print(f"Remediation: {result.aggregated_remediation}")
```

---

## 📊 Output Format

```json
{
  "consensus_severity": "HIGH",
  "confidence_percent": 85.0,
  "total_models": 10,
  "successful_models": 9,
  "failed_models": 1,
  "severity_distribution": {
    "HIGH": 5,
    "CRITICAL": 3,
    "MEDIUM": 1
  },
  "weighted_scores": {
    "CRITICAL": 35.2,
    "HIGH": 48.5,
    "MEDIUM": 12.1,
    "LOW": 3.2,
    "INFO": 1.0
  },
  "aggregated_remediation": [
    "Implement parameterized queries to prevent SQL injection",
    "Use an ORM framework with built-in escaping",
    "Apply input validation and sanitization",
    "Enable WAF rules for SQL injection protection"
  ],
  "compliance_mapping": {
    "NIST": ["SI-2", "CM-6", "AC-3"],
    "CIS": ["4.1", "5.2", "9.1"],
    "PCI-DSS": ["6.1", "6.5", "11.2"],
    "HIPAA": ["164.308(a)(5)"],
    "SOC2": ["CC6.1", "CC7.1"]
  },
  "model_responses": [
    {
      "model_name": "claude-3-haiku",
      "provider": "OpenRouter",
      "severity": "HIGH",
      "confidence": 0.9,
      "weight": 1.5,
      "success": true
    }
    // ... more models
  ],
  "timestamp": "2026-01-13T12:00:00Z"
}
```

---

## 🔑 API Keys Setup

### GitHub Organization Secrets (Recommended)

Add these as **organization-level secrets** so all repos can use them:

1. Go to `github.com/IronCityIT` → Settings → Secrets → Actions
2. Add organization secrets:
   - `GROQ_API_KEY`
   - `OPENROUTER_API_KEY`
   - `GEMINI_API_KEY`

### Getting API Keys

| Provider | URL | Free Tier |
|----------|-----|-----------|
| Groq | https://console.groq.com | ✅ Yes |
| OpenRouter | https://openrouter.ai | $5 credit |
| Google Gemini | https://aistudio.google.com | ✅ Yes |

---

## 📁 Repository Structure

```
ICIT-ConsensusEngine/
├── src/
│   ├── __init__.py
│   └── consensus_engine.py     # Main engine - 10 models, weighted voting
├── .github/workflows/
│   └── analyze.yml             # Reusable workflow other repos call
├── examples/
│   ├── attacksim-example.yml   # How AttackSim Pro calls the engine
│   └── threat-inspector-example.yml
├── tests/
│   └── sample_findings.json    # Test data
├── README.md
└── requirements.txt
```

---

## 🛠️ Products Using This Engine

| Product | Repo | Finding Types |
|---------|------|---------------|
| AttackSim Pro | `ICIT-AttackSimPro` | ZAP/Nuclei web vulnerabilities |
| Threat Inspector | `threat-inspector` | Nmap/SSL network findings |
| DNS Guard | `ICIT-DNSGuard` | DNS security anomalies |
| ShadowScan | TBD | Dark web breach exposures |
| IronSight Forensics | TBD | Memory/disk forensic findings |

---

## 💰 Cost

| Provider | Cost per Query | Est. per Scan (10 findings) |
|----------|---------------|----------------------------|
| Groq | FREE | $0.00 |
| Gemini | FREE tier | $0.00 |
| OpenRouter | ~$0.001/finding | ~$0.01 |

**Total estimated cost: ~$0.01 per scan**

---

## 📜 License

Proprietary - Iron City IT Advisors © 2026

---

## 🔗 Links

- [Iron City IT Advisors](https://ironcityit.com)
- [AttackSim Pro](https://asp.ironcityit.com)
- [ICIT Sentinel SIEM](https://sentinel.ironcityit.com)
- [Command Center Portal](https://portal.ironcityit.com)
