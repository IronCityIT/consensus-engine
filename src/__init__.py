"""Iron City AI Consensus Engine - Multi-model security analysis."""

from .consensus_engine import (
    analyze_finding,
    analyze_findings_batch,
    ConsensusResult,
    ModelResponse,
    MODEL_WEIGHTS,
    SEVERITY_ORDER,
)

__version__ = "3.0.0"
__all__ = [
    "analyze_finding",
    "analyze_findings_batch", 
    "ConsensusResult",
    "ModelResponse",
    "MODEL_WEIGHTS",
    "SEVERITY_ORDER",
]
