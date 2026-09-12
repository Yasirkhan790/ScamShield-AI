from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class AgentState:
    """
    State container for the ScamShield AI agentic pipeline per PRD Section 17.
    """
    input_type: str  # "message" | "url" | "screenshot"
    raw_input: str  # Text message, URL string, or filename
    file_bytes: Optional[bytes] = None
    
    extracted_text: Optional[str] = None
    detected_urls: List[str] = field(default_factory=list)
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    analysis_results: Dict[str, Any] = field(default_factory=dict)
    
    risk_score: int = 0
    risk_level: str = "LOW"
    scam_category: str = "Uncategorized / No significant indicators"
    category_confidence: str = "low"
    
    explanation: str = ""
    recommendations: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    selected_tools: List[str] = field(default_factory=list)
