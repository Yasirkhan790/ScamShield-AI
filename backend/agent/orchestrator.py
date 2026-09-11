import logging
from typing import Optional
from backend.agent.state import AgentState
from backend.agent.nodes import (
    observe_node,
    reason_node,
    select_tool_node,
    analyze_node,
    evaluate_node,
    respond_node
)
from backend.schemas import AnalysisResultResponse

logger = logging.getLogger(__name__)

def run_agent_workflow(
    input_type: str,
    raw_input: str,
    file_bytes: Optional[bytes] = None
) -> AnalysisResultResponse:
    """
    Executes the 6-step Agentic AI workflow:
    OBSERVE -> REASON -> SELECT TOOL -> ANALYZE -> EVALUATE -> RESPOND
    
    Structure is 1:1 compatible with LangGraph (langgraph.graph.StateGraph).
    """
    state = AgentState(
        input_type=input_type,
        raw_input=raw_input,
        file_bytes=file_bytes
    )

    state = observe_node(state)
    state = reason_node(state)
    state = select_tool_node(state)
    state = analyze_node(state)
    state = evaluate_node(state)
    result = respond_node(state)

    logger.info(f"Agent Workflow Complete: type='{input_type}', score={result.risk_score}, level='{result.risk_level}'")
    return result
