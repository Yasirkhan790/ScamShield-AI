import logging
from datetime import datetime, timezone
from typing import List, Dict, Any

from backend.agent.state import AgentState

try:
    from backend.tools.message_analyzer import analyze_message
    from backend.tools.url_analyzer import analyze_url
    from backend.tools.ocr_tool import extract_text_from_image
    from backend.tools.risk_engine import calculate_risk, classify_category
except ImportError:
    from backend.analyzers.message_analyzer import analyze_message
    from backend.analyzers.url_analyzer import analyze_url
    from backend.analyzers.ocr_tool import extract_text_from_image
    from backend.risk_engine import calculate_risk, classify_category

from backend.services.ai_service import AIService
from backend.schemas import AnalysisResultResponse, IndicatorModel
from backend.database.database import save_analysis

logger = logging.getLogger(__name__)

def observe_node(state: AgentState) -> AgentState:
    logger.info(f"Agent OBSERVE: input_type='{state.input_type}'")
    return state

def reason_node(state: AgentState) -> AgentState:
    valid_types = {"message", "url", "screenshot"}
    if state.input_type not in valid_types:
        state.errors.append(f"Invalid input_type '{state.input_type}'. Must be one of {valid_types}.")
        logger.error(f"Agent REASON error: {state.errors[-1]}")
    return state

def select_tool_node(state: AgentState) -> AgentState:
    if state.errors:
        return state

    if state.input_type == "screenshot":
        state.selected_tools = ["ocr_tool", "message_analyzer", "url_analyzer"]
    elif state.input_type == "message":
        state.selected_tools = ["message_analyzer", "url_analyzer"]
    elif state.input_type == "url":
        state.selected_tools = ["url_analyzer"]

    logger.info(f"Agent SELECT TOOL: selected={state.selected_tools}")
    return state

def analyze_node(state: AgentState) -> AgentState:
    if state.errors:
        return state

    collected_indicators = []
    collected_urls = []
    collected_notes = []

    if "ocr_tool" in state.selected_tools and state.file_bytes:
        extracted_text, success, note = extract_text_from_image(state.file_bytes)
        state.extracted_text = extracted_text
        if note:
            collected_notes.append(note)

        if not extracted_text:
            state.indicators = []
            state.detected_urls = []
            state.notes = collected_notes
            return state
        text_to_analyze = extracted_text
    else:
        text_to_analyze = state.raw_input

    if "message_analyzer" in state.selected_tools and text_to_analyze:
        msg_indicators, msg_urls, msg_notes = analyze_message(text_to_analyze)
        collected_indicators.extend(msg_indicators)
        collected_urls.extend(msg_urls)
        collected_notes.extend(msg_notes)

    if "url_analyzer" in state.selected_tools:
        urls_to_check = [state.raw_input] if state.input_type == "url" else collected_urls
        for target_url in set(urls_to_check):
            if target_url:
                url_indicators, url_findings = analyze_url(target_url)
                collected_indicators.extend(url_indicators)
                collected_notes.extend(url_findings)

    state.indicators = collected_indicators
    state.detected_urls = list(set(collected_urls))
    state.notes = collected_notes
    return state

def evaluate_node(state: AgentState) -> AgentState:
    if state.errors:
        return state

    score, level, final_indicators = calculate_risk(state.indicators)
    state.risk_score = score
    state.risk_level = level

    category, confidence = classify_category(final_indicators)
    state.scam_category = category
    state.category_confidence = confidence

    recommendations = AIService.generate_recommendations(final_indicators)
    state.recommendations = recommendations

    content_for_explanation = state.extracted_text or state.raw_input or ""
    explanation = AIService.generate_explanation(
        risk_score=score,
        risk_level=level,
        scam_category=category,
        indicators=final_indicators,
        notes=state.notes,
        content_excerpt=content_for_explanation
    )
    state.explanation = explanation

    return state

def respond_node(state: AgentState) -> AnalysisResultResponse:
    if state.errors:
        raise ValueError("; ".join(state.errors))

    score, level, final_indicators = calculate_risk(state.indicators)
    now_str = datetime.now(timezone.utc).isoformat()

    result = AnalysisResultResponse(
        input_type=state.input_type,
        risk_score=state.risk_score,
        risk_level=state.risk_level,
        scam_category=state.scam_category,
        category_confidence=state.category_confidence,
        indicators=final_indicators,
        detected_urls=state.detected_urls,
        extracted_text=state.extracted_text,
        explanation=state.explanation,
        recommendations=state.recommendations,
        created_at=now_str
    )

    raw_content = state.extracted_text or state.raw_input or ""
    saved_id = save_analysis(result, raw_content)
    result.id = saved_id

    return result
