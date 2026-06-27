"""
Shared state object that flows through the LangGraph.

LangGraph nodes read from and write to this TypedDict. Making the state
explicit and strongly typed is what makes the system testable and
reproducible. Nothing is passed implicitly between agents.
"""
from __future__ import annotations

from typing import TypedDict

from codesentinel.graph.schemas import (
    EvaluatorVerdict,
    QualityFinding,
    SecurityFinding,
)


class RetrievedPassage(TypedDict):
    """One passage returned from the RAG retriever."""
    doc: str
    passage_id: str
    text: str
    score: float


class CodeSentinelState(TypedDict, total=False):
    # --- Inputs ---
    input_code: str
    language: str  # "python" | "javascript" | "java" | "unknown"

    # --- RAG ---
    retrieved_passages: list[RetrievedPassage]

    # --- Findings ---
    security_findings: list[SecurityFinding]
    quality_findings: list[QualityFinding]

    # --- Evaluation ---
    evaluator_verdict: EvaluatorVerdict | None
    retry_count: dict[str, int]  # agent_name -> retry count
    evaluator_feedback: str | None  # feedback routed back to upstream

    # --- Output ---
    final_report: str | None
    run_id: str

    # --- Diagnostics ---
    trace: list[str]  # one entry per graph transition
    error: str | None
