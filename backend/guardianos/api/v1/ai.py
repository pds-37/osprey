"""AI Security Analyst API endpoints."""

from fastapi import APIRouter, Query, status
from pydantic import BaseModel, Field
from guardianos.ai.analyst import AIAnalysisReport, ai_analyst

router = APIRouter(prefix="/ai", tags=["AI Security Analyst"])


class AIQueryRequest(BaseModel):
    component_name: str = Field(..., description="Target component to investigate (e.g., libheif)")
    question: str = Field("Why is this vulnerability dangerous and how can it be reached?", description="Specific inquiry")


@router.post("/analyze", response_model=AIAnalysisReport, status_code=status.HTTP_200_OK)
async def query_ai_analyst(payload: AIQueryRequest):
    """Query the AI Security Analyst for evidence-grounded threat synthesis."""
    report = ai_analyst.analyze_component(
        component_name=payload.component_name,
        user_question=payload.question
    )
    return report


@router.get("/explain/{component_name}", response_model=AIAnalysisReport)
async def explain_component_threat(component_name: str):
    """Get instant 'Why Am I Affected?' narrative report citing graph evidence."""
    return ai_analyst.analyze_component(component_name=component_name)
