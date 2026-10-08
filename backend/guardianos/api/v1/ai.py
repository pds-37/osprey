"""Deterministic evidence summary API endpoints."""

from fastapi import Depends, Query, status
from pydantic import BaseModel, Field
from guardianos.api.security import SecuredAPIRouter
from guardianos.core.security import require_single_organization
from guardianos.ai.analyst import AIAnalysisReport, ai_analyst

router = SecuredAPIRouter(prefix="/ai", tags=["Evidence Summary"], dependencies=[Depends(require_single_organization)])


class AIQueryRequest(BaseModel):
    component_name: str = Field(..., description="Target component to investigate (e.g., libheif)")
    question: str = Field("Why is this vulnerability dangerous and how can it be reached?", description="Specific inquiry")


@router.post("/analyze", response_model=AIAnalysisReport, status_code=status.HTTP_200_OK)
async def query_ai_analyst(payload: AIQueryRequest):
    """Summarize existing component and advisory records deterministically."""
    report = ai_analyst.analyze_component(
        component_name=payload.component_name,
        user_question=payload.question
    )
    return report


@router.get("/explain/{component_name}", response_model=AIAnalysisReport)
async def explain_component_threat(component_name: str):
    """Get a deterministic summary of existing component and advisory records."""
    return ai_analyst.analyze_component(component_name=component_name)
