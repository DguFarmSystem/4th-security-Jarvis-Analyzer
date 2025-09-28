from pydantic import BaseModel, Field
from typing import List, Dict

# Go의 EnrichedLog 구조체에 해당하는 입력 모델
# FastAPI가 이 모델을 사용하여 들어오는 JSON을 자동으로 검증하고 파싱.
class AnalysisRequest(BaseModel):
    session_id: str = Field(..., alias="SessionID")
    user: str = Field(..., alias="User")
    server_id: str = Field(..., alias="ServerID")
    server_addr: str = Field(..., alias="ServerAddr")
    session_start: str = Field(..., alias="SessionStart")
    session_end: str = Field(..., alias="SessionEnd")
    transcript: str = Field(..., alias="Transcript")
    
    # Go에서 생성된 JSON 필드명(PascalCase)을 Python(snake_case)에 맞게 매핑.
    class Config:
        allow_population_by_field_name = True


# 분석 결과를 담을 응답 모델
class AnalysisResponse(BaseModel):
    is_anomaly: bool
    threat_score: float
    threat_level: str
    summary: str
    tags: List[str]
    details: List[Dict]
    llm_reasoning: str
