from fastapi import APIRouter, HTTPException
from app.models.schemas import AnalysisRequest, AnalysisResponse
from app.core.analyzer import hybrid_analysis
import logging

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# APIRouter 인스턴스 생성
router = APIRouter()


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_session(request: AnalysisRequest):
    """
    백엔드로부터 세션 정보를 받아 분석을 수행하고 결과를 반환하는 API 엔드포인트.
    """

    # 데이터 수신 확인
    logger.info(f"Received analysis request for session_id: {request.session_id}")

    # 핵심 분석 로직 호출
    # core/analyzer.py의 hybrid_analysis 함수에 전체 요청 객체를 전달.
    analysis_result = await hybrid_analysis(request)

    # 분석 결과를 API 응답 모델에 맞춰 반환
    # 딕셔너리를 AnalysisResponse 모델의 키워드 인자로 자동 매핑.
    return AnalysisResponse(**analysis_result)
