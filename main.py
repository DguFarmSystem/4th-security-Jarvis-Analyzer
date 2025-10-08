from fastapi import FastAPI
from app.api.endpoints import analysis

# FastAPI 애플리케이션 인스턴스 생성
app = FastAPI(
    title="Jarvis Security Analyzer",
    description="A threat analysis tool for SSH session logs.",
    version="0.1.0",
)

# /api/v1 접두사와 함께 analysis 라우터를 앱에 포함
app.include_router(analysis.router, prefix="/api/v1", tags=["Analysis"])


@app.get("/", tags=["Root"])
async def read_root():
    """
    서버가 정상적으로 실행 중인지 확인하는 기본 엔드포인트.
    """
    return {"message": "Jarvis Security Analyzer is running."}
