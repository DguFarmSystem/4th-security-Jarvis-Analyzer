from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.endpoints import analysis

# FastAPI 애플리케이션 인스턴스 생성
app = FastAPI(
    title="Jarvis Security Analyzer",
    description="A threat analysis tool for SSH session logs.",
    version="0.1.0",
)

# CORS 미들웨어 추가
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# /api/v1 접두사와 함께 analysis 라우터를 앱에 포함
app.include_router(analysis.router, prefix="/api/v1", tags=["Analysis"])


@app.get("/", tags=["Root"])
async def read_root():
    """
    서버가 정상적으로 실행 중인지 확인하는 기본 엔드포인트.
    """
    return {"message": "Jarvis Security Analyzer is running."}
