import httpx
from app.models.schemas import AnalysisRequest

# 애플리케이션 전체에서 재사용할 수 있도록 비동기 HTTP 클라이언트를 생성.
client = httpx.AsyncClient()

# 실제 LLM 분석 서비스의 주소 (실제 URL로 변경 예정)
LLM_ANALYZER_URL = "http://llm-analyzer:8000/v1/analyze"

async def hybrid_analysis(request: AnalysisRequest) -> dict:
    """
    세션 로그(transcript)와 메타데이터를 받아 규칙 기반 및 AI 분석을 수행하고 결과를 AnalysisResponse 형태의 딕셔너리로 반환.
    """
    transcript = request.transcript
    user = request.user
    server_id = request.server_id

    # 규칙/시퀀스 기반 분석 로직
    rule_based_findings = []

    # 규칙 리스트 (작성 예정)
    dangerous_commands = ["rm -rf /"]

    for commannd in dangerous_commands:
        if commannd in transcript:
            rule_based_findings.append({
                "finding": f"Critical command '{commannd}' detected",
                "type": "rule-based"
            })

    # 시퀀스 기반 로직 (작성 예정)
    # if "sudo" in transcript and "passwd" in transcript:
    #     rule_based_findings.append({
    #         "finding": "Potential privilege escalation attempt detected",
    #         "type": "rule-based"
    #     })

    # AI/LLM 분석 로직
    # 프롬프트 작성 예정
    llm_reasoning_text = "구현중.."
    try:
        # LLM 분석 서비스에 transcript를 보내 분석을 요청.
        response = await client.post(
            LLM_ANALYZER_URL,
            json={"transcript": transcript, "metadata": {"user": user, "server_id": server_id}},
            timeout=30.0
        )
        response.raise_for_status()  # 2xx 이외의 응답 코드는 예외를 발생시킴
        
        # 실제 응답에서 필요한 부분을 추출.
        llm_result = response.json()
        llm_reasoning_text = llm_result.get("reasoning", "No reasoning provided by LLM.")

    except httpx.RequestError as e:
        # 네트워크 오류
        llm_reasoning_text = f"네트워크 오류: {e}"
    except Exception as e:
        # 그 외 모든 예외 처리
        llm_reasoning_text = f"오류 발생: {e}"

    # 결과 종합
    # 규칙 및 시퀀스 로직 추가 예정
    is_anomaly_detected = len(rule_based_findings) > 0
    threat_score = 9.8 if is_anomaly_detected else 1.0
    threat_level = "Critical" if is_anomaly_detected else "Low"
    summary = "Critical threat detected based on command patterns." if is_anomaly_detected else "No immediate threats detected."

    final_result = {
        "is_anomaly": is_anomaly_detected,
        "threat_score": threat_score,
        "threat_level": threat_level,
        "summary": summary,
        "tags": ["rule-based-check"] if is_anomaly_detected else ["initial-pass"],
        "details": rule_based_findings,
        "llm_reasoning": llm_reasoning_text
    }

    return final_result