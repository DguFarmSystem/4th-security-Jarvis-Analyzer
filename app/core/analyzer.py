import httpx
from app.models.schemas import AnalysisRequest

client = httpx.AsyncClient()

# 컨테이너의 API 주소
LLM_ANALYZER_URL = "http://llm-analyzer:11434/v1/chat/completions"

async def hybrid_analysis(request: AnalysisRequest) -> dict:
    transcript = request.transcript
    user = request.user
    server_id = request.server_id

    # 규칙/시퀀스 기반 분석 로직 (여기에 규칙 추가)
    rule_based_findings = []
    dangerous_commands = ["rm -rf /"]
    for command in dangerous_commands:
        if command in transcript:
            rule_based_findings.append({
                "type": "dangerous_command",
                "command": command,
                "description": f"Dangerous command '{command}' found in session."
            })

    # 시퀀스 기반 로직 추가 예정

    # AI 분석 로직 (Ollama 연동)
    llm_reasoning_text = "AI 분석 로직 실행 전"
    try:
        # Phi-3-mini에 보낼 프롬프트
        prompt = f"""
                You are a security expert specializing in analyzing SSH session logs.
                Analyze the following SSH session transcript for user '{user}' on server '{server_id}'.
                Identify any suspicious or malicious activities.

                Based on your analysis, provide a brief, one-sentence summary of the threat level and your reasoning.

                Transcript:
                ---
                {transcript}
                ---
                """

        # Ollama  API 형식에 맞는 Payload
        payload = {
            "model": "phi3",
            "messages": [
                {"role": "system", "content": "You are a helpful security analysis assistant."},
                {"role": "user", "content": prompt}
            ],
            "stream": False
        }

        response = await client.post(LLM_ANALYZER_URL, json=payload, timeout=60.0)
        response.raise_for_status()
        
        llm_result = response.json()
        llm_reasoning_text = llm_result['choices'][0]['message']['content']

    except httpx.RequestError as e:
        # 네트워크 관련 에러
        llm_reasoning_text = f"네트워크 에러: {e}"
    except Exception as e:
        llm_reasoning_text = f"에러 발생: {e}"

    # 결과 종합
    # 분석 결과 종합 관련 설정 예정
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
