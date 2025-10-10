import os
import httpx
import glob
import json
from sigma.rule import SigmaRule
from sigma.exceptions import SigmaError

from app.models.schemas import AnalysisRequest

class RuleBasedAnalyzer:
    def __init__(self, rules_path: str):
        self.rules = self._load_rules(rules_path)
        print(f"Loaded {len(self.rules)} Sigma rules successfully.")

    def _load_rules(self, path: str) -> list[SigmaRule]:
        rule_files = glob.glob(os.path.join(path, '**', '*.yml'), recursive=True)

        loaded_rules = []
        for file_path in rule_files:
            with open(file_path, 'r', encoding='utf-8') as f:
                try:
                    # 각 YAML 파일을 SigmaRule 객체로 직접 파싱.
                    rule = SigmaRule.from_yaml(f.read())
                    loaded_rules.append(rule)
                except SigmaError as e:
                    print(f"Warning: Could not load rule {os.path.basename(file_path)}. Reason: {e}")
                except Exception as e:
                    print(f"Error processing rule file {file_path}: {e}")
        return loaded_rules

    def analyze(self, transcript: str) -> list[dict]:
        findings = []

        # transcript를 줄 단위로 나누어 각 줄을 별도의 이벤트로 처리
        lines = transcript.strip().split('\n')

        for line in lines:
            if not line.strip():  # 빈 줄은 건너뛰기
                continue

            # 각 명령어 라인을 더 구조화된 이벤트로 구성.
            command_parts = line.strip().split()
            image = command_parts[0]

            event = {
                'CommandLine': line.strip(), # 전체 명령어 라인
                'Image': image               # 명령어 실행 파일
            }

            for rule in self.rules:
                try:
                    # rule.match()는 이벤트의 리스트를 받으므로 [event]로 전달
                    if any(rule.check([event])):
                        # 중복 탐지를 방지하기 위해 이미 추가된 규칙인지 확인
                        if not any(f['rule_id'] == str(rule.id) for f in findings):
                            findings.append({
                                "type": "sigma_rule",
                                "rule_id": str(rule.id),
                                "name": rule.title,
                                "description": rule.description,
                                "threat_level": rule.level.name.upper(),
                                "tags": [str(tag) for tag in rule.tags]
                            })
                except Exception as e:
                    print(f"Error matching rule '{rule.title}': {e}")
        return findings


# Sigma 규칙이 있는 디렉토리 경로를 지정.
RULES_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'sigma_rules')

# RuleBasedAnalyzer 인스턴스 생성
rule_analyzer = RuleBasedAnalyzer(RULES_PATH)

client = httpx.AsyncClient()
LLM_ANALYZER_URL = "http://llm-analyzer:11434/v1/chat/completions"

async def hybrid_analysis(request: AnalysisRequest) -> dict:
    transcript = request.transcript
    user = getattr(request, 'user', 'unknown')
    server_id = getattr(request, 'server_id', 'unknown')

    # 규칙 기반 분석 실행
    rule_based_findings = rule_analyzer.analyze(transcript)

    llm_reasoning_text = "N/A"
    is_anomaly_detected = len(rule_based_findings) > 0

    # 규칙 기반 탐지가 없을 경우에만 LLM 호출
    if not is_anomaly_detected:
        try:
            # [수정] 새로운 프롬프트 적용
            prompt = f'''
                    You are a security expert. Analyze the following SSH session transcript.
                    The transcript did not match any known high-risk rules.
                    Your task is to find any other subtle, suspicious, or anomalous behavior.

                    Respond ONLY in JSON format with the following structure:
                    {{
                      "is_threat": boolean,
                      "threat_command": "the single most threatening command line found",
                      "reason": "a single, concise sentence explaining the threat in Korean"
                    }}

                    If no threat is found, set "is_threat" to false and provide a benign reason.

                    Transcript:
                    ---
                    {transcript}
                    ---
                    '''
            payload = { "model": "phi3", "messages": [{"role": "user", "content": prompt}], "stream": False }

            response = await client.post(LLM_ANALYZER_URL, json=payload, timeout=60.0)
            response.raise_for_status()

            llm_raw_response = response.json()['choices'][0]['message']['content']

            # LLM의 응답을 JSON으로 파싱
            llm_analysis = json.loads(llm_raw_response)
            llm_reasoning_text = llm_analysis.get("reason", "No reason provided.")

            # LLM의 판단을 최종 결과에 반영
            if llm_analysis.get("is_threat") == True:
                is_anomaly_detected = True # is_anomaly 상태를 True로 변경
                # LLM이 탐지한 위협을 'details'에 추가
                rule_based_findings.append({
                    "type": "llm_analysis",
                    "rule_id": "LLM-S01",
                    "name": "Suspicious Activity Detected by AI",
                    "description": f"AI detected a potential threat: {llm_analysis.get('threat_command', 'N/A')}",
                    "threat_level": "MEDIUM",
                    "tags": ["ai-detection"]
                })

        except (httpx.RequestError, json.JSONDecodeError, KeyError, IndexError) as e:
            llm_reasoning_text = f"LLM analysis failed or returned invalid format: {e}"
        except Exception as e:
            llm_reasoning_text = f"An unexpected error occurred during LLM analysis: {e}"
    else:
        llm_reasoning_text = "명확한 규칙 기반 위협이 탐지되어 LLM 분석을 건너뛰었습니다."

    # 최종 결과 종합
    highest_level = "LOW"
    summary = "No immediate threats detected based on Sigma rules."

    if is_anomaly_detected:
        levels = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}
        highest_rule = max(rule_based_findings, key=lambda x: levels.get(x['threat_level'], 0), default=None)
        if highest_rule:
            highest_level = highest_rule['threat_level']
            summary = f"Threat detected: {highest_level}. Matched rule: {highest_rule['name']}."

    final_result = {
        "is_anomaly": is_anomaly_detected,
        "threat_level": highest_level,
        "summary": summary,
        "details": rule_based_findings,
        "llm_reasoning": llm_reasoning_text
    }

    return final_result