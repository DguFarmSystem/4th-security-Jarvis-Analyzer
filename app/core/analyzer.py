import os
import httpx
import glob
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
                if any(rule.match([event])):
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

    # 규칙 기반 분석을 먼저 실행합니다.
    rule_based_findings = rule_analyzer.analyze(transcript)

    llm_reasoning_text = "N/A" # LLM 분석 결과 기본값
    is_anomaly_detected = len(rule_based_findings) > 0

    # 규칙 기반에서 탐지된 내용이 없을 경우에만 LLM을 호출.
    if not is_anomaly_detected:
        llm_reasoning_text = "규칙 기반 위협이 탐지되지 않아 LLM 분석을 실행합니다."
        try:
            prompt = f'''
                    You are a security expert specializing in analyzing SSH session logs.
                    The following SSH session transcript for user '{user}' on server '{server_id}' did not match any known threat rules.
                    Analyze it for any other subtle, suspicious, or anomalous behavior that might indicate a threat.
                    If you find a potential threat, provide a brief, one-sentence summary of your reasoning.
                    If not, simply state that the activity appears benign.
                    Transcript:
                    ---
                    {transcript}
                    ---
                    '''
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
            llm_reasoning_text = f"LLM Analyzer Network Error: {e}"
        except Exception as e:
            llm_reasoning_text = f"An unexpected error occurred during LLM analysis: {e}"
    else:
        # 규칙 기반에서 위협이 탐지되었으므로 LLM 분석 스킵.
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