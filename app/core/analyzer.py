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
        # Sigma 규칙과 매칭시키기 위해 분석할 데이터를 리스트 형태로 변형.
        events = [{'CommandLine': transcript}]

        for rule in self.rules:
            try:
                # rule.match() 메서드를 사용하여 이벤트가 규칙과 일치하는지 확인.
                if any(rule.match(events)):
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


    rule_based_findings = rule_analyzer.analyze(transcript)

    # LLM 기반 분석 실행
    llm_reasoning_text = "AI 분석 로직 실행 전"
    # ... (LLM 호출 로직은 여기에 그대로 유지) ...
    try:
        prompt = f'''
                You are a security expert specializing in analyzing SSH session logs.
                Analyze the following SSH session transcript for user '{user}' on server '{server_id}'.
                Identify any suspicious or malicious activities.

                Based on your analysis, provide a brief, one-sentence summary of the threat level and your reasoning.

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

    # 결과 종합
    is_anomaly_detected = len(rule_based_findings) > 0

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