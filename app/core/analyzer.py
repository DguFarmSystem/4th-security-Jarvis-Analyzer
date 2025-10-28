import os
import httpx
import glob
import json
import yaml
import re
import ast
import logging

from app.models.schemas import AnalysisRequest

class RuleBasedAnalyzer:
    def __init__(self, rules_path: str):
        self.rules = self._load_rules(rules_path)
        print(f"Loaded {len(self.rules)} rules using PyYAML.")

    def _load_rules(self, path: str) -> list[dict]:
        rule_files = glob.glob(os.path.join(path, '**', '*.yml'), recursive=True)
        loaded_rules = []
        for file_path in rule_files:
            with open(file_path, 'r', encoding='utf-8') as f:
                try:
                    rule = yaml.safe_load(f)
                    if rule and 'detection' in rule and 'logsource' in rule:
                        if rule['logsource'].get('category') == 'process_creation':
                            loaded_rules.append(rule)
                except yaml.YAMLError as e:
                    print(f"Warning: Could not parse YAML file {os.path.basename(file_path)}. Reason: {e}")
        return loaded_rules

    import re

    def extract_user_commands(transcript: str) -> str:
        lines = transcript.splitlines()
        commands = []
        for line in lines:
            match = re.search(r'root@[^\s]+:~#\s*(.+)', line)
            if match:
                cmd = match.group(1).strip()
                if cmd:
                    commands.append(cmd)
        return "\n".join(commands)

    def _evaluate_rule(self, rule_detection: dict, event: dict) -> bool:
        """규칙의 detection 조건을 간단히 평가하는 함수"""
        condition = rule_detection.get('condition')

        # 각 selection/keyword의 평가 결과를 저장
        eval_results = {}

        for key, value in rule_detection.items():
            if key.startswith('selection') or key == 'keywords':
                eval_results[key] = self._check_selection(value, event)

        # condition을 평가하여 최종 결과 반환
        try:
            # condition 문자열의 변수들을 True/False로 치환
            condition_str = condition.replace('1 of them', 'or').replace('all of them', 'and')
            for key, result in eval_results.items():
                # '1 of selection_*' 같은 패턴을 처리하기 위해 와일드카드 지원
                if '*' in key:
                    key_pattern = key.replace('*', '.*')
                    for eval_key in eval_results:
                        if re.match(key_pattern, eval_key):
                            condition_str = condition_str.replace(key, str(eval_results[eval_key]))
                else:
                    condition_str = condition_str.replace(key, str(result))

            return eval(condition_str)
        except:
            return False # condition 평가 실패 시 False 반환

    def _check_selection(self, selection: any, event: dict) -> bool:
        """개별 selection/keywords 블록이 event와 일치하는지 확인"""
        if isinstance(selection, dict):
            # 'CommandLine|contains|all': ['a', 'b'] 같은 딕셔너리 형태
            for key, value in selection.items():
                # '|all' 같은 특수 키 처리
                if '|' in key and key.split('|')[1] == 'all':
                    patterns = value if isinstance(value, list) else [value]
                    # 모든 패턴이 CommandLine에 포함되어야 함
                    return all(p in event['CommandLine'] for p in patterns)

                parts = key.split('|')
                field, modifiers = parts[0], parts[1:]

                event_value = event.get(field)
                if not event_value: continue

                patterns = value if isinstance(value, list) else [value]

                all_modifier = 'all' in modifiers
                match_results = []

                for pattern in patterns:
                    match = False
                    # pattern이 문자열일 경우에만 연산 수행
                    if isinstance(pattern, str):
                        if 'contains' in modifiers and pattern in event_value: match = True
                        elif 'endswith' in modifiers and event_value.endswith(pattern): match = True
                        elif 'startswith' in modifiers and event_value.startswith(pattern): match = True
                        elif not modifiers and event_value == pattern: match = True
                    match_results.append(match)

                if all_modifier: return all(match_results)
                else: return any(match_results)

        elif isinstance(selection, list):
            # 키워드 리스트 형태
            for item in selection:
                # 리스트의 항목이 문자열인 경우에만 확인
                if isinstance(item, str) and item in event['CommandLine']:
                    return True
        return False


    def analyze(self, transcript: str) -> list[dict]:
        findings = []
        lines = transcript.strip().split('\n')

        for rule in self.rules:
            detected_lines = []
            for line in lines:
                if not line.strip(): continue

                command_parts = line.strip().split()
                image = command_parts[0] if command_parts else ""

                event = {'CommandLine': line.strip(), 'Image': image, 'ParentImage': ''}

                if self._evaluate_rule(rule.get('detection', {}), event):
                    detected_lines.append(line.strip())

            if detected_lines:
                if not any(f['rule_id'] == rule.get('id') for f in findings):
                    findings.append({
                        "type": "sigma_rule",
                        "rule_id": rule.get('id', 'N/A'),
                        "name": rule.get('title', 'N/A'),
                        "description": rule.get('description', '') + f" (Matched Command: {', '.join(detected_lines)})",
                        "threat_level": rule.get('level', 'informational').upper(),
                        "tags": rule.get('tags', [])
                    })
        return findings


# Sigma 규칙이 있는 디렉토리 경로를 지정.
RULES_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'sigma_rules')

# RuleBasedAnalyzer 인스턴스 생성
rule_analyzer = RuleBasedAnalyzer(RULES_PATH)

client = httpx.AsyncClient()
LLM_ANALYZER_URL = "http://llm-analyzer:11434/api/chat"

async def call_and_parse_llm(payload):
    try:
        logging.debug("Calling LLM_ANALYZER_URL %s with payload keys: %s", LLM_ANALYZER_URL, list(payload.keys()))
        response = await client.post(LLM_ANALYZER_URL, json=payload, timeout=60.0)
        logging.debug("LLM response status: %s", response.status_code)
        response.raise_for_status()

        # 응답 본문을 JSON으로 파싱 시도
        try:
            body = response.json()
            # Ollama 응답 형식에서 content 추출
            if 'message' in body and 'content' in body['message']:
                return body['message']['content'].strip()
        except json.JSONDecodeError:
            # JSON 파싱 실패 시, 텍스트로 처리
            return response.text.strip()
        
        # 예상치 못한 JSON 구조일 경우
        return response.text.strip()

    except httpx.RequestError as e:
        logging.exception("LLM call failed")
        raise RuntimeError(f"Failed to call LLM: {e}")
    except Exception as e:
        logging.exception("LLM response processing failed")
        raise RuntimeError(f"Failed to process LLM response: {e}")


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
            # LLM이 위협적인 명령어를 직접 추출하도록 프롬프트 설정
            prompt = f"""
                You are a strict security log analyzer. Analyze only the given SSH transcript.

                You must follow these strict rules:

                1. Only analyze actual user commands that come *after* the prompt like `root@...:~#`.
                2. Ignore any lines that:
                - start with `bash:`, `logout`, `Failed to launch:`, or other system messages
                - do not directly follow a prompt
                3. You are forbidden from making assumptions or hallucinating commands.
                - If a command is **not explicitly written** in the transcript, you **must not mention it.**
                - Do NOT invent or imagine commands such as `rm -rf`, `curl`, etc. unless they literally appear.
                4. Respond only with:
                - The exact suspicious command line (if found in the transcript)
                - or exactly `NO_THREAT` if no suspicious command exists.
                5. Do not include any reasoning, explanation, or additional text.

                Transcript:
                ---
                {transcript}
                ---
                """
            payload = { "model": "phi3", "messages": [{"role": "user", "content": prompt}], "stream": False }

            llm_response_text = await call_and_parse_llm(payload)
            
            is_threat = False
            # 기본적으로 위협이 없다고 가정
            llm_reasoning_text = "AI가 분석한 결과, 특별한 위협이 발견되지 않았습니다."

            # LLM 응답이 'NO_THREAT'가 아니고, 비어있지 않다면 위협으로 간주
            if llm_response_text and llm_response_text.strip() != "NO_THREAT":
                is_threat = True
                threatening_cmd = llm_response_text.strip()
                llm_reasoning_text = f"AI가 다음 명령어를 의심스러운 활동으로 탐지했습니다: `{threatening_cmd}`"
            
            # LLM의 판단을 최종 결과에 반영
            if is_threat:
                is_anomaly_detected = True
                rule_based_findings.append({
                    "type": "llm_analysis",
                    "rule_id": "LLM-S01",
                    "name": "Suspicious Activity Detected by AI",
                    "description": f"AI detected a potential threat in the command: `{threatening_cmd}`",
                    "threat_level": "MEDIUM",
                    "tags": ["ai-detection"]
                })

        except (httpx.RequestError, RuntimeError) as e:
            llm_reasoning_text = f"LLM analysis failed: {e}"
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