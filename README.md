# Jarvis 보안 분석 도구

## 1. 프로젝트 설명

Jarvis 보안 분석 도구는 SSH 세션 로그를 받아 위협을 탐지하고 평가하는 하이브리드 분석 시스템입니다. Go로 작성된 백엔드(Teleport)로부터 세션 로그를 API 형태로 수신하여, 사전에 정의된 규칙 기반 분석과 AI 모델(Ollama + Phi-3-mini)을 이용한 심층 분석을 함께 수행합니다.

모든 컴포넌트는 Docker 컨테이너 환경에서 동작하도록 설계되어 있어, 쉽고 빠르게 배포하고 확장할 수 있습니다.

## 2. 주요 기능

- **하이브리드 분석**: 알려진 위협 패턴을 빠르게 탐지하는 규칙 기반 분석과, 문맥을 이해하여 미묘한 위협을 찾아내는 AI 기반 분석을 결합하여 정확도를 높였습니다.
- **API 기반 연동**: 간단한 REST API 엔드포인트(`POST /api/v1/analyze`)를 통해 외부 시스템과 쉽게 연동할 수 있습니다.
- **컨테이너 기반 아키텍처**: Docker 및 Docker Compose를 사용하여 전체 서비스를 손쉽게 배포하고 관리할 수 있습니다.
- **로컬 LLM 연동**: Ollama를 통해 Phi-3-mini와 같은 경량 LLM을 로컬 서버에 직접 띄워 사용하므로, 민감한 로그 데이터가 외부로 유출되지 않습니다.

## 3. 아키텍처

이 시스템은 Docker Compose에 의해 관리되는 여러 컨테이너가 Docker의 가상 네트워크를 통해 통신하는 구조로 이루어져 있습니다.

`[Go Backend (Teleport)] <--> [Python Analyzer] <--> [AI Model]`

## 4. 기술 스택

- **Backend**: Python, FastAPI, Uvicorn
- **AI / LLM**: Ollama, Phi-3-mini
- **API Client**: HTTPX
- **Deployment**: Docker, Docker Compose

---

## 5. 테스트 환경 설정 및 실행 가이드

이 가이드는 Docker를 사용해 테스트 환경을 설정하고 실행하는 방법을 안내합니다.

### 5.1. 사전 준비

- **Docker 및 Docker Compose 설치**:
    - 테스트를 진행할 시스템에 Docker가 설치되어 있어야 합니다.
- **프로젝트 소스 코드**:
    - 이 프로젝트의 전체 소스 코드를 준비합니다.

### 5.2. 테스트 환경 실행

터미널에서 프로젝트의 루트 디렉토리로 이동한 후, 아래 명령어를 순서대로 실행합니다.

1. **소스 코드 로컬 환경에 클론**:
    - 서비스를 빌드할 수 있는 소스 코드를 로컬 환경에 클론한 후, 해당 디렉토리로 이동합니다.
    ```bash
    git clone https://github.com/DguFarmSystem/4th-security-Jarvis-Analyzer.git
   ```
    ```bash
    cd 4th-security-Jarvis-Analyzer
    ```

2. **전체 서비스 빌드 및 실행**:
    -   `docker-compose.yml`에 정의된 모든 서비스(Backend, Analyzer, Ollama)를 빌드하고 백그라운드에서 실행합니다.
    ```bash
    docker compose up -d --build
    ```

3. **AI 모델 다운로드**:
    -   서비스가 실행된 후, 아래 명령어를 터미널에 입력하여 Ollama 컨테이너가 Phi-3 모델을 다운로드하도록 합니다.
    ```bash
    docker exec -it phi-3-mini ollama run phi3
    ```
    *(다운로드가 시작되고 `>>>` 프롬프트가 표시되면 완료된 것입니다. `Ctrl+D`로 빠져나올 수 있습니다.)*

4. **컨테이너 실행 확인 (선택 사항)**:
    -   아래 명령어로 모든 컨테이너가 정상적으로 실행 중인지 확인할 수 있습니다.
    ```bash
    docker compose ps
    ```

### 5.3. API 테스트

모든 서비스가 실행되면, 터미널에서 `curl` 명령어를 사용하여 분석 서버가 정상적으로 동작하는지 테스트할 수 있습니다.

- **테스트 명령어**:
  ```bash
  curl -X POST "http://localhost:8000/api/v1/analyze" -H "Content-Type: application/json" -d '{"SessionID": "test-session-123", "User": 
     "testuser", "ServerID": "server-01", "ServerAddr": "192.168.1.10", "SessionStart": "2025-09-28T10:00:00Z", "SessionEnd": 
     "2025-09-28T10:05:00Z", "Transcript": "/rm"}'
  ```

- **예상 결과**:
    -   `Transcript`에 `/rm` 명령어 때문에, 다음과 같이 "Critical" 등급의 분석 결과가 JSON 형태로 반환됩니다.
  ```json
  {
  "is_anomaly": true,
  "threat_level": "MEDIUM",
  "summary": "Threat detected: MEDIUM. Matched rule: Clear Linux Logs.",
  "details": [
    {
      "type": "sigma_rule",
      "rule_id": "80915f59-9b56-4616-9de0-fd0dea6c12fe",
      "name": "Clear Linux Logs",
      "description": "Detects attempts to clear logs on the system. Adversaries may clear system logs to hide evidence of an intrusion (Matched Command: /rm)",
      "threat_level": "MEDIUM",
      "tags": [
        "attack.defense-evasion",
        "attack.t1070.002"
      ]
    },
    {
      "type": "sigma_rule",
      "rule_id": "30aed7b6-d2c1-4eaf-9382-b6bc43e50c57",
      "name": "File Deletion",
      "description": "Detects file deletion using \"rm\", \"shred\" or \"unlink\" commands which are used often by adversaries to delete files left behind by the actions of their intrusion activity (Matched Command: /rm)",
      "threat_level": "INFORMATIONAL",
      "tags": [
        "attack.defense-evasion",
        "attack.t1070.004"
      ]
    }
  ],
  "llm_reasoning": "명확한 규칙 기반 위협이 탐지되어 LLM 분석을 건너뛰었습니다."
    }
    ```

### 5.4. 서비스 접속 정보

- **Backend 웹 UI**: `http://localhost:3000`
- **분석 서버 API 문서 (Swagger UI)**: `http://localhost:8000/docs`

### 5.5. 테스트 환경 종료

-   테스트가 끝나면 아래 명령어로 실행 중인 모든 컨테이너를 중지하고 삭제할 수 있습니다.
    ```bash
    docker compose down
    ```
