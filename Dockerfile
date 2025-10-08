FROM python:3.13-slim

# 컨테이너 내의 작업 디렉토리를 /app 으로 설정합니다.
WORKDIR /app

# 의존성 정의 파일 복사
COPY requirements.txt requirements.txt

# requirements.txt 에 정의된 라이브러리들을 설치합니다.
RUN pip install --no-cache-dir -r requirements.txt

# 현재 디렉토리의 모든 파일(소스코드)을 컨테이너의 /app 디렉토리로 복사합니다.
COPY . .

# 컨테이너의 8000번 포트를 외부에 노출시킵니다.
EXPOSE 8000

# 컨테이너가 시작될 때 실행할 기본 명령어를 설정합니다.
# 0.0.0.0 호스트를 사용하여 컨테이너 외부에서의 접속을 허용합니다.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
