from fastapi import FastAPI

app = FastAPI(
    title="Analyzer API",
    description="SSH session analyzer API",
    version="1.0.0",
)

@app.get("/")
async def root():
    return {"status": "Analyzer is running"}