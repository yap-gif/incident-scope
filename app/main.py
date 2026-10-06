from fastapi import FastAPI

app = FastAPI(
    title="IncidentScope",
    description="Defensive security event analysis and incident investigation platform.",
    version="0.1.0",
)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "incident-scope",
    }
