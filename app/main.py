from fastapi import FastAPI

from app.api.routes import router as api_router


app = FastAPI(
    title="IncidentScope",
    description=(
        "Defensive security event analysis "
        "and incident investigation platform."
    ),
    version="0.1.1",
)

app.include_router(api_router)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "incident-scope",
    }
