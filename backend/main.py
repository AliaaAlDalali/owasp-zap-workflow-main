"""Himaak (حِماك) platform API.

Run from the repository root, so the shared `himaak_core` package is importable:
    python -m uvicorn main:app --app-dir backend
"""

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from config import settings
from database import Database
from modules.auth.router import router as auth_router
from modules.findings.router import router as findings_router
from modules.organizations.router import router as organizations_router
from modules.scans.router import router as scans_router
from modules.scans.service import ScanService
from modules.targets.router import router as targets_router
from utils.errors import (
    AppError, AuthenticationError, ConflictError, NotFoundError, PermissionDeniedError,
    RuleViolationError, TooManyAttemptsError,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await Database.initialize()
    stop = asyncio.Event()
    worker = asyncio.create_task(ScanService().run_worker(stop))
    yield
    stop.set()
    try:
        await asyncio.wait_for(worker, timeout=10)
    except asyncio.TimeoutError:
        worker.cancel()


app = FastAPI(title="Himaak API", lifespan=lifespan)

if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Content-Type"],
    )


_APP_ERROR_STATUS = {
    NotFoundError: 404,
    PermissionDeniedError: 403,
    ConflictError: 409,
    RuleViolationError: 400,
    AuthenticationError: 401,
    TooManyAttemptsError: 429,
}


@app.exception_handler(AppError)
async def app_error(request: Request, error: AppError) -> JSONResponse:
    status_code = next((code for kind, code in _APP_ERROR_STATUS.items() if isinstance(error, kind)), 400)
    return JSONResponse({"message": error.message}, status_code=status_code)


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, error: StarletteHTTPException) -> JSONResponse:
    return JSONResponse({"message": str(error.detail)}, status_code=error.status_code, headers=error.headers)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, error: RequestValidationError) -> JSONResponse:
    first = error.errors()[0]
    field = ".".join(str(part) for part in first["loc"][1:])
    return JSONResponse({"message": f"{field}: {first['msg']}" if field else first["msg"]}, status_code=422)


@app.get("/health", tags=["health"])
async def health() -> dict[str, str]:
    return {"status": "ok"}


app.include_router(auth_router)
app.include_router(organizations_router)
app.include_router(targets_router)
app.include_router(scans_router)
app.include_router(findings_router)
