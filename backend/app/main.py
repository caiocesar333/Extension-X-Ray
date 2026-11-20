from __future__ import annotations

import os
import tempfile
from pathlib import Path

from fastapi import FastAPI, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import __version__
from .analyzer import ExtensionAnalyzer
from .config import ArchiveLimits
from .errors import XRayError
from .models import AnalysisReport, ApiError, ApiErrorDetail, HealthResponse, RepositoryAnalysisReport
from .rea import ReaAdapter
from .repository_analyzer import RepositoryAnalyzer

limits = ArchiveLimits.from_env()
rea_adapter = ReaAdapter()
analyzer = ExtensionAnalyzer(limits=limits, rea=rea_adapter)
repository_analyzer = RepositoryAnalyzer(limits=limits, rea=rea_adapter)

app = FastAPI(
    title="Extension X-Ray API",
    version=__version__,
    description="Local-first static security analysis for VS Code extensions and source repositories.",
)
origins = [value.strip() for value in os.getenv("XRAY_CORS_ORIGINS", "http://localhost:5173").split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.exception_handler(XRayError)
async def handle_xray_error(_request: Request, error: XRayError) -> JSONResponse:
    body = ApiError(detail=ApiErrorDetail(code=error.code, message=error.message))
    return JSONResponse(status_code=error.status_code, content=body.model_dump())


@app.get("/api/v1/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", version=__version__, rea=rea_adapter.status())


@app.get("/api/v1/report-schema")
def report_schema() -> dict[str, object]:
    return AnalysisReport.model_json_schema()


@app.get("/api/v1/repository-report-schema")
def repository_report_schema() -> dict[str, object]:
    return RepositoryAnalysisReport.model_json_schema()


async def _save_upload(file: UploadFile, uploaded_path: Path, *, label: str) -> int:
    total = 0
    try:
        with uploaded_path.open("xb") as output:
            while chunk := await file.read(128 * 1024):
                total += len(chunk)
                if total > limits.max_upload_bytes:
                    raise XRayError(
                        "upload_too_large",
                        f"{label} exceeds the upload size limit",
                        status_code=413,
                    )
                output.write(chunk)
    finally:
        await file.close()
    if total == 0:
        raise XRayError("empty_upload", f"Uploaded {label} is empty", status_code=400)
    return total


@app.post(
    "/api/v1/analyze",
    response_model=AnalysisReport,
    responses={400: {"model": ApiError}, 413: {"model": ApiError}, 422: {"model": ApiError}},
)
async def analyze_extension(file: UploadFile) -> AnalysisReport:
    filename = Path(file.filename or "").name
    if not filename.lower().endswith(".vsix"):
        raise XRayError("invalid_file_type", "Upload must use the .vsix extension", status_code=400)
    with tempfile.TemporaryDirectory(prefix="extension-xray-upload-") as temporary:
        uploaded_path = Path(temporary) / "upload.vsix"
        await _save_upload(file, uploaded_path, label="VSIX")
        return analyzer.analyze(uploaded_path, source_filename=filename)


@app.post(
    "/api/v1/analyze-repository",
    response_model=RepositoryAnalysisReport,
    responses={400: {"model": ApiError}, 413: {"model": ApiError}, 422: {"model": ApiError}},
)
async def analyze_repository(file: UploadFile) -> RepositoryAnalysisReport:
    filename = Path(file.filename or "").name
    if not filename.lower().endswith(".zip"):
        raise XRayError("invalid_file_type", "Repository upload must use the .zip extension", status_code=400)
    with tempfile.TemporaryDirectory(prefix="repo-xray-upload-") as temporary:
        uploaded_path = Path(temporary) / "repository.zip"
        await _save_upload(file, uploaded_path, label="repository archive")
        return repository_analyzer.analyze(uploaded_path, source_filename=filename)

