from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import secrets

APPROVAL_REQUEST_FORMAT = "FVP12-REQ-1"
APPROVAL_RESPONSE_FORMAT = "FVP12-RESP-1"
REQUESTS_DIR_NAME = "requests"
RESPONSES_DIR_NAME = "responses"
REQUEST_EXTENSION = ".req"
RESPONSE_EXTENSION = ".resp"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def generate_request_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{timestamp}-{secrets.token_hex(3)}"


def ensure_exchange_dirs(base_dir: Path) -> tuple[Path, Path]:
    requests_dir = base_dir / REQUESTS_DIR_NAME
    responses_dir = base_dir / RESPONSES_DIR_NAME
    requests_dir.mkdir(parents=True, exist_ok=True)
    responses_dir.mkdir(parents=True, exist_ok=True)
    return requests_dir, responses_dir


def request_path_for(base_dir: Path, request_id: str) -> Path:
    return base_dir / REQUESTS_DIR_NAME / f"{request_id}{REQUEST_EXTENSION}"


def response_path_for(base_dir: Path, request_id: str) -> Path:
    return base_dir / RESPONSES_DIR_NAME / f"{request_id}{RESPONSE_EXTENSION}"


def encode_record(fields: dict[str, str | None]) -> str:
    lines: list[str] = []
    for key, value in fields.items():
        if value is None:
            continue
        lines.append(f"{key}={value}")
    return "\n".join(lines) + "\n"


def write_record(path: Path, fields: dict[str, str | None]) -> Path:
    path.write_text(encode_record(fields), encoding="utf-8")
    return path


def read_record(path: Path) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        metadata[key] = value
    return metadata


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()