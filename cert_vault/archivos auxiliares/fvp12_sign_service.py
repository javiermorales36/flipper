from __future__ import annotations

import argparse
import base64
import getpass
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import string
from urllib.parse import urlparse

from flipper_usb_storage import FlipperUsbStorage, FlipperUsbStorageError, probe_flipper_port

from fvp12_approval import (
    APPROVAL_REQUEST_FORMAT,
    APPROVAL_RESPONSE_FORMAT,
    ensure_exchange_dirs,
    generate_request_id,
    read_record,
    request_path_for,
    response_path_for,
    sha256_file,
    utc_now_iso,
    write_record,
)
from fvp12_core import (
    SUPPORTED_SIGNATURE_ALGORITHMS,
    build_bundle_summary,
    certificate_to_pem_bytes,
    decrypt_bundle,
    load_signing_material_with_chain,
    read_bundle,
    read_bundle_text,
    resolve_signature_algorithm,
    sign_bytes,
)
from fvp12_pdf_sign import default_output_path, sign_pdf_bytes, sign_pdf_file


FLIPPER_CERT_VAULT_ROOT = "/ext/apps_data/cert_vault"
FLIPPER_INSTALLED_ROOT = f"{FLIPPER_CERT_VAULT_ROOT}/installed"
FLIPPER_REQUESTS_ROOT = f"{FLIPPER_CERT_VAULT_ROOT}/requests"
FLIPPER_RESPONSES_ROOT = f"{FLIPPER_CERT_VAULT_ROOT}/responses"


def probe_flipper_usb_bridge(port: str) -> tuple[bool, str, str]:
    try:
        resolved_port = probe_flipper_port(port)
    except Exception as exc:  # noqa: BLE001
        return False, port, str(exc)
    return True, resolved_port, ""


def resolve_flipper_cert_vault_dir(root_hint: Path | None) -> Path | None:
    if root_hint is not None:
        root = root_hint.expanduser()
        if root.name in {"requests", "responses"}:
            return root.parent.resolve()
        if root.name == "cert_vault":
            return root.resolve()
        if (root / "ext").exists():
            return (root / "ext" / "apps_data" / "cert_vault").resolve()
        if root.exists():
            return (root / "apps_data" / "cert_vault").resolve()
        return None

    for drive_letter in string.ascii_uppercase:
        drive_root = Path(f"{drive_letter}:/")
        if not drive_root.exists():
            continue
        for candidate in (
            drive_root / "apps_data" / "cert_vault",
            drive_root / "ext" / "apps_data" / "cert_vault",
        ):
            if candidate.exists():
                return candidate.resolve()

    return None


def classify_flipper_bridge_mode(cert_vault_dir: Path | None, use_usb: bool) -> str:
    if use_usb:
        return "usb"
    if cert_vault_dir is None:
        return "none"

    lowered_parts = {part.lower() for part in cert_vault_dir.parts}
    if "simulated_flipper" in lowered_parts:
        return "simulated"

    return "device"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Expose a local JSON signing service backed by a Flipper vault bundle (.fvp12)."
    )
    parser.add_argument(
        "bundle",
        type=Path,
        help="Local path to the .fvp12 bundle or installed bundle filename to read from the Flipper.",
    )
    parser.add_argument(
        "--vault-pin", help="Vault PIN/passphrase used when the .fvp12 bundle was generated"
    )
    parser.add_argument(
        "--p12-password",
        help="Original PKCS#12 password. Only needed for legacy pkcs12-based bundles.",
    )
    parser.add_argument(
        "--exchange-dir",
        type=Path,
        default=Path("approval_exchange"),
        help="Directory used to exchange approval request/response files with the Flipper app.",
    )
    parser.add_argument(
        "--flipper-root",
        type=Path,
        help="Mounted Flipper storage root or apps_data/cert_vault path. If omitted, the service tries to auto-detect it.",
    )
    parser.add_argument(
        "--flipper-usb",
        action="store_true",
        help="Use the standalone USB storage bridge instead of a mounted SD path.",
    )
    parser.add_argument(
        "--flipper-port",
        default="auto",
        help="USB CDC port for the Flipper storage bridge. Defaults to auto.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address. Defaults to 127.0.0.1")
    parser.add_argument("--port", type=int, default=8765, help="TCP port. Defaults to 8765")
    return parser.parse_args()


def prompt_secret(value: str | None, prompt: str) -> str:
    if value is not None:
        return value
    return getpass.getpass(prompt)


def resolve_bundle_filename(bundle_reference: Path) -> str:
    bundle_name = bundle_reference.name or str(bundle_reference)
    if not bundle_name:
        raise SystemExit("Bundle reference cannot be empty.")
    if Path(bundle_name).suffix.lower() != ".fvp12":
        bundle_name = f"{bundle_name}.fvp12"
    return bundle_name


def bundle_selector_tokens(value: str) -> set[str]:
    return {token.lower() for token in re.findall(r"[A-Za-z0-9]+", value) if len(token) >= 3}


def normalize_bundle_selector(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "", value).lower()


def bundle_reference_values(bundle_reference: Path) -> set[str]:
    values = {str(bundle_reference), bundle_reference.name, bundle_reference.stem, resolve_bundle_filename(bundle_reference)}
    return {value for value in values if value}


def bundle_candidate_values(candidate_path: str, metadata: dict[str, str] | None = None) -> set[str]:
    path = Path(candidate_path)
    values = {candidate_path, path.name, path.stem}
    if metadata is not None:
        values.update(
            value
            for value in (metadata.get("alias", ""), metadata.get("serial", ""), metadata.get("common_name", ""))
            if value
        )
    return values


def select_installed_bundle_path(
    bundle_reference: Path,
    candidates: list[tuple[str, dict[str, str] | None]],
) -> str:
    reference_values = bundle_reference_values(bundle_reference)
    reference_norms = {normalize_bundle_selector(value) for value in reference_values if value}
    reference_tokens = set().union(*(bundle_selector_tokens(value) for value in reference_values if value))
    scored_candidates: list[tuple[bool, int, int, str]] = []

    for candidate_path, metadata in candidates:
        candidate_values = bundle_candidate_values(candidate_path, metadata)
        candidate_norms = {normalize_bundle_selector(value) for value in candidate_values if value}
        matched_tokens = reference_tokens.intersection(
            set().union(*(bundle_selector_tokens(value) for value in candidate_values if value))
        )
        scored_candidates.append(
            (
                bool(reference_norms.intersection(candidate_norms)),
                len(matched_tokens),
                max((len(token) for token in matched_tokens), default=0),
                candidate_path,
            )
        )

    if not scored_candidates:
        raise SystemExit("No installed bundles were found in Cert Vault.")

    scored_candidates.sort(key=lambda item: (item[0], item[1], item[2], item[3]), reverse=True)
    best_match = scored_candidates[0]
    if best_match[0] or best_match[1] > 0:
        if len(scored_candidates) > 1 and scored_candidates[1][:3] == best_match[:3]:
            conflicting = ", ".join(candidate[3] for candidate in scored_candidates[:2])
            raise SystemExit(
                f"Bundle reference '{bundle_reference}' is ambiguous. Matching installed bundles: {conflicting}"
            )
        return best_match[3]

    available_bundles = ", ".join(candidate[3] for candidate in scored_candidates)
    raise SystemExit(
        f"Could not match bundle reference '{bundle_reference}' against installed bundles: {available_bundles}"
    )


def parse_remote_bundle_listing(listing: list[str]) -> list[str]:
    bundle_paths: list[str] = []
    for line in listing:
        remote_path = line.split(", size ", 1)[0].strip()
        if remote_path.lower().endswith(".fvp12"):
            bundle_paths.append(remote_path)
    return bundle_paths


def load_bundle_from_flipper_storage(
    bundle_reference: Path,
    *,
    flipper_bridge_mode: str,
    flipper_cert_vault_dir: Path | None,
    flipper_port: str,
) -> tuple[dict[str, str], str]:
    local_bundle_path = bundle_reference.expanduser()
    if local_bundle_path.is_file():
        resolved_path = local_bundle_path.resolve()
        return read_bundle(resolved_path), str(resolved_path)

    bundle_filename = resolve_bundle_filename(bundle_reference)

    if flipper_bridge_mode == "usb":
        try:
            with FlipperUsbStorage(flipper_port) as storage:
                remote_bundle_path = select_installed_bundle_path(
                    bundle_reference,
                    [
                        (candidate_path, read_bundle_text(storage.read_file(candidate_path).decode("utf-8")))
                        for candidate_path in parse_remote_bundle_listing(storage.list_tree(FLIPPER_INSTALLED_ROOT))
                    ],
                )
                bundle_bytes = storage.read_file(remote_bundle_path)
        except Exception as exc:  # noqa: BLE001
            raise SystemExit(
                f"Failed to read bundle from Flipper storage at {FLIPPER_INSTALLED_ROOT}: {exc}"
            ) from exc
        try:
            return read_bundle_text(bundle_bytes.decode("utf-8")), remote_bundle_path
        except Exception as exc:  # noqa: BLE001
            raise SystemExit(f"Failed to decode bundle read from Flipper storage: {remote_bundle_path}: {exc}") from exc

    if flipper_cert_vault_dir is not None:
        installed_dir = (flipper_cert_vault_dir / "installed").resolve()
        installed_candidates = [
            (str(candidate.resolve()), read_bundle(candidate.resolve()))
            for candidate in installed_dir.glob("*.fvp12")
            if candidate.is_file()
        ]
        installed_bundle_path = Path(select_installed_bundle_path(bundle_reference, installed_candidates))
        if installed_bundle_path.is_file():
            return read_bundle(installed_bundle_path), str(installed_bundle_path)

    raise SystemExit(
        "Bundle file not found locally and could not be read from Flipper installed storage: "
        f"{bundle_reference}"
    )


class Fvp12SignService(ThreadingHTTPServer):
    def __init__(
        self,
        server_address,
        request_handler_class,
        summary,
        private_key,
        certificate,
        additional_certificates,
        exchange_dir: Path,
        flipper_cert_vault_dir: Path | None,
        flipper_bridge_mode: str,
        flipper_port: str,
    ):
        super().__init__(server_address, request_handler_class)
        self.summary = summary
        self.private_key = private_key
        self.certificate = certificate
        self.additional_certificates = additional_certificates
        self.exchange_dir = exchange_dir
        self.web_stage_dir = exchange_dir / "web_stage"
        self.web_stage_dir.mkdir(parents=True, exist_ok=True)
        self.flipper_cert_vault_dir = flipper_cert_vault_dir
        self.flipper_bridge_mode = flipper_bridge_mode
        self.flipper_port = flipper_port
        self.flipper_requests_dir = None if flipper_cert_vault_dir is None else flipper_cert_vault_dir / "requests"
        self.flipper_responses_dir = None if flipper_cert_vault_dir is None else flipper_cert_vault_dir / "responses"
        if self.flipper_requests_dir is not None:
            self.flipper_requests_dir.mkdir(parents=True, exist_ok=True)
        if self.flipper_responses_dir is not None:
            self.flipper_responses_dir.mkdir(parents=True, exist_ok=True)


class Fvp12RequestHandler(BaseHTTPRequestHandler):
    server: Fvp12SignService

    def _bridge_is_available(self) -> bool:
        return bool(self.server.summary.get("flipper_bridge_active"))

    def _flipper_bridge_error(self) -> dict[str, str]:
        error_message = self.server.summary.get("flipper_bridge_error") or (
            "No se ha detectado el almacenamiento del Flipper. Monta la SD del dispositivo o usa --flipper-usb."
        )
        return {
            "error": error_message,
            "flipper_bridge_path": self.server.summary.get("flipper_bridge_path", ""),
        }

    def _json_error_message(self, raw_text: str, fallback: str) -> str:
        try:
            payload = json.loads(raw_text)
        except Exception:  # noqa: BLE001
            return raw_text or fallback
        if isinstance(payload, dict) and isinstance(payload.get("error"), str):
            return payload["error"]
        return raw_text or fallback

    def _render_web_ui(self) -> bytes:
        summary_json = json.dumps(self.server.summary, ensure_ascii=False)
        template_path = Path(__file__).with_name("fvp12_sign_service_ui.html")
        html_body = template_path.read_text(encoding="utf-8").replace("__SUMMARY_JSON__", summary_json)
        return html_body.encode("utf-8")

    def log_message(self, format: str, *args) -> None:
        return

    def _send_json(self, status: HTTPStatus, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status: HTTPStatus, content_type: str, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_binary(
        self,
        status: HTTPStatus,
        content_type: str,
        payload: bytes,
        download_name: str | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        if download_name:
            self.send_header("Content-Disposition", f'attachment; filename="{download_name}"')
        self.end_headers()
        self.wfile.write(payload)

    def _resolve_local_path(self, value: str) -> Path:
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = (Path.cwd() / path).resolve()
        return path

    def _read_json_body(self) -> dict:
        content_length = self.headers.get("Content-Length")
        if content_length is None:
            raise ValueError("Missing Content-Length header.")

        try:
            raw_body = self.rfile.read(int(content_length))
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"Failed to read request body: {exc}") from exc

        try:
            return json.loads(raw_body.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"Request body is not valid JSON: {exc}") from exc

    def _safe_signed_filename(self, file_name: str) -> str:
        candidate = Path(file_name or "documento.pdf").name
        candidate = re.sub(r"[^A-Za-z0-9._-]+", "_", candidate).strip("._") or "documento.pdf"
        path = Path(candidate)
        if path.suffix.lower() == ".pdf":
            return f"{path.stem}.signed.pdf"
        return f"{path.name}.signed.pdf"

    def _mirror_request_to_flipper(self, request_path: Path) -> None:
        if self.server.flipper_bridge_mode == "usb":
            self._ensure_usb_cert_vault_dirs()
            self._run_usb_storage(["send", str(request_path), f"{FLIPPER_REQUESTS_ROOT}/{request_path.name}"])
            return
        if self.server.flipper_requests_dir is None:
            return
        mirrored_path = self.server.flipper_requests_dir / request_path.name
        mirrored_path.write_bytes(request_path.read_bytes())

    def _sync_response_from_flipper(self, request_id: str) -> bool:
        if self.server.flipper_bridge_mode == "usb":
            local_response_path = response_path_for(self.server.exchange_dir, request_id)
            try:
                self._run_usb_storage(
                    ["receive", f"{FLIPPER_RESPONSES_ROOT}/{request_id}.resp", str(local_response_path)],
                    allow_missing=True,
                )
            except FileNotFoundError:
                return False
            return local_response_path.is_file()
        if self.server.flipper_responses_dir is None:
            return False

        mirrored_path = self.server.flipper_responses_dir / f"{request_id}.resp"
        if not mirrored_path.is_file():
            return False

        local_response_path = response_path_for(self.server.exchange_dir, request_id)
        mirrored_bytes = mirrored_path.read_bytes()
        if not local_response_path.is_file() or local_response_path.read_bytes() != mirrored_bytes:
            local_response_path.parent.mkdir(parents=True, exist_ok=True)
            local_response_path.write_bytes(mirrored_bytes)
        return True

    def _cleanup_flipper_exchange(self, request_id: str) -> None:
        if self.server.flipper_bridge_mode == "usb":
            self._run_usb_storage(["remove", f"{FLIPPER_REQUESTS_ROOT}/{request_id}.req"], allow_missing=True)
            self._run_usb_storage(["remove", f"{FLIPPER_RESPONSES_ROOT}/{request_id}.resp"], allow_missing=True)
            return
        if self.server.flipper_requests_dir is not None:
            (self.server.flipper_requests_dir / f"{request_id}.req").unlink(missing_ok=True)
        if self.server.flipper_responses_dir is not None:
            (self.server.flipper_responses_dir / f"{request_id}.resp").unlink(missing_ok=True)

    def _run_usb_storage(
        self,
        arguments: list[str],
        *,
        allow_missing: bool = False,
        allow_exists: bool = False,
    ) -> None:
        missing_markers = ("file/dir not exist", "invalid name/path")
        try:
            with FlipperUsbStorage(self.server.flipper_port) as storage:
                command = arguments[0]
                if command == "send":
                    storage.send_file(arguments[1], arguments[2])
                    return
                if command == "receive":
                    storage.receive_file(arguments[1], arguments[2])
                    return
                if command == "remove":
                    storage.remove(arguments[1])
                    return
                if command == "mkdir":
                    storage.mkdir(arguments[1])
                    return
                if command == "list":
                    storage.list_tree(arguments[1])
                    return
                raise RuntimeError(f"Unsupported USB storage command: {command}")
        except FlipperUsbStorageError as exc:
            lowered = str(exc).lower()
            if allow_missing and any(marker in lowered for marker in missing_markers):
                raise FileNotFoundError(str(exc)) from exc
            if allow_exists and "file/dir already exist" in lowered:
                return
            raise RuntimeError(str(exc)) from exc

    def _ensure_usb_cert_vault_dirs(self) -> None:
        for path in ("/ext/apps_data", FLIPPER_CERT_VAULT_ROOT, FLIPPER_REQUESTS_ROOT, FLIPPER_RESPONSES_ROOT):
            self._run_usb_storage(["mkdir", path], allow_exists=True)

    def _safe_stage_filename(self, file_name: str, request_id: str) -> str:
        candidate = Path(file_name or "documento.pdf").name
        candidate = re.sub(r"[^A-Za-z0-9._-]+", "_", candidate).strip("._") or "documento.pdf"
        suffix = Path(candidate).suffix.lower()
        if suffix != ".pdf":
            candidate = f"{Path(candidate).name}.pdf"
        return f"{request_id}_{candidate}"

    def _build_request_record(
        self,
        *,
        request_id: str,
        input_path: Path,
        output_path: Path,
        file_name: str,
        field_name: str,
        reason: str,
        location: str,
        contact_info: str,
        signer_name: str,
        signer_id: str,
        visible_signature: bool,
        web_request: bool,
    ) -> dict[str, str]:
        return {
            "format": APPROVAL_REQUEST_FORMAT,
            "request_id": request_id,
            "operation": "sign_pdf",
            "alias": self.server.summary["alias"],
            "bundle_kind": self.server.summary["bundle_kind"],
            "input_path": str(input_path),
            "output_path": str(output_path),
            "file_name": file_name,
            "field_name": field_name,
            "reason": reason,
            "location": location,
            "contact_info": contact_info,
            "signer_name": signer_name,
            "signer_id": signer_id,
            "visible_signature": "true" if visible_signature else "false",
            "web_request": "true" if web_request else "false",
            "pdf_sha256": sha256_file(input_path),
            "created_at": utc_now_iso(),
        }

    def _handle_status_route(self, request_id: str) -> None:
        request_path = request_path_for(self.server.exchange_dir, request_id)
        response_path = response_path_for(self.server.exchange_dir, request_id)
        self._sync_response_from_flipper(request_id)

        if not request_path.is_file():
            self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Unknown request_id: {request_id}"})
            return

        request_record = read_record(request_path)
        payload = {
            "request_id": request_id,
            "status": "pending",
            "alias": request_record.get("alias", self.server.summary.get("alias", "")),
            "file_name": request_record.get("file_name", ""),
            "pdf_sha256": request_record.get("pdf_sha256", ""),
        }
        if response_path.is_file():
            response_record = read_record(response_path)
            payload["status"] = response_record.get("decision", "pending")
            payload["decided_at"] = response_record.get("decided_at", "")

        self._send_json(HTTPStatus.OK, payload)

    def _handle_request_sign_pdf(self) -> None:
        try:
            request = self._read_json_body()
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        input_path_raw = request.get("input_path")
        if not isinstance(input_path_raw, str) or not input_path_raw:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "input_path is required."})
            return

        input_path = self._resolve_local_path(input_path_raw)
        if not input_path.is_file():
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Input PDF not found: {input_path}"})
            return

        output_path_raw = request.get("output_path")
        output_path = (
            self._resolve_local_path(output_path_raw)
            if isinstance(output_path_raw, str) and output_path_raw
            else default_output_path(input_path)
        )

        request_id = generate_request_id()
        request_record = self._build_request_record(
            request_id=request_id,
            input_path=input_path,
            output_path=output_path,
            file_name=input_path.name,
            field_name=str(request.get("field_name") or "Signature1"),
            reason=str(request.get("reason") or ""),
            location=str(request.get("location") or ""),
            contact_info=str(request.get("contact_info") or ""),
            signer_name=str(request.get("signer_name") or self.server.summary.get("signer_name") or ""),
            signer_id=str(request.get("signer_id") or self.server.summary.get("signer_id") or ""),
            visible_signature=str(request.get("visible_signature") or "true").lower() != "false",
            web_request=False,
        )
        request_path = request_path_for(self.server.exchange_dir, request_id)
        write_record(request_path, request_record)
        try:
            self._mirror_request_to_flipper(request_path)
        except OSError as exc:
            request_path.unlink(missing_ok=True)
            self._send_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": f"No se pudo copiar la solicitud al almacenamiento del Flipper: {exc}"},
            )
            return

        self._send_json(
            HTTPStatus.ACCEPTED,
            {
                "status": "pending_approval",
                "request_id": request_id,
                "request_path": str(request_path),
                "response_path": str(response_path_for(self.server.exchange_dir, request_id)),
                "output_path": str(output_path),
                "pdf_sha256": request_record["pdf_sha256"],
                "alias": self.server.summary["alias"],
            },
        )

    def _handle_web_request_sign_pdf(self) -> None:
        try:
            request = self._read_json_body()
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        if not self._bridge_is_available():
            self._send_json(HTTPStatus.SERVICE_UNAVAILABLE, self._flipper_bridge_error())
            return

        pdf_b64 = request.get("pdf_b64")
        if not isinstance(pdf_b64, str) or not pdf_b64:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "pdf_b64 is required."})
            return

        try:
            pdf_bytes = base64.b64decode(pdf_b64, validate=True)
        except Exception as exc:  # noqa: BLE001
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"pdf_b64 is not valid Base64: {exc}"})
            return

        if not pdf_bytes.startswith(b"%PDF"):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "The uploaded file is not a PDF."})
            return

        request_id = generate_request_id()
        file_name = request.get("file_name") if isinstance(request.get("file_name"), str) else "documento.pdf"
        staged_name = self._safe_stage_filename(file_name, request_id)
        input_path = self.server.web_stage_dir / staged_name
        output_path = self.server.web_stage_dir / f"{Path(staged_name).stem}.signed.pdf"
        input_path.write_bytes(pdf_bytes)

        request_record = self._build_request_record(
            request_id=request_id,
            input_path=input_path,
            output_path=output_path,
            file_name=Path(file_name).name or "documento.pdf",
            field_name="Signature1",
            reason=str(request.get("reason") or ""),
            location=str(request.get("location") or ""),
            contact_info=str(request.get("contact_info") or ""),
            signer_name=str(request.get("signer_name") or self.server.summary.get("signer_name") or ""),
            signer_id=str(request.get("signer_id") or self.server.summary.get("signer_id") or ""),
            visible_signature=request.get("visible_signature") is not False,
            web_request=True,
        )
        request_path = request_path_for(self.server.exchange_dir, request_id)
        write_record(request_path, request_record)
        try:
            self._mirror_request_to_flipper(request_path)
        except OSError as exc:
            request_path.unlink(missing_ok=True)
            input_path.unlink(missing_ok=True)
            output_path.unlink(missing_ok=True)
            self._send_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": f"No se pudo copiar la solicitud al almacenamiento del Flipper: {exc}"},
            )
            return

        self._send_json(
            HTTPStatus.ACCEPTED,
            {
                "status": "pending_approval",
                "request_id": request_id,
                "alias": self.server.summary["alias"],
                "file_name": request_record["file_name"],
                "pdf_sha256": request_record["pdf_sha256"],
                "flipper_bridge_path": self.server.summary.get("flipper_bridge_path", ""),
            },
        )

    def _handle_web_sign_pdf(self) -> None:
        try:
            request = self._read_json_body()
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        pdf_b64 = request.get("pdf_b64")
        if not isinstance(pdf_b64, str) or not pdf_b64:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "pdf_b64 is required."})
            return

        try:
            pdf_bytes = base64.b64decode(pdf_b64, validate=True)
        except Exception as exc:  # noqa: BLE001
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"pdf_b64 is not valid Base64: {exc}"})
            return

        if not pdf_bytes.startswith(b"%PDF"):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "The uploaded file is not a PDF."})
            return

        file_name = request.get("file_name") if isinstance(request.get("file_name"), str) else "documento.pdf"
        reason = request.get("reason") if isinstance(request.get("reason"), str) else None
        location = request.get("location") if isinstance(request.get("location"), str) else None
        contact_info = request.get("contact_info") if isinstance(request.get("contact_info"), str) else None
        signer_name = request.get("signer_name") if isinstance(request.get("signer_name"), str) else None
        signer_id = request.get("signer_id") if isinstance(request.get("signer_id"), str) else None
        visible_signature = request.get("visible_signature") is not False

        try:
            signed_pdf = sign_pdf_bytes(
                pdf_bytes=pdf_bytes,
                metadata=self.server.summary,
                private_key=self.server.private_key,
                certificate=self.server.certificate,
                additional_certificates=self.server.additional_certificates,
                field_name="Signature1",
                reason=reason,
                location=location,
                contact_info=contact_info,
                visible_signature=visible_signature,
                signer_name=signer_name,
                signer_id=signer_id,
            )
        except SystemExit as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        except Exception as exc:  # noqa: BLE001
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"Failed to sign PDF: {exc}"})
            return

        self._send_binary(
            HTTPStatus.OK,
            "application/pdf",
            signed_pdf,
            download_name=self._safe_signed_filename(file_name),
        )

    def _finalize_sign_pdf_request(self, request_id: str) -> None:
        request_path = request_path_for(self.server.exchange_dir, request_id)
        response_path = response_path_for(self.server.exchange_dir, request_id)
        self._sync_response_from_flipper(request_id)
        if not request_path.is_file():
            self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Unknown request_id: {request_id}"})
            return
        if not response_path.is_file():
            self._send_json(HTTPStatus.ACCEPTED, {"status": "pending_approval", "request_id": request_id})
            return

        request_record = read_record(request_path)
        response_record = read_record(response_path)
        if response_record.get("format") != APPROVAL_RESPONSE_FORMAT:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Approval response format is invalid."})
            return
        if response_record.get("request_id") != request_id:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Approval response does not match request_id."})
            return

        decision = response_record.get("decision", "")
        if decision == "rejected":
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"status": "rejected", "request_id": request_id, "decided_at": response_record.get("decided_at", "")},
            )
            return
        if decision != "approved":
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Unsupported decision: {decision}"})
            return

        input_path = Path(request_record["input_path"])
        output_path = Path(request_record["output_path"])
        web_request = request_record.get("web_request") == "true"

        try:
            sign_pdf_file(
                metadata=self.server.summary,
                input_path=input_path,
                output_path=output_path,
                private_key=self.server.private_key,
                certificate=self.server.certificate,
                additional_certificates=self.server.additional_certificates,
                field_name=request_record.get("field_name", "Signature1"),
                reason=request_record.get("reason") or None,
                location=request_record.get("location") or None,
                contact_info=request_record.get("contact_info") or None,
                visible_signature=request_record.get("visible_signature", "true") != "false",
                signer_name=request_record.get("signer_name") or None,
                signer_id=request_record.get("signer_id") or None,
            )

            if web_request:
                signed_bytes = output_path.read_bytes()
                download_name = self._safe_signed_filename(request_record.get("file_name") or output_path.name)
                self._send_binary(HTTPStatus.OK, "application/pdf", signed_bytes, download_name=download_name)
            else:
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "status": "signed",
                        "request_id": request_id,
                        "output_path": str(output_path),
                        "alias": self.server.summary["alias"],
                        "pdf_sha256": request_record.get("pdf_sha256", ""),
                    },
                )
        finally:
            request_path.unlink(missing_ok=True)
            response_path.unlink(missing_ok=True)
            self._cleanup_flipper_exchange(request_id)
            if web_request:
                input_path.unlink(missing_ok=True)
                output_path.unlink(missing_ok=True)

    def _handle_finalize_sign_pdf(self) -> None:
        try:
            request = self._read_json_body()
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        request_id = request.get("request_id")
        if not isinstance(request_id, str) or not request_id:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "request_id is required."})
            return
        self._finalize_sign_pdf_request(request_id)

    def _handle_web_finalize_sign_pdf(self) -> None:
        try:
            request = self._read_json_body()
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        request_id = request.get("request_id")
        if not isinstance(request_id, str) or not request_id:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "request_id is required."})
            return

        request_path = request_path_for(self.server.exchange_dir, request_id)
        if not request_path.is_file():
            self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Unknown request_id: {request_id}"})
            return

        request_record = read_record(request_path)
        if request_record.get("web_request") != "true":
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "request_id is not a web approval flow."})
            return

        self._finalize_sign_pdf_request(request_id)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/":
            self._send_text(HTTPStatus.OK, "text/html; charset=utf-8", self._render_web_ui())
            return

        if parsed.path == "/health":
            self._send_json(
                HTTPStatus.OK,
                {"status": "ok", "exchange_dir": str(self.server.exchange_dir), **self.server.summary},
            )
            return

        if parsed.path == "/info":
            self._send_json(HTTPStatus.OK, {"exchange_dir": str(self.server.exchange_dir), **self.server.summary})
            return

        if parsed.path == "/certificate.pem":
            self._send_text(
                HTTPStatus.OK,
                "application/x-pem-file",
                certificate_to_pem_bytes(self.server.certificate),
            )
            return

        if parsed.path.startswith("/approval-status/"):
            request_id = parsed.path.removeprefix("/approval-status/")
            self._handle_status_route(request_id)
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Unknown route: {parsed.path}"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/web-sign-pdf":
            self._handle_web_sign_pdf()
            return

        if parsed.path == "/web-request-sign-pdf":
            self._handle_web_request_sign_pdf()
            return

        if parsed.path == "/web-finalize-sign-pdf":
            self._handle_web_finalize_sign_pdf()
            return

        if parsed.path == "/request-sign-pdf":
            self._handle_request_sign_pdf()
            return

        if parsed.path == "/finalize-sign-pdf":
            self._handle_finalize_sign_pdf()
            return

        if parsed.path != "/sign":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Unknown route: {parsed.path}"})
            return

        try:
            request = self._read_json_body()
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        data_b64 = request.get("data_b64")
        if not isinstance(data_b64, str) or not data_b64:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Request must include non-empty data_b64."})
            return

        algorithm = request.get("algorithm", "auto")
        if algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Unsupported algorithm: {algorithm}"})
            return

        try:
            payload = base64.b64decode(data_b64, validate=True)
        except Exception as exc:  # noqa: BLE001
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"data_b64 is not valid Base64: {exc}"})
            return

        try:
            signature = sign_bytes(self.server.private_key, payload, algorithm)
            algorithm_used = resolve_signature_algorithm(self.server.private_key, algorithm)
        except SystemExit as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        self._send_json(
            HTTPStatus.OK,
            {
                **self.server.summary,
                "algorithm_used": algorithm_used,
                "signature_b64": base64.b64encode(signature).decode("ascii"),
            },
        )


def main() -> int:
    args = parse_args()
    exchange_dir = args.exchange_dir.resolve()
    ensure_exchange_dirs(exchange_dir)
    flipper_cert_vault_dir = None if args.flipper_usb else resolve_flipper_cert_vault_dir(args.flipper_root)
    flipper_bridge_mode = classify_flipper_bridge_mode(flipper_cert_vault_dir, args.flipper_usb)
    flipper_bridge_active = False
    flipper_bridge_path = ""
    flipper_bridge_error = ""
    flipper_port = args.flipper_port

    if flipper_bridge_mode == "usb":
        flipper_bridge_active, flipper_port, flipper_bridge_error = probe_flipper_usb_bridge(args.flipper_port)
        flipper_bridge_path = f"USB serial storage via {flipper_port}"
    else:
        flipper_bridge_active = flipper_cert_vault_dir is not None
        flipper_bridge_path = "" if flipper_cert_vault_dir is None else str(flipper_cert_vault_dir)
        if flipper_cert_vault_dir is None:
            flipper_bridge_error = (
                "No se ha detectado el almacenamiento del Flipper. Monta la SD del dispositivo "
                "o arranca el servicio con --flipper-usb."
            )

    bundle_metadata, bundle_source = load_bundle_from_flipper_storage(
        args.bundle,
        flipper_bridge_mode=flipper_bridge_mode,
        flipper_cert_vault_dir=flipper_cert_vault_dir,
        flipper_port=flipper_port,
    )
    vault_pin = prompt_secret(args.vault_pin, "Vault PIN/passphrase: ")
    p12_password = None
    if bundle_metadata["bundle_kind"] == "pkcs12":
        p12_password = prompt_secret(args.p12_password, "Original PKCS#12 password: ")

    decrypted_payload = decrypt_bundle(bundle_metadata, vault_pin)
    private_key, certificate, additional_certificates = load_signing_material_with_chain(
        bundle_metadata, decrypted_payload, p12_password
    )
    summary = build_bundle_summary(bundle_metadata, certificate)

    summary["flipper_bridge_active"] = flipper_bridge_active
    summary["flipper_bridge_mode"] = flipper_bridge_mode
    summary["flipper_bridge_path"] = flipper_bridge_path
    summary["flipper_bridge_error"] = flipper_bridge_error
    summary["bundle_source"] = bundle_source

    server = Fvp12SignService(
        (args.host, args.port),
        Fvp12RequestHandler,
        summary,
        private_key,
        certificate,
        additional_certificates,
        exchange_dir,
        flipper_cert_vault_dir,
        flipper_bridge_mode,
        flipper_port,
    )
    print(f"FVP12 sign service listening on http://{args.host}:{args.port}")
    print(
        "Routes: GET /, GET /health, GET /info, GET /certificate.pem, GET /approval-status/<id>, POST /sign, POST /web-sign-pdf, POST /web-request-sign-pdf, POST /web-finalize-sign-pdf, POST /request-sign-pdf, POST /finalize-sign-pdf"
    )
    print(f"Exchange dir: {exchange_dir}")
    print(f"Bundle alias: {summary['alias']}")
    print(f"Bundle source: {bundle_source}")
    if flipper_bridge_mode == "usb":
        if flipper_bridge_active:
            print(f"Flipper bridge: USB serial storage via {flipper_port}")
        else:
            print(f"Flipper bridge: USB unavailable ({flipper_bridge_error})")
    elif flipper_cert_vault_dir is None:
        print("Flipper bridge: not detected. Mount the Flipper SD or restart with --flipper-root <path> or --flipper-usb.")
    elif flipper_bridge_mode == "simulated":
        print(f"Flipper bridge: SIMULATED at {flipper_cert_vault_dir}")
    else:
        print(f"Flipper bridge: {flipper_cert_vault_dir}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping FVP12 sign service.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
