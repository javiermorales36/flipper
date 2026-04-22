from __future__ import annotations

import base64
import json
from pathlib import Path
import re

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import Encoding, load_der_private_key
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography.x509 import load_der_x509_certificate
from cryptography.x509.oid import NameOID

PBKDF2_ITERATIONS = 200_000
SUPPORTED_SIGNATURE_ALGORITHMS = {"auto", "rsa-pkcs1v15", "rsa-pss", "ecdsa"}


def derive_key(vault_pin: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(vault_pin.encode("utf-8"))


def read_bundle_text(bundle_text: str) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for raw_line in bundle_text.splitlines():
        line = raw_line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        metadata[key] = value

    required_keys = {
        "format",
        "bundle_kind",
        "alias",
        "salt_hex",
        "nonce_hex",
        "aad",
    }
    missing = sorted(required_keys.difference(metadata))
    if missing:
        raise SystemExit(f"Bundle is missing required fields: {', '.join(missing)}")

    if metadata["format"] != "FVP12-1":
        raise SystemExit(
            f"Unsupported bundle format: format={metadata['format']} bundle_kind={metadata['bundle_kind']}"
        )

    if metadata["bundle_kind"] not in {"pkcs12", "vault_keyset"}:
        raise SystemExit(f"Unsupported bundle kind: {metadata['bundle_kind']}")

    if metadata["bundle_kind"] == "pkcs12" and "wrapped_p12_b64" not in metadata:
        raise SystemExit("Legacy pkcs12 bundle is missing wrapped_p12_b64.")
    if metadata["bundle_kind"] == "vault_keyset" and "wrapped_keyset_b64" not in metadata:
        raise SystemExit("Vault keyset bundle is missing wrapped_keyset_b64.")

    return metadata


def read_bundle(bundle_path: Path) -> dict[str, str]:
    if not bundle_path.is_file():
        raise SystemExit(f"Bundle file not found: {bundle_path}")

    return read_bundle_text(bundle_path.read_text(encoding="utf-8"))


def decrypt_bundle(metadata: dict[str, str], vault_pin: str) -> bytes:
    iterations = int(metadata.get("iterations", str(PBKDF2_ITERATIONS)))
    salt = bytes.fromhex(metadata["salt_hex"])
    nonce = bytes.fromhex(metadata["nonce_hex"])
    aad = metadata["aad"].encode("utf-8")
    wrapped_payload_key = (
        "wrapped_keyset_b64" if metadata["bundle_kind"] == "vault_keyset" else "wrapped_p12_b64"
    )
    wrapped_payload = base64.b64decode(metadata[wrapped_payload_key])
    key = derive_key(vault_pin, salt, iterations)
    return AESGCM(key).decrypt(nonce, wrapped_payload, aad)


def load_signing_material_with_chain(
    metadata: dict[str, str], decrypted_payload: bytes, p12_password: str | None
):
    if metadata["bundle_kind"] == "pkcs12":
        try:
            private_key, certificate, additional_certificates = load_key_and_certificates(
                decrypted_payload, p12_password.encode("utf-8") if p12_password else None
            )
        except Exception as exc:  # noqa: BLE001
            raise SystemExit(f"Failed to open decrypted PKCS#12 payload: {exc}") from exc

        if private_key is None or certificate is None:
            raise SystemExit("The bundle did not yield both a private key and a certificate.")

        return private_key, certificate, list(additional_certificates or [])

    try:
        keyset = json.loads(decrypted_payload.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"Failed to decode decrypted vault keyset: {exc}") from exc

    try:
        private_key = load_der_private_key(
            base64.b64decode(keyset["private_key_der_b64"]), password=None
        )
        certificate = load_der_x509_certificate(base64.b64decode(keyset["certificate_der_b64"]))
        additional_certificates = [
            load_der_x509_certificate(base64.b64decode(encoded_certificate))
            for encoded_certificate in keyset.get("chain_der_b64", [])
        ]
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"Failed to load signing material from keyset: {exc}") from exc

    return private_key, certificate, additional_certificates


def load_signing_material(
    metadata: dict[str, str], decrypted_payload: bytes, p12_password: str | None
):
    private_key, certificate, _ = load_signing_material_with_chain(
        metadata, decrypted_payload, p12_password
    )
    return private_key, certificate


def resolve_signature_algorithm(private_key, algorithm: str) -> str:
    if algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
        raise SystemExit(f"Unsupported signature algorithm: {algorithm}")

    if isinstance(private_key, rsa.RSAPrivateKey):
        selected_algorithm = algorithm if algorithm != "auto" else "rsa-pkcs1v15"
        if selected_algorithm in {"rsa-pkcs1v15", "rsa-pss"}:
            return selected_algorithm
        raise SystemExit(f"Algorithm '{algorithm}' is not compatible with an RSA private key.")

    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        selected_algorithm = algorithm if algorithm != "auto" else "ecdsa"
        if selected_algorithm == "ecdsa":
            return selected_algorithm
        raise SystemExit(f"Algorithm '{algorithm}' is not compatible with an EC private key.")

    raise SystemExit(f"Unsupported private key type: {private_key.__class__.__name__}")


def sign_bytes(private_key, payload: bytes, algorithm: str) -> bytes:
    selected_algorithm = resolve_signature_algorithm(private_key, algorithm)

    if selected_algorithm == "rsa-pkcs1v15":
        return private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    if selected_algorithm == "rsa-pss":
        return private_key.sign(
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    if selected_algorithm == "ecdsa":
        return private_key.sign(payload, ec.ECDSA(hashes.SHA256()))

    raise SystemExit(f"Unsupported signature algorithm: {selected_algorithm}")


def certificate_to_pem_bytes(certificate) -> bytes:
    return certificate.public_bytes(Encoding.PEM)


def certificate_subject_value(certificate, oid) -> str:
    attributes = certificate.subject.get_attributes_for_oid(oid)
    if not attributes:
        return ""
    return str(attributes[0].value)


def derive_signer_identity(metadata: dict[str, str], certificate) -> dict[str, str]:
    common_name = metadata.get("common_name") or certificate_subject_value(certificate, NameOID.COMMON_NAME)
    given_name = certificate_subject_value(certificate, NameOID.GIVEN_NAME)
    surname = certificate_subject_value(certificate, NameOID.SURNAME)
    serial_number = certificate_subject_value(certificate, NameOID.SERIAL_NUMBER)

    signer_name = " ".join(part for part in (given_name, surname) if part).strip()
    if not signer_name:
        signer_name = common_name

    if signer_name:
        signer_name = re.sub(r"\s*-\s*(?:NIF|DNI)\s*:\s*[^,]+$", "", signer_name, flags=re.IGNORECASE).strip()

    if not serial_number and common_name:
        match = re.search(r"(?:NIF|DNI)\s*:?\s*([0-9A-Z-]+)", common_name, flags=re.IGNORECASE)
        if match:
            serial_number = match.group(1).upper()

    return {
        "signer_name": signer_name or common_name or metadata.get("alias", ""),
        "signer_id": serial_number,
    }


def public_key_summary(certificate) -> str:
    public_key = certificate.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return f"RSA-{public_key.key_size}"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return public_key.curve.name
    return public_key.__class__.__name__


def build_bundle_summary(metadata: dict[str, str], certificate) -> dict[str, str]:
    identity = derive_signer_identity(metadata, certificate)
    return {
        "alias": metadata["alias"],
        "subject": metadata.get("subject", ""),
        "bundle_kind": metadata["bundle_kind"],
        "serial": metadata.get("serial", ""),
        "key_type": metadata.get("key_type", ""),
        "common_name": metadata.get("common_name", ""),
        "cert_sha1": metadata.get("cert_sha1", ""),
        "public_key": public_key_summary(certificate),
        "signer_name": identity["signer_name"],
        "signer_id": identity["signer_id"],
    }