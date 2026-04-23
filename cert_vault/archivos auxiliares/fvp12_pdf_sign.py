from __future__ import annotations

import argparse
import getpass
from io import BytesIO
from pathlib import Path

from asn1crypto import keys as asn1_keys, x509 as asn1_x509
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.text import TextBoxStyle
from pyhanko.sign import signers
from pyhanko.sign import fields
from pyhanko.stamp import TextStampStyle
from pyhanko_certvalidator.registry import SimpleCertificateStore
from PyPDF2 import PdfReader

from fvp12_core import (
    decrypt_bundle,
    derive_signer_identity,
    load_signing_material_with_chain,
    read_bundle,
)

VISIBLE_BOX_WIDTH = 185
VISIBLE_BOX_HEIGHT = 118
VISIBLE_BOX_MARGIN = 18


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Digitally sign a PDF using a Flipper vault bundle (.fvp12)."
    )
    parser.add_argument("bundle", type=Path, help="Path to the .fvp12 bundle")
    parser.add_argument("input", type=Path, help="Path to the source PDF")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output path for the signed PDF. Defaults to <input>.signed.pdf",
    )
    parser.add_argument(
        "--vault-pin", help="Vault PIN/passphrase used when the .fvp12 bundle was generated"
    )
    parser.add_argument(
        "--p12-password",
        help="Original PKCS#12 password. Only needed for legacy pkcs12-based bundles.",
    )
    parser.add_argument(
        "--field-name",
        default="Signature1",
        help="PDF signature field name. Defaults to Signature1.",
    )
    parser.add_argument("--reason", help="Optional signing reason to embed in the PDF")
    parser.add_argument("--location", help="Optional signing location to embed in the PDF")
    parser.add_argument(
        "--contact-info", help="Optional contact information to embed in the PDF signature"
    )
    parser.add_argument(
        "--visible-signature",
        action="store_true",
        help="Add a visible signature stamp on the right side of the first PDF page.",
    )
    parser.add_argument(
        "--signer-name",
        help="Override the signer name shown in the visible signature stamp.",
    )
    parser.add_argument(
        "--signer-id",
        help="Override the DNI/NIF shown in the visible signature stamp.",
    )
    return parser.parse_args()


def prompt_secret(value: str | None, prompt: str) -> str:
    if value is not None:
        return value
    return getpass.getpass(prompt)


def default_output_path(input_path: Path) -> Path:
    if input_path.suffix.lower() == ".pdf":
        return input_path.with_name(f"{input_path.stem}.signed.pdf")
    return input_path.with_suffix(input_path.suffix + ".signed.pdf")


def build_pdf_signer(private_key, certificate, additional_certificates):
    signing_cert = asn1_x509.Certificate.load(certificate.public_bytes(Encoding.DER))
    signing_key = asn1_keys.PrivateKeyInfo.load(
        private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    )

    certificate_store = SimpleCertificateStore()
    for chain_certificate in additional_certificates:
        certificate_store.register(
            asn1_x509.Certificate.load(chain_certificate.public_bytes(Encoding.DER))
        )

    return signers.SimpleSigner(
        signing_cert=signing_cert,
        signing_key=signing_key,
        cert_registry=certificate_store,
    )


def build_visible_stamp_style() -> TextStampStyle:
    return TextStampStyle(
        border_width=1,
        border_color=(0.10, 0.31, 0.39),
        text_box_style=TextBoxStyle(
            font_size=9,
            leading=12,
            text_color=(0.11, 0.16, 0.20),
        ),
        stamp_text=(
            "Firmado digitalmente\n"
            "por: %(signer_name)s\n"
            "DNI/NIF: %(signer_id)s\n"
            "Fecha: %(ts)s%(reason_line)s"
        ),
    )


def compute_visible_signature_box(pdf_bytes: bytes) -> tuple[int, int, int, int]:
    reader = PdfReader(BytesIO(pdf_bytes))
    first_page = reader.pages[0]
    page_width = int(float(first_page.mediabox.right) - float(first_page.mediabox.left))
    page_height = int(float(first_page.mediabox.top) - float(first_page.mediabox.bottom))

    box_width = min(VISIBLE_BOX_WIDTH, max(150, page_width // 3))
    box_height = min(VISIBLE_BOX_HEIGHT, max(96, page_height // 5))
    x2 = max(box_width + VISIBLE_BOX_MARGIN, page_width - VISIBLE_BOX_MARGIN)
    x1 = x2 - box_width
    y1 = max(VISIBLE_BOX_MARGIN, (page_height - box_height) // 2)
    y2 = y1 + box_height
    return (x1, y1, x2, y2)


def build_visible_stamp_params(
    metadata: dict[str, str],
    certificate,
    signer_name: str | None,
    signer_id: str | None,
    reason: str | None,
) -> dict[str, str]:
    identity = derive_signer_identity(metadata, certificate)
    final_signer_name = (signer_name or identity["signer_name"] or metadata.get("alias", "")).strip()
    final_signer_id = (signer_id or identity["signer_id"] or "N/D").strip()
    reason_line = f"\nMotivo: {reason}" if reason else ""
    return {
        "signer_name": final_signer_name,
        "signer_id": final_signer_id,
        "reason_line": reason_line,
    }


def sign_pdf_bytes(
    pdf_bytes: bytes,
    metadata: dict[str, str],
    private_key,
    certificate,
    additional_certificates,
    field_name: str,
    reason: str | None,
    location: str | None,
    contact_info: str | None,
    visible_signature: bool = False,
    signer_name: str | None = None,
    signer_id: str | None = None,
) -> bytes:
    stamp_style = None
    new_field_spec = None
    appearance_text_params = None

    if visible_signature:
        stamp_style = build_visible_stamp_style()
        new_field_spec = fields.SigFieldSpec(
            sig_field_name=field_name,
            on_page=0,
            box=compute_visible_signature_box(pdf_bytes),
        )
        appearance_text_params = build_visible_stamp_params(
            metadata,
            certificate,
            signer_name=signer_name,
            signer_id=signer_id,
            reason=reason,
        )

    pdf_signer = signers.PdfSigner(
        signers.PdfSignatureMetadata(
            field_name=field_name,
            reason=reason,
            location=location,
            contact_info=contact_info,
        ),
        signer=build_pdf_signer(private_key, certificate, additional_certificates),
        stamp_style=stamp_style,
        new_field_spec=new_field_spec,
    )

    input_stream = BytesIO(pdf_bytes)
    output_stream = BytesIO()
    pdf_writer = IncrementalPdfFileWriter(input_stream)
    pdf_signer.sign_pdf(
        pdf_writer,
        output=output_stream,
        appearance_text_params=appearance_text_params,
    )
    return output_stream.getvalue()


def sign_pdf_file(
    metadata: dict[str, str],
    input_path: Path,
    output_path: Path,
    private_key,
    certificate,
    additional_certificates,
    field_name: str,
    reason: str | None,
    location: str | None,
    contact_info: str | None,
    visible_signature: bool = False,
    signer_name: str | None = None,
    signer_id: str | None = None,
) -> None:
    if not input_path.is_file():
        raise SystemExit(f"Input PDF not found: {input_path}")

    pdf_bytes = input_path.read_bytes()
    signed_pdf = sign_pdf_bytes(
        pdf_bytes=pdf_bytes,
        metadata=metadata,
        private_key=private_key,
        certificate=certificate,
        additional_certificates=additional_certificates,
        field_name=field_name,
        reason=reason,
        location=location,
        contact_info=contact_info,
        visible_signature=visible_signature,
        signer_name=signer_name,
        signer_id=signer_id,
    )
    output_path.write_bytes(signed_pdf)


def main() -> int:
    args = parse_args()
    bundle_metadata = read_bundle(args.bundle)
    vault_pin = prompt_secret(args.vault_pin, "Vault PIN/passphrase: ")
    p12_password = None
    if bundle_metadata["bundle_kind"] == "pkcs12":
        p12_password = prompt_secret(args.p12_password, "Original PKCS#12 password: ")

    decrypted_payload = decrypt_bundle(bundle_metadata, vault_pin)
    private_key, certificate, additional_certificates = load_signing_material_with_chain(
        bundle_metadata, decrypted_payload, p12_password
    )

    output_path = args.output or default_output_path(args.input)
    sign_pdf_file(
        metadata=bundle_metadata,
        input_path=args.input,
        output_path=output_path,
        private_key=private_key,
        certificate=certificate,
        additional_certificates=additional_certificates,
        field_name=args.field_name,
        reason=args.reason,
        location=args.location,
        contact_info=args.contact_info,
        visible_signature=args.visible_signature,
        signer_name=args.signer_name,
        signer_id=args.signer_id,
    )

    print(f"Bundle alias: {bundle_metadata['alias']}")
    print(f"Bundle kind: {bundle_metadata['bundle_kind']}")
    print(f"Input PDF: {args.input}")
    print(f"Signed PDF written to: {output_path}")
    print(f"Signature field: {args.field_name}")
    print(f"Visible signature: {'yes' if args.visible_signature else 'no'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())