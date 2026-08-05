"""Core digital signing logic: PAdES signature embedding via pyHanko.

The ERPNext server can never reach the DSC helper — it only listens on
``127.0.0.1`` on the *user's* machine, not the server's. So the signing
operation is split into two requests, separated by a browser round-trip to
the helper's ``POST /sign``:

    Phase 1 — :func:`begin_signature`
        Build the PDF's to-be-signed CMS structure using the certificate the
        user selected in the browser. Returns the SHA-256 digest of the
        DER-encoded CMS *signed attributes* — this, not a hash of the raw
        PDF, is what the helper must actually sign. Also returns an opaque,
        short-lived session that carries everything needed to finish the
        job later.

    Phase 2 — :func:`complete_signature`
        Take the raw signature bytes the browser got back from the helper,
        reassemble the CMS ``SignedData`` structure with the real signature,
        and embed it into the PDF via an incremental update.

A signature built this way is a real CMS/CAdES structure (PAdES-BES) that
validates in Adobe Reader and other PAdES validators — unlike naively
hashing the whole PDF and dropping a raw RSA signature into it, which does
not produce a structurally valid PDF signature at all.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import frappe

logger = frappe.logger("usb_dsc_signing", allow_site=True)

SESSION_CACHE_PREFIX = "usb_dsc_signing:session:"
SESSION_TTL_SECONDS = 900  # 15 minutes — enough for token insertion + PIN entry
DIGEST_ALGORITHM = "sha256"  # matches the fixed 'SHA-256' used by helper_client.js

_PEM_CERT_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL
)


class SigningStateError(Exception):
    """Raised when a signing session is missing, expired, or invalid."""


def get_document_pdf(doctype: str, docname: str, print_format: str | None = None) -> bytes:
    """Render the PDF for a given ERPNext document via the configured print format."""
    html = frappe.get_print(doctype, docname, print_format=print_format or "Standard")
    pdf_bytes = frappe.utils.pdf.get_pdf(html)

    if not pdf_bytes:
        frappe.throw(
            frappe._("Could not generate PDF for {0} {1}").format(doctype, docname)
        )

    return pdf_bytes


# ---------------------------------------------------------------------------
# Certificate parsing helpers
# ---------------------------------------------------------------------------


def _parse_pem_certificates(pem_text: str) -> list:
    """Extract every X.509 certificate block from a PEM string.

    Tolerant of a single cert, or several concatenated in one string, since
    the helper's ``chain_pem`` is an array and we don't want to assume each
    array element contains exactly one ``BEGIN CERTIFICATE`` block.
    """
    from cryptography import x509 as crypto_x509

    blocks = _PEM_CERT_RE.findall(pem_text.encode("ascii"))
    if not blocks:
        return []
    return [crypto_x509.load_pem_x509_certificate(block) for block in blocks]


def _to_asn1_cert(cryptography_cert):
    """Convert a `cryptography` Certificate to the asn1crypto form pyHanko wants."""
    from asn1crypto import x509 as asn1_x509
    from cryptography.hazmat.primitives.serialization import Encoding

    return asn1_x509.Certificate.load(cryptography_cert.public_bytes(Encoding.DER))


def _extract_common_name(cryptography_cert) -> str:
    """Best-effort extraction of the certificate subject's Common Name.

    Falls back to the full subject DN (RFC 4514 form) if no CN attribute is
    present — some DSC certificates omit it in favour of organisation/serial
    attributes only.
    """
    from cryptography.x509.oid import NameOID

    cn_attrs = cryptography_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        return cn_attrs[0].value
    return cryptography_cert.subject.rfc4514_string()


# ---------------------------------------------------------------------------
# Phase 1 — prepare the to-be-signed digest
# ---------------------------------------------------------------------------


@dataclass
class SignatureBoxSpec:
    page: int  # 0-based
    x: int
    y: int
    width: int
    height: int


def begin_signature(
    *,
    pdf_bytes: bytes,
    certificate_pem: str,
    chain_pem: list[str] | None,
    reason: str | None,
    location: str | None,
    contact_info: str | None,
    box: SignatureBoxSpec,
) -> dict[str, Any]:
    """Phase 1: build the CMS-to-be-signed structure and the digest to sign.

    Returns a dict with:
        - ``tbs_hash_hex``: hex SHA-256 digest of the DER-encoded CMS signed
          attributes. This is what must be sent to the helper's ``/sign``.
        - ``signed_by``: Common Name extracted from the certificate, for
          display/audit purposes (derived server-side from the actual
          certificate, not trusted client metadata).
        - ``_state``: opaque dict to be handed back unmodified to
          :func:`complete_signature` (via the session cache).

    Raises:
        frappe.ValidationError: if the certificate PEM is missing/invalid.
    """
    import asyncio
    import io

    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import fields
    from pyhanko.sign.signers.pdf_cms import ExternalSigner
    from pyhanko.sign.signers.pdf_signer import PdfSignatureMetadata, PdfSigner
    from pyhanko_certvalidator.registry import SimpleCertificateStore

    if not certificate_pem:
        frappe.throw(
            frappe._(
                "The DSC helper did not return certificate data (PEM) for the "
                "selected certificate. Cannot prepare a signature without it."
            )
        )

    leaf_certs = _parse_pem_certificates(certificate_pem)
    if not leaf_certs:
        frappe.throw(frappe._("Could not parse the signing certificate (PEM)."))
    leaf_cert = leaf_certs[0]
    asn1_leaf = _to_asn1_cert(leaf_cert)

    registry = SimpleCertificateStore()
    registry.register(asn1_leaf)
    chain_der: list[bytes] = []
    for chain_entry in chain_pem or []:
        for chain_cert in _parse_pem_certificates(chain_entry):
            asn1_chain_cert = _to_asn1_cert(chain_cert)
            registry.register(asn1_chain_cert)
            chain_der.append(asn1_chain_cert.dump())

    prelim_signer = ExternalSigner(
        signing_cert=asn1_leaf,
        cert_registry=registry,
        signature_value=None,  # placeholder only — used for size estimation
    )

    sig_field = fields.SigFieldSpec(
        sig_field_name="DSCSignature",
        on_page=box.page,
        box=(box.x, box.y, box.x + box.width, box.y + box.height),
    )
    sig_meta = PdfSignatureMetadata(
        field_name="DSCSignature",
        md_algorithm=DIGEST_ALGORITHM,
        reason=reason or None,
        location=location or None,
        contact_info=contact_info or None,
        subfilter=fields.SigSeedSubFilter.PADES,
    )
    pdf_signer = PdfSigner(sig_meta, signer=prelim_signer, new_field_spec=sig_field)

    writer = IncrementalPdfFileWriter(io.BytesIO(pdf_bytes))

    try:
        prepared_br_digest, _tbs_document, out_stream = asyncio.run(
            pdf_signer.async_digest_doc_for_signing(writer)
        )
        signed_attrs = asyncio.run(
            prelim_signer.signed_attrs(
                prepared_br_digest.document_digest,
                DIGEST_ALGORITHM,
                use_pades=True,
                dry_run=False,
            )
        )
    except Exception as exc:
        logger.error("Failed to prepare PDF for signing: %s", exc)
        raise

    signed_attrs_der = signed_attrs.dump()
    tbs_hash_hex = _sha256_hex(signed_attrs_der)

    signed_by = _extract_common_name(leaf_cert)
    state = {
        "intermediate_pdf": out_stream.getvalue(),
        "document_digest": prepared_br_digest.document_digest,
        "region_start": prepared_br_digest.reserved_region_start,
        "region_end": prepared_br_digest.reserved_region_end,
        "signed_attrs_der": signed_attrs_der,
        "cert_der": asn1_leaf.dump(),
        "chain_der": chain_der,
        "digest_algorithm": DIGEST_ALGORITHM,
        "signed_by": signed_by,
    }

    return {
        "tbs_hash_hex": tbs_hash_hex,
        "signed_by": signed_by,
        "_state": state,
    }


def _sha256_hex(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Phase 2 — embed the real signature
# ---------------------------------------------------------------------------


def complete_signature(state: dict[str, Any], signature_hex: str) -> bytes:
    """Phase 2: reassemble the CMS SignedData with the real signature.

    Args:
        state: the ``_state`` dict returned by :func:`begin_signature`
            (round-tripped through the session cache).
        signature_hex: raw signature bytes (hex) returned by the helper's
            ``POST /sign`` — a raw RSA signature over the exact digest of
            ``state["signed_attrs_der"]`` that was requested in phase 1.

    Returns:
        The final, signed PDF bytes.
    """
    import asyncio
    import io

    from asn1crypto import cms, x509 as asn1_x509
    from pyhanko.sign.signers.pdf_byterange import PreparedByteRangeDigest
    from pyhanko.sign.signers.pdf_cms import ExternalSigner
    from pyhanko.sign.signers.pdf_signer import PdfTBSDocument
    from pyhanko_certvalidator.registry import SimpleCertificateStore

    try:
        signature_bytes = bytes.fromhex(signature_hex)
    except ValueError as exc:
        frappe.throw(frappe._("Invalid signature hex received: {0}").format(str(exc)))

    asn1_leaf = asn1_x509.Certificate.load(state["cert_der"])
    registry = SimpleCertificateStore()
    registry.register(asn1_leaf)
    for chain_cert_der in state.get("chain_der") or []:
        registry.register(asn1_x509.Certificate.load(chain_cert_der))

    final_signer = ExternalSigner(
        signing_cert=asn1_leaf,
        cert_registry=registry,
        signature_value=signature_bytes,
    )

    signed_attrs = cms.CMSAttributes.load(state["signed_attrs_der"])
    if signed_attrs.dump() != state["signed_attrs_der"]:
        # Should never happen — asn1crypto DER round-trips deterministically —
        # but if it did, the embedded signature would silently not match the
        # signed attributes, producing an invalid signature. Fail loudly.
        raise SigningStateError("Signed attributes did not round-trip through DER.")

    content_info = asyncio.run(
        final_signer.async_sign_prescribed_attributes(
            state["digest_algorithm"],
            signed_attrs,
            cms_version="v1",
            dry_run=False,
        )
    )

    prepared_digest = PreparedByteRangeDigest(
        document_digest=state["document_digest"],
        reserved_region_start=state["region_start"],
        reserved_region_end=state["region_end"],
    )

    output = io.BytesIO(state["intermediate_pdf"])
    asyncio.run(
        PdfTBSDocument.async_finish_signing(
            output,
            prepared_digest=prepared_digest,
            signature_cms=content_info,
        )
    )
    return output.getvalue()


# ---------------------------------------------------------------------------
# Session store — bridges the two-request signing flow via Redis cache
# ---------------------------------------------------------------------------


def create_session(*, doctype: str, docname: str, cert_serial: str | None, state: dict) -> str:
    """Persist phase-1 state and return an opaque, single-use session id."""
    session_id = secrets.token_urlsafe(32)
    payload = {
        "user": frappe.session.user,
        "doctype": doctype,
        "docname": docname,
        "cert_serial": cert_serial,
        "created": datetime.now(timezone.utc).isoformat(),
        "state": state,
    }
    frappe.cache().set_value(
        SESSION_CACHE_PREFIX + session_id, payload, expires_in_sec=SESSION_TTL_SECONDS
    )
    return session_id


def load_and_consume_session(session_id: str, *, cert_serial: str | None = None) -> dict:
    """Fetch a signing session, enforcing ownership and single use.

    Deletes the session immediately (single-use, whether this call succeeds
    or the caller fails afterwards) to prevent replay.
    """
    cache_key = SESSION_CACHE_PREFIX + session_id
    payload = frappe.cache().get_value(cache_key)
    frappe.cache().delete_value(cache_key)

    if not payload:
        raise SigningStateError(
            frappe._("Signing session not found or expired. Please try again.")
        )
    if payload["user"] != frappe.session.user:
        raise SigningStateError(
            frappe._("This signing session does not belong to the current user.")
        )
    if (
        cert_serial
        and payload.get("cert_serial")
        and cert_serial != payload["cert_serial"]
    ):
        raise SigningStateError(
            frappe._(
                "Certificate mismatch between signing steps. Please restart "
                "the signing process."
            )
        )
    return payload


def save_signed_pdf_to_file(
    doctype: str,
    docname: str,
    pdf_bytes: bytes,
    signed_by: str,
) -> str:
    """Save the signed PDF as a Frappe File document and return its URL."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_docname = docname.replace("/", "_").replace(" ", "_")
    filename = f"SIGNED_{doctype}_{safe_docname}_{timestamp}.pdf"

    file_doc = frappe.get_doc({
        "doctype": "File",
        "file_name": filename,
        "content": pdf_bytes,
        "is_private": 1,
        "attached_to_doctype": doctype,
        "attached_to_name": docname,
        "file_size": len(pdf_bytes),
        "folder": "Home/Attachments",
    })
    file_doc.insert(ignore_permissions=False)
    frappe.db.commit()

    return file_doc.file_url


@frappe.whitelist()
def log_signing_event(
    doctype: str,
    docname: str,
    event: str,
    signed_by: str | None = None,
    details: str | None = None,
):
    """Log a DSC signing event for audit purposes, if debug logging is enabled."""
    settings = frappe.get_cached_doc("DSC Settings")
    if not settings.enable_debug_logging:
        return

    log = frappe.get_doc({
        "doctype": "DSC Signing Log",
        "reference_doctype": doctype,
        "reference_docname": docname,
        "event": event,
        "signed_by": signed_by or "",
        "user": frappe.session.user,
        "details": details or "",
    })
    log.insert(ignore_permissions=True)
