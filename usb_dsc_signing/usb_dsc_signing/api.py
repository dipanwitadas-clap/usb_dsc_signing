"""Whitelisted API endpoints for USB DSC Signing.

All methods are called from the browser (client-side JavaScript).
The DSC helper is never called directly from the server — all helper
communication happens from the user's browser via HTTPS to localhost.

Signing is split across two calls (see signing.py for why):
    1. prepare_for_signing — build the CMS-to-be-signed digest.
    2. complete_signing    — embed the real signature once the browser
       has it back from the helper's POST /sign.
"""

from __future__ import annotations

import json
import logging

import frappe
from frappe import _

from .signing import (
    SigningStateError,
    begin_signature,
    complete_signature,
    create_session,
    get_document_pdf,
    load_and_consume_session,
    log_signing_event,
    save_signed_pdf_to_file,
    SignatureBoxSpec,
)

logger = logging.getLogger(__name__)


def _check_doctype_allowed(doctype: str, docname: str, settings) -> None:
    if not frappe.has_permission(doctype, "read", doc=docname):
        frappe.throw(_("You do not have permission to read this document."), frappe.PermissionError)

    if not settings.enabled:
        frappe.throw(_("DSC signing is currently disabled. Contact your administrator."))

    allowed = {row.doc_type for row in settings.allowed_doctypes}
    if doctype not in allowed:
        frappe.throw(_("DSC signing is not enabled for {0}.").format(doctype))


def _coerce_list(value) -> list:
    """frappe.call may deliver a JS array as a JSON string or a native list."""
    if not value:
        return []
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return [value]
    return list(value) if isinstance(value, (list, tuple)) else [value]


@frappe.whitelist()
def prepare_for_signing(
    doctype: str,
    docname: str,
    certificate_pem: str,
    certificate_serial: str | None = None,
    chain_pem: str | list | None = None,
) -> dict:
    """Phase 1: build the CMS-to-be-signed structure for the selected certificate.

    The browser must call this *after* the user has picked a certificate
    from the helper's GET /info or GET /certificates response, since a valid
    PAdES signature embeds a hash of the signing certificate itself — the
    certificate has to be known before we can compute the digest that needs
    signing.

    Args:
        doctype: Source DocType (e.g., "Sales Invoice").
        docname: Source document name.
        certificate_pem: PEM of the certificate the user selected (from the
            helper's certificate list).
        certificate_serial: The certificate's serial_number, for consistency
            checks against the /sign response later.
        chain_pem: Optional list of intermediate/root certificate PEMs, from
            the same certificate entry.

    Returns:
        dict with keys:
            - session_id: opaque token to pass to complete_signing.
            - tbs_hash_hex: hex SHA-256 digest to send to the helper's /sign.
            - hash_algorithm: "SHA-256" — matches the helper's SignRequest enum.
            - document_name: Human-readable name for the UI.
    """
    settings = frappe.get_cached_doc("DSC Settings")
    _check_doctype_allowed(doctype, docname, settings)

    chain_pem_list = _coerce_list(chain_pem)

    try:
        pdf_bytes = get_document_pdf(doctype, docname)
        result = begin_signature(
            pdf_bytes=pdf_bytes,
            certificate_pem=certificate_pem,
            chain_pem=chain_pem_list,
            reason=settings.signature_reason,
            location=settings.signature_location,
            contact_info=None,
            box=SignatureBoxSpec(
                page=settings.signature_box_page - 1,  # 0-based
                x=settings.signature_box_x,
                y=settings.signature_box_y,
                width=settings.signature_box_width,
                height=settings.signature_box_height,
            ),
        )
    except frappe.exceptions.ValidationError:
        raise
    except Exception as exc:
        logger.error("Failed to prepare PDF for signing: %s", exc)
        log_signing_event(doctype, docname, "pdf_generation_failed", details=str(exc))
        frappe.log_error(title="DSC: PDF Preparation Failed", message=frappe.get_traceback())
        frappe.throw(
            _("Could not prepare PDF for signing. Please check the error log."),
            title=_("Preparation Error"),
        )

    session_id = create_session(
        doctype=doctype,
        docname=docname,
        cert_serial=certificate_serial,
        state=result["_state"],
    )

    log_signing_event(
        doctype, docname, "pdf_generated",
        signed_by=result["signed_by"],
        details=json.dumps({"tbs_hash": result["tbs_hash_hex"]}),
    )

    return {
        "session_id": session_id,
        "tbs_hash_hex": result["tbs_hash_hex"],
        "hash_algorithm": "SHA-256",
        "document_name": f"{doctype}: {docname}",
    }


@frappe.whitelist()
def complete_signing(
    session_id: str,
    signature_hex: str,
    cert_serial: str | None = None,
) -> dict:
    """Phase 2: embed the real signature returned by the helper's POST /sign.

    Args:
        session_id: Token returned by prepare_for_signing.
        signature_hex: signature_hex from the helper's SignResponse.
        cert_serial: cert_serial from the helper's SignResponse — checked
            against the certificate used in phase 1 to catch mismatches.

    Returns:
        dict with keys:
            - file_url: URL to the signed PDF.
            - signed_by: Certificate Common Name.
            - signed_on: ISO datetime string.
    """
    from datetime import datetime, timezone

    try:
        session = load_and_consume_session(session_id, cert_serial=cert_serial)
    except SigningStateError as exc:
        frappe.throw(str(exc), title=_("Signing Session Error"))

    doctype = session["doctype"]
    docname = session["docname"]

    try:
        signed_pdf_bytes = complete_signature(session["state"], signature_hex)
        file_url = save_signed_pdf_to_file(
            doctype=doctype,
            docname=docname,
            pdf_bytes=signed_pdf_bytes,
            signed_by=session["state"].get("signed_by", "Unknown"),
        )
        signed_on = datetime.now(timezone.utc).isoformat()

        log_signing_event(
            doctype, docname, "signed",
            signed_by=session["state"].get("signed_by", "Unknown"),
            details=json.dumps({"file_url": file_url}),
        )

        return {
            "file_url": file_url,
            "signed_by": session["state"].get("signed_by", "Unknown"),
            "signed_on": signed_on,
        }

    except frappe.exceptions.ValidationError:
        raise
    except Exception as exc:
        logger.error("Failed to embed signature: %s", exc)
        log_signing_event(doctype, docname, "embed_failed", details=str(exc))
        frappe.log_error(title="DSC: Signature Embedding Failed", message=frappe.get_traceback())
        frappe.throw(
            _("Could not embed the digital signature. Please check the error log."),
            title=_("Signing Error"),
        )


@frappe.whitelist()
def get_dsc_settings() -> dict:
    """Return DSC Settings for the frontend."""
    from .doctype.dsc_settings.dsc_settings import get_dsc_settings as _get

    return _get()
