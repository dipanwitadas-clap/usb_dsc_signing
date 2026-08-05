"""DSC Settings single DocType controller."""

import frappe
from frappe.model.document import Document


class DSCSettings(Document):
	"""Global settings for USB DSC Signing integration."""

	def validate(self):
		"""Validate settings."""
		self._validate_helper_url()

	def _validate_helper_url(self):
		"""Ensure helper URL starts with https://."""
		if not self.helper_url.startswith("https://"):
			frappe.msgprint(
				frappe._("Helper URL should start with https:// for security."),
				alert=True,
				indicator="orange",
			)


@frappe.whitelist()
def get_dsc_settings() -> dict | None:
	"""Return DSC Settings as a dict for frontend consumption.

	Returns None if DSC signing is disabled.
	"""
	settings = frappe.get_cached_doc("DSC Settings")
	return {
		"helper_url": settings.helper_url,
		"enabled": bool(settings.enabled),
		"request_timeout": settings.request_timeout,
		"signature_reason": settings.signature_reason,
		"signature_location": settings.signature_location,
		"signature_box_page": settings.signature_box_page,
		"signature_box_x": settings.signature_box_x,
		"signature_box_y": settings.signature_box_y,
		"signature_box_width": settings.signature_box_width,
		"signature_box_height": settings.signature_box_height,
		"enable_debug_logging": bool(settings.enable_debug_logging),
		"allowed_doctypes": [row.doc_type for row in settings.allowed_doctypes],
	}