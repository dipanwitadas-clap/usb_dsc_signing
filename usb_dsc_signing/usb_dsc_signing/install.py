"""Installation hooks for USB DSC Signing app."""


def after_install():
	"""Run after the app is installed on a site.

	Creates the default DSC Settings record if it doesn't exist.
	"""
	_create_default_settings()


def _create_default_settings():
	"""Create the DSC Settings single doc if not already present."""
	import frappe

	if not frappe.db.exists("DSC Settings", "DSC Settings"):
		settings = frappe.new_doc("DSC Settings")
		settings.title = "DSC Settings"
		settings.helper_url = "https://127.0.0.1:39999"
		settings.enabled = 1
		settings.request_timeout = 30
		settings.signature_reason = "Digitally Signed"
		settings.signature_location = "India"
		settings.signature_box_page = 1
		settings.signature_box_x = 0
		settings.signature_box_y = 0
		settings.signature_box_width = 320
		settings.signature_box_height = 50
		settings.enable_debug_logging = 0
		settings.max_log_days = 30
		settings.insert(ignore_permissions=True)
		frappe.db.commit()