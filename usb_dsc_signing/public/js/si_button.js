/**
 * Custom Button Injection — "Digitally Sign PDF"
 *
 * Adds the [Digitally Sign PDF] button to configured doctypes (e.g. Sales
 * Invoice) when the document is submitted (docstatus === 1).
 *
 * The list of allowed doctypes is read from DSC Settings.
 * The DSC Helper is never contacted from this file — that is delegated to
 * dsc.SigningDialog which orchestrates the full flow.
 */

frappe.provide('dsc');

(function () {
	'use strict';

	/**
	 * Returns a Promise that resolves to an array of allowed doctype names.
	 * Example: ["Sales Invoice", "Purchase Order"]
	 */
	function getAllowedDoctypes() {
		// Check cached value first
		if (window._dsc_allowed_doctypes) {
			return Promise.resolve(window._dsc_allowed_doctypes);
		}

		return frappe
			.call('usb_dsc_signing.usb_dsc_signing.api.get_dsc_settings')
			.then(function (r) {
				const settings = r.message || {};
				// Cache both settings and allowed doctypes globally
				window._dsc_settings = settings;

				const doctypeNames = settings.allowed_doctypes || [];

				window._dsc_allowed_doctypes = doctypeNames;
				return doctypeNames;
			})
			.catch(function () {
				// Settings not available — no button for any doctype
				window._dsc_allowed_doctypes = [];
				return [];
			});
	}

	/**
	 * Check if a doctype is allowed for DSC signing.
	 */
	function isDoctypeAllowed(doctype, allowedList) {
		return allowedList.indexOf(doctype) !== -1;
	}

	/**
	 * Register the "Digitally Sign PDF" button on all allowed doctypes.
	 */
	function registerButton(doctype) {
		frappe.ui.form.on(doctype, {
			refresh: function (frm) {
				// Only show on submitted documents
				if (frm.doc.docstatus !== 1) {
					return;
				}

				// Only if globally enabled
				const settings = window._dsc_settings || {};
				if (settings.enabled === 0 || settings.enabled === false) {
					return;
				}

				frm.add_custom_button(
					__('Digitally Sign PDF'),
					function () {
						if (!window.dsc || !window.dsc.SigningDialog) {
							frappe.msgprint(
								__('DSC Signing module is not loaded. Please ask your administrator to check the app installation.')
							);
							return;
						}
						new dsc.SigningDialog({
							doctype: frm.doc.doctype,
							docname: frm.doc.name,
						}).show();
					},
					__('Actions')
				);
			},
		});
	}

	/**
	 * Initialise: fetch allowed doctypes and register the button.
	 */
	function init() {
		getAllowedDoctypes().then(function (allowedList) {
			if (!allowedList || allowedList.length === 0) {
				// No doctypes configured — nothing to register
				return;
			}

			allowedList.forEach(function (doctype) {
				registerButton(doctype);
			});
		});
	}

	// Boot
	init();
})();