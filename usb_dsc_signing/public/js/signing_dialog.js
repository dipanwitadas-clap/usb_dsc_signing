/**
 * Multi-step Digital Signing Dialog
 *
 * Orchestrates the full signing flow:
 *   1. Check DSC Helper status  (GET /info)
 *   2. Select certificate        (from /info response or GET /certificates)
 *   3. Select print format       (same list as Frappe's own print view)
 *   4. Generate PDF + hash       (frappe.call → prepare_for_signing)
 *   5. Sign hash                 (POST /sign)
 *   6. Embed signature           (frappe.call → complete_signing)
 *   7. Show result / download
 *
 * The DSC helper is treated as a black-box external service.
 * We never prompt for a PIN — the vendor CSP handles that automatically.
 */

frappe.provide('dsc');

(function (dsc) {
	'use strict';

	// -----------------------------------------------------------------------
	// SigningDialog constructor
	// -----------------------------------------------------------------------

	/**
	 * @param {object}  opts
	 * @param {string}  opts.doctype   Source DocType (e.g. "Sales Invoice")
	 * @param {string}  opts.docname   Source document name
	 */
	dsc.SigningDialog = function (opts) {
		if (!opts || !opts.doctype || !opts.docname) {
			frappe.throw(__('SigningDialog requires doctype and docname.'));
		}

		this.doctype = opts.doctype;
		this.docname = opts.docname;
		this.selectedCert = null;
		this.selectedPrintFormat = null;
		this.sessionId = null;
		this.tbsHashHex = null;
		this.hashAlgorithm = 'SHA-256';
		this.signedFileUrl = null;

		this._currentStep = 0;
		this._aborted = false;
		this._buildDialog();
	};

	dsc.SigningDialog.prototype = {
		// -------------------------------------------------------------------
		// Public
		// -------------------------------------------------------------------

		/** Open the dialog and start the signing flow. */
		show: function () {
			this.dialog.show();
			this._loadSettings().then(this._startFlow.bind(this));
		},

		/** Abort the current flow and close the dialog. */
		abort: function () {
			this._aborted = true;
			this.dialog.hide();
		},

		// -------------------------------------------------------------------
		// Internal — flow orchestration
		// -------------------------------------------------------------------

		/**
		 * Load DSC Settings from server (cached in window._dsc_settings so
		 * helper_client.js can also use them).
		 */
		_loadSettings: function () {
			var self = this;
			if (window._dsc_settings) {
				return Promise.resolve(window._dsc_settings);
			}
			return frappe
				.call('usb_dsc_signing.usb_dsc_signing.api.get_dsc_settings')
				.then(function (r) {
					window._dsc_settings = r.message || {};
					return window._dsc_settings;
				})
				.catch(function () {
					// Settings not available — use defaults
					window._dsc_settings = {};
					return window._dsc_settings;
				});
		},

		/**
		 * Step 1 → Step 2 → Step 3 → Step 4 → Step 5 → Step 6 → Step 7
		 * Each step calls _nextStep internally on success.
		 */
		_startFlow: function () {
			this._goToStep(1);
		},

		_nextStep: function () {
			if (this._aborted) return;
			this._currentStep += 1;
			this._executeStep(this._currentStep);
		},

		_goToStep: function (step) {
			if (this._aborted) return;
			this._currentStep = step;
			this._executeStep(step);
		},

		_executeStep: function (step) {
			switch (step) {
				case 1:
					return this._stepCheckHelper();
				case 2:
					return this._stepSelectCertificate();
				case 3:
					return this._stepSelectPrintFormat();
				case 4:
					return this._stepGeneratePdf();
				case 5:
					return this._stepSignHash();
				case 6:
					return this._stepEmbedSignature();
				case 7:
					return this._stepDone();
				default:
					break;
			}
		},

		// -------------------------------------------------------------------
		// Step 1 – Check Helper
		// -------------------------------------------------------------------

		_stepCheckHelper: function () {
			this._markStepActive(1);
			this._setStatus(__('Checking DSC Helper...'), 'info', true);

			var self = this;
			dsc
				.checkHelperStatus()
				.then(function (info) {
					if (self._aborted) return;
					self.helperInfo = info;

					if (!info.present) {
						self._markStepError(1);
						self._setStatus(
							__('USB Token not detected. Please insert your DSC USB Token and try again.'),
							'error'
						);
						self._showRetryButton(function () {
							self._goToStep(1);
						});
						return;
					}

					if (!Array.isArray(info.certificates) || info.certificates.length === 0) {
						self._markStepError(1);
						self._setStatus(
							__('No certificates found on the USB token.'),
							'error'
						);
						self._showRetryButton(function () {
							self._goToStep(1);
						});
						return;
					}

					self.certificates = info.certificates;
					self._markStepDone(1);
					self._nextStep();
				})
				.catch(function (err) {
					if (self._aborted) return;
					self._markStepError(1);
					self._setStatus(
						__('DSC Helper is not running. Please start DSC Signing Helper on your Windows machine.<br><br>Error: {0}', [
							err.message || String(err),
						]),
						'error'
					);
					self._showRetryButton(function () {
						self._goToStep(1);
					});
				});
		},

		// -------------------------------------------------------------------
		// Step 2 – Select Certificate
		// -------------------------------------------------------------------

		_stepSelectCertificate: function () {
			var certs = this.certificates;

			if (certs.length === 1) {
				// Auto-select
				this.selectedCert = certs[0];
				this._markStepDone(2, __('Auto-selected'));
				this._renderCertSummary(this.selectedCert);
				this._nextStep();
				return;
			}

			// Multiple certificates — show selection UI
			this._markStepActive(2);
			this._setStatus(__('Select the certificate to use for signing:'), 'info');
			this._renderCertSelection(certs);
		},

		/**
		 * Certificate subject/issuer come from the DSC helper as raw
		 * RFC-2253-ish DN strings (e.g. "CN=John Doe,1.2.840.113549.1.9.1=
		 * john@x.com,2.5.4.5=...,O=Personal,C=IN"). Parse out the handful
		 * of fields worth showing a human instead of dumping the whole DN.
		 */
		_splitDN: function (dn) {
			var parts = [];
			var current = '';
			for (var i = 0; i < dn.length; i++) {
				var ch = dn[i];
				if (ch === '\\' && i + 1 < dn.length) {
					current += ch + dn[i + 1];
					i++;
					continue;
				}
				if (ch === ',') {
					parts.push(current);
					current = '';
					continue;
				}
				current += ch;
			}
			if (current) parts.push(current);
			return parts;
		},

		_parseDN: function (dn) {
			var result = {};
			if (!dn) return result;
			this._splitDN(dn).forEach(function (part) {
				var idx = part.indexOf('=');
				if (idx === -1) return;
				var key = part.slice(0, idx).trim();
				var value = part
					.slice(idx + 1)
					.trim()
					.replace(/\\,/g, ',')
					.replace(/\\\\/g, '\\');
				if (key && !(key in result)) {
					result[key] = value;
				}
			});
			return result;
		},

		_formatDate: function (isoStr) {
			if (!isoStr) return '';
			try {
				if (window.moment) {
					return moment(isoStr).format('DD MMM YYYY');
				}
				return new Date(isoStr).toLocaleDateString();
			} catch (_e) {
				return isoStr;
			}
		},

		/** Pull just Name / Email / Issuer / Expiry out of the raw cert DNs. */
		_certFriendly: function (cert) {
			var subject = this._parseDN(cert.subject || '');
			var issuer = this._parseDN(cert.issuer || '');
			var email = subject['1.2.840.113549.1.9.1'] || subject.E || subject.emailAddress || '';
			return {
				name: subject.CN || __('Unknown'),
				email: email,
				issuerName: issuer.CN || '',
				issuerOrg: issuer.O || '',
				expires: cert.not_after || '',
			};
		},

		/** Short one-line label, e.g. "John Doe <john@x.com> — expires 02 Apr 2029" */
		_certDisplay: function (cert) {
			var f = this._certFriendly(cert);
			var line = f.email ? f.name + ' <' + f.email + '>' : f.name;
			if (f.expires) {
				line += ' — ' + __('expires {0}', [this._formatDate(f.expires)]);
			}
			return line;
		},

		/** Renders a compact, persistent summary card for the chosen certificate. */
		_renderCertSummary: function (cert) {
			var body = this.dialog.body;
			var old = body.querySelector('.dsc-cert-summary');
			if (old) old.remove();

			var f = this._certFriendly(cert);
			var card = document.createElement('div');
			card.className = 'dsc-cert-summary';

			var rows = [
				[__('Signer'), f.email ? f.name + ' <' + f.email + '>' : f.name],
				[__('Issued By'), [f.issuerName, f.issuerOrg].filter(Boolean).join(', ')],
				[__('Valid Until'), this._formatDate(f.expires)],
			];

			rows.forEach(function (row) {
				if (!row[1]) return;
				var rowDiv = document.createElement('div');
				rowDiv.className = 'dsc-cert-summary-row';

				var keyEl = document.createElement('span');
				keyEl.className = 'dsc-cert-summary-key';
				keyEl.textContent = row[0];

				var valEl = document.createElement('span');
				valEl.className = 'dsc-cert-summary-value';
				valEl.textContent = row[1];

				rowDiv.appendChild(keyEl);
				rowDiv.appendChild(valEl);
				card.appendChild(rowDiv);
			});

			var loaderEl = body.querySelector('.dsc-loader');
			if (loaderEl) {
				body.insertBefore(card, loaderEl);
			} else {
				body.appendChild(card);
			}
		},

		_renderCertSelection: function (certs) {
			var self = this;
			var body = this.dialog.body;
			// Keep the status area, add selection below it
			var selDiv = document.createElement('div');
			selDiv.className = 'dsc-cert-selection';

			certs.forEach(function (cert, idx) {
				var row = document.createElement('div');
				row.className = 'dsc-cert-row';

				var radio = document.createElement('input');
				radio.type = 'radio';
				radio.name = 'dsc_cert';
				radio.value = cert.serial_number || idx;
				radio.id = 'dsc_cert_' + idx;

				var label = document.createElement('label');
				label.htmlFor = 'dsc_cert_' + idx;
				label.innerHTML = frappe.utils.escape_html(self._certDisplay(cert));

				row.appendChild(radio);
				row.appendChild(label);
				selDiv.appendChild(row);
			});

			// Replace previous selection if it exists
			var old = body.querySelector('.dsc-cert-selection');
			if (old) old.remove();
			body.appendChild(selDiv);

			// Change the footer to show Continue
			self._hideRetryButton();
			var footer = self.dialog.footer.get(0);
			footer.innerHTML = '';

			var continueBtn = document.createElement('button');
			continueBtn.className = 'btn btn-primary btn-sm';
			continueBtn.textContent = __('Continue');
			continueBtn.addEventListener('click', function () {
				var selected = selDiv.querySelector('input[name="dsc_cert"]:checked');
				if (!selected) {
					frappe.msgprint(__('Please select a certificate.'));
					return;
				}
				var certIdx = parseInt(selected.value, 10);
				if (isNaN(certIdx)) {
					// value is the serial_number string
					self.selectedCert = certs.find(function (c) {
						return c.serial_number === selected.value;
					});
				} else {
					self.selectedCert = certs[certIdx];
				}

				// Clean up selection UI
				if (selDiv) selDiv.remove();
				self._markStepDone(2, __('Selected'));
				self._renderCertSummary(self.selectedCert);
				self._nextStep();
			});
			footer.appendChild(continueBtn);

			var cancelBtn = document.createElement('button');
			cancelBtn.className = 'btn btn-default btn-sm ml-2';
			cancelBtn.textContent = __('Cancel');
			cancelBtn.addEventListener('click', function () {
				self.abort();
			});
			footer.appendChild(cancelBtn);
		},

		// -------------------------------------------------------------------
		// Step 3 – Select Print Format
		// -------------------------------------------------------------------

		/**
		 * Same print format list Frappe's own print preview offers for this
		 * DocType (frappe.meta.get_print_formats), so whatever the user
		 * would normally print is available to sign too.
		 */
		_stepSelectPrintFormat: function () {
			this._markStepActive(3);
			this._setStatus(__('Choose the print format to sign:'), 'info');
			this._renderPrintFormatSelection();
		},

		_renderPrintFormatSelection: function () {
			var self = this;
			var body = this.dialog.body;

			var formats = [];
			try {
				formats = frappe.meta.get_print_formats(this.doctype) || [];
			} catch (_e) {
				formats = ['Standard'];
			}
			if (!formats.length) {
				formats = ['Standard'];
			}

			var selDiv = document.createElement('div');
			selDiv.className = 'dsc-print-format-selection';

			var label = document.createElement('label');
			label.className = 'dsc-print-format-label';
			label.textContent = __('Print Format');
			selDiv.appendChild(label);

			var select = document.createElement('select');
			select.className = 'form-control dsc-print-format-select';
			formats.forEach(function (fmt) {
				var option = document.createElement('option');
				option.value = fmt;
				option.textContent = fmt;
				select.appendChild(option);
			});
			selDiv.appendChild(select);

			var old = body.querySelector('.dsc-print-format-selection');
			if (old) old.remove();
			body.appendChild(selDiv);

			this._hideRetryButton();
			var footer = this.dialog.footer.get(0);
			footer.innerHTML = '';

			var continueBtn = document.createElement('button');
			continueBtn.className = 'btn btn-primary btn-sm';
			continueBtn.textContent = __('Continue');
			continueBtn.addEventListener('click', function () {
				self.selectedPrintFormat = select.value;
				if (selDiv) selDiv.remove();
				self._markStepDone(3, __('Format: {0}', [self.selectedPrintFormat]));
				self._nextStep();
			});
			footer.appendChild(continueBtn);

			var cancelBtn = document.createElement('button');
			cancelBtn.className = 'btn btn-default btn-sm ml-2';
			cancelBtn.textContent = __('Cancel');
			cancelBtn.addEventListener('click', function () {
				self.abort();
			});
			footer.appendChild(cancelBtn);
		},

		// -------------------------------------------------------------------
		// Step 4 – Generate PDF & compute hash
		// -------------------------------------------------------------------

		_stepGeneratePdf: function () {
			this._markStepActive(4);
			this._setStatus(__('Generating PDF and preparing signature...'), 'info', true);

			if (!this.selectedCert || !this.selectedCert.pem) {
				this._markStepError(4);
				this._setStatus(
					__('The DSC Helper did not return certificate data (PEM) for the selected certificate. Cannot proceed.'),
					'error'
				);
				return;
			}

			var self = this;
			frappe
				.call('usb_dsc_signing.usb_dsc_signing.api.prepare_for_signing', {
					doctype: this.doctype,
					docname: this.docname,
					certificate_pem: this.selectedCert.pem,
					certificate_serial: this.selectedCert.serial_number || null,
					chain_pem: this.selectedCert.chain_pem || [],
					print_format: this.selectedPrintFormat || 'Standard',
				})
				.then(function (r) {
					if (self._aborted) return;
					var data = r.message;
					self.sessionId = data.session_id;
					self.tbsHashHex = data.tbs_hash_hex;
					self.hashAlgorithm = data.hash_algorithm || 'SHA-256';
					self._markStepDone(4);
					self._nextStep();
				})
				.catch(function (err) {
					if (self._aborted) return;
					self._markStepError(4);
					self._setStatus(
						__('Failed to generate PDF: {0}', [err.message || String(err)]),
						'error'
					);
				});
		},

		// -------------------------------------------------------------------
		// Step 5 – Sign hash via helper
		// -------------------------------------------------------------------

		_stepSignHash: function () {
			this._markStepActive(5);
			this._setStatus(
				__('Signing... If this is your first sign, the PIN dialog will appear. Please enter your PIN in the vendor dialog.'),
				'info',
				true
			);

			var certSerial = this.selectedCert ? this.selectedCert.serial_number : null;
			var self = this;

			dsc
				.signHash(this.tbsHashHex, certSerial, {
					hashAlgorithm: this.hashAlgorithm,
					// Longer timeout for PIN entry
					timeoutMs: (window._dsc_settings && window._dsc_settings.request_timeout
						? window._dsc_settings.request_timeout * 1000
						: 120000),
				})
				.then(function (signResult) {
					if (self._aborted) return;
					self.signResult = signResult;
					self._markStepDone(5);
					self._nextStep();
				})
				.catch(function (err) {
					if (self._aborted) return;
					self._markStepError(5);
					var msg = err.message || String(err);
					// Friendly message for common errors
					if (msg.indexOf('AbortError') !== -1 || msg.indexOf('timed out') !== -1) {
						msg = __('Signing timed out. Please ensure you entered your PIN in the vendor dialog within the time limit.');
					}
					self._setStatus(__('Signing failed: {0}', [msg]), 'error');
					self._showRetryButton(function () {
						self._goToStep(5);
					});
				});
		},

		// -------------------------------------------------------------------
		// Step 6 – Embed signature into PDF
		// -------------------------------------------------------------------

		_stepEmbedSignature: function () {
			this._markStepActive(6);
			this._setStatus(__('Embedding digital signature into PDF...'), 'info', true);

			var self = this;
			frappe
				.call('usb_dsc_signing.usb_dsc_signing.api.complete_signing', {
					session_id: this.sessionId,
					signature_hex: this.signResult.signature_hex,
					cert_serial: this.signResult.cert_serial || null,
				})
				.then(function (r) {
					if (self._aborted) return;
					self.signedResult = r.message;
					self.signedFileUrl = r.message.file_url;
					self._markStepDone(6);
					self._nextStep();
				})
				.catch(function (err) {
					if (self._aborted) return;
					self._markStepError(6);
					self._setStatus(
						__('Failed to embed signature: {0}', [err.message || String(err)]),
						'error'
					);
				});
		},

		// -------------------------------------------------------------------
		// Step 7 – Done
		// -------------------------------------------------------------------

		_stepDone: function () {
			var self = this;
			this._markStepDone(7);
			this._setStatus(
				__('✔ Document Signed Successfully by {0} on {1}', [
					this.signedResult.signed_by || __('Unknown'),
					this.signedResult.signed_on || '',
				]),
				'success'
			);

			// Replace footer with action buttons
			var footer = this.dialog.footer.get(0);
			footer.innerHTML = '';

			var viewBtn = document.createElement('button');
			viewBtn.className = 'btn btn-primary btn-sm';
			viewBtn.textContent = __('View Signed PDF');
			viewBtn.addEventListener('click', function () {
				var url = self.signedFileUrl;
				if (url) {
					window.open(url, '_blank');
				}
			});
			footer.appendChild(viewBtn);

			var downloadBtn = document.createElement('button');
			downloadBtn.className = 'btn btn-default btn-sm ml-2';
			downloadBtn.textContent = __('Download');
			downloadBtn.addEventListener('click', function () {
				var url = self.signedFileUrl;
				if (url) {
					var a = document.createElement('a');
					a.href = url;
					a.download = '';
					a.click();
				}
			});
			footer.appendChild(downloadBtn);

			var closeBtn = document.createElement('button');
			closeBtn.className = 'btn btn-default btn-sm ml-2';
			closeBtn.textContent = __('Close');
			closeBtn.addEventListener('click', function () {
				self.dialog.hide();
			});
			footer.appendChild(closeBtn);
		},

		// -------------------------------------------------------------------
		// UI builders
		// -------------------------------------------------------------------

		_buildDialog: function () {
			var self = this;

			this.dialog = new frappe.ui.Dialog({
				title: __('Digitally Sign PDF — {0}', [this.docname]),
				size: 'large',
				fields: [],
				primary_action_label: __('Close'),
				primary_action: function () {
					self.dialog.hide();
				},
			});

			// Hide the default primary button — we manage our own footer
			this.dialog.$wrapper.find('.modal-footer').addClass('dsc-dialog-footer');

			// Build the step indicator + status area in the body
			this._buildStepIndicator();
			this._buildStatusArea();
			this._buildLoadingArea();
		},

		/** Seven-step indicator: [1:Helper] [2:Cert] [3:Format] [4:PDF] [5:Sign] [6:Embed] [7:Done] */
		_buildStepIndicator: function () {
			var stepsDiv = document.createElement('div');
			stepsDiv.className = 'dsc-steps';

			var stepNames = [
				__('Check Helper'),
				__('Certificate'),
				__('Print Format'),
				__('Generate PDF'),
				__('Sign'),
				__('Embed'),
				__('Complete'),
			];

			for (var i = 0; i < stepNames.length; i++) {
				var step = document.createElement('div');
				step.className = 'dsc-step';
				step.setAttribute('data-step', i + 1);

				var indicator = document.createElement('span');
				indicator.className = 'dsc-step-indicator';
				indicator.textContent = i + 1;

				var label = document.createElement('span');
				label.className = 'dsc-step-label';
				label.textContent = stepNames[i];

				step.appendChild(indicator);
				step.appendChild(label);
				stepsDiv.appendChild(step);
			}

			this.dialog.body.appendChild(stepsDiv);
		},

		_buildStatusArea: function () {
			var statusDiv = document.createElement('div');
			statusDiv.className = 'dsc-status';
			this.dialog.body.appendChild(statusDiv);
		},

		_buildLoadingArea: function () {
			var loaderDiv = document.createElement('div');
			loaderDiv.className = 'dsc-loader';
			loaderDiv.style.display = 'none';
			loaderDiv.innerHTML = '<div class="dsc-spinner"></div>';
			this.dialog.body.appendChild(loaderDiv);
		},

		// -------------------------------------------------------------------
		// UI helpers
		// -------------------------------------------------------------------

		_setStatus: function (html, type, showLoader) {
			var statusEl = this.dialog.body.querySelector('.dsc-status');
			if (!statusEl) return;
			statusEl.className = 'dsc-status dsc-status-' + (type || 'info');
			statusEl.innerHTML = html;

			var loaderEl = this.dialog.body.querySelector('.dsc-loader');
			if (loaderEl) {
				loaderEl.style.display = showLoader ? 'flex' : 'none';
			}
		},

		_markStepDone: function (step, labelOverride) {
			var el = this.dialog.body.querySelector('.dsc-step[data-step="' + step + '"]');
			if (!el) return;
			el.className = 'dsc-step dsc-step-done';
			el.querySelector('.dsc-step-indicator').textContent = '✓';
			if (labelOverride) {
				el.querySelector('.dsc-step-label').textContent = labelOverride;
			}
		},

		_markStepActive: function (step) {
			var el = this.dialog.body.querySelector('.dsc-step[data-step="' + step + '"]');
			if (!el) return;
			el.className = 'dsc-step dsc-step-active';
		},

		_markStepError: function (step) {
			var el = this.dialog.body.querySelector('.dsc-step[data-step="' + step + '"]');
			if (!el) return;
			el.className = 'dsc-step dsc-step-error';
			el.querySelector('.dsc-step-indicator').textContent = '✗';
		},

		_showRetryButton: function (cb) {
			var footer = this.dialog.footer.get(0);
			footer.innerHTML = '';

			var retryBtn = document.createElement('button');
			retryBtn.className = 'btn btn-primary btn-sm';
			retryBtn.textContent = __('Retry');
			retryBtn.addEventListener('click', cb);
			footer.appendChild(retryBtn);

			var self = this;
			var cancelBtn = document.createElement('button');
			cancelBtn.className = 'btn btn-default btn-sm ml-2';
			cancelBtn.textContent = __('Cancel');
			cancelBtn.addEventListener('click', function () {
				self.abort();
			});
			footer.appendChild(cancelBtn);
		},

		_hideRetryButton: function () {
			// footer is managed per-step — no-op here
		},
	};

})(dsc);
