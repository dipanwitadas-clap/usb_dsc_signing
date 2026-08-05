/**
 * DSC Helper Communication Layer
 *
 * All communication with the local DSC Signing Helper (https://127.0.0.1:39999)
 * happens from the user's browser.  The ERPNext server never contacts the helper.
 *
 * The helper is a black-box external service running on the user's Windows machine.
 * API contract: OpenAPI 3.0 (see project docs).
 */

frappe.provide('dsc');

(function (dsc) {
	'use strict';

	/** Default helper URL — overridden by DSC Settings */
	const DEFAULT_BASE_URL = 'https://127.0.0.1:39999';
	const DEFAULT_TIMEOUT_MS = 30000;

	// ---------------------------------------------------------------------------
	// Public API
	// ---------------------------------------------------------------------------

	/**
	 * Health check + token status + certificate list (single request).
	 *
	 * Uses GET /info which returns everything we need to determine whether the
	 * helper is running, a token is inserted, and which certificates are
	 * available for signing.
	 *
	 * @param {object} [opts]
	 * @param {string} [opts.baseUrl]  Override helper URL (default: from DSC Settings or built-in).
	 * @param {number} [opts.timeoutMs] Timeout in milliseconds.
	 * @returns {Promise<object>}  {version, token, provider, present, certificates[]}
	 */
	dsc.checkHelperStatus = function (opts) {
		const { baseUrl, timeoutMs } = _resolveOpts(opts);
		return _fetchWithTimeout(`${baseUrl}/info`, { method: 'GET' }, timeoutMs)
			.then(_parseJson)
			.then(function (data) {
				// Normalise: ensure certificates is always an array
				if (!Array.isArray(data.certificates)) {
					data.certificates = [];
				}
				return data;
			});
	};

	/**
	 * List signing certificates from the USB token.
	 *
	 * Normally you can get certificates from checkHelperStatus() — this is a
	 * dedicated fallback that hits GET /certificates.
	 *
	 * @param {object} [opts]
	 * @param {string} [opts.baseUrl]
	 * @param {number} [opts.timeoutMs]
	 * @returns {Promise<object>}  {certificates[]}
	 */
	dsc.getCertificates = function (opts) {
		const { baseUrl, timeoutMs } = _resolveOpts(opts);
		return _fetchWithTimeout(`${baseUrl}/certificates`, { method: 'GET' }, timeoutMs)
			.then(_parseJson)
			.then(function (data) {
				if (!Array.isArray(data.certificates)) {
					data.certificates = [];
				}
				return data;
			});
	};

	/**
	 * Sign a pre-computed SHA-256 hash using the USB token.
	 *
	 * On the first sign after token insertion the HyperPKI native PIN dialog
	 * appears automatically.  We do NOT implement a PIN prompt — the vendor CSP
	 * handles authentication.
	 *
	 * @param {string}  hashHex       Hex-encoded SHA-256 digest of the PDF.
	 * @param {string}  certSerial    Certificate serial_number from /info or /certificates.
	 * @param {object}  [opts]
	 * @param {string}  [opts.baseUrl]
	 * @param {number}  [opts.timeoutMs]  Long timeout recommended — user may
	 *                                    need time to enter PIN.
	 * @returns {Promise<object>}
	 *   {signature_hex, cert_serial, algorithm, certificate_pem, chain_pem[]}
	 */
	dsc.signHash = function (hashHex, certSerial, opts) {
		const { baseUrl, timeoutMs } = _resolveOpts(opts);
		const body = {
			hash_hex: hashHex,
			hash_algorithm: (opts && opts.hashAlgorithm) || 'SHA-256',
		};
		if (certSerial) {
			body.cert_serial = certSerial;
		}

		return _fetchWithTimeout(
			`${baseUrl}/sign`,
			{
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(body),
			},
			timeoutMs
		).then(_parseJson);
	};

	// ---------------------------------------------------------------------------
	// Helpers
	// ---------------------------------------------------------------------------

	/**
	 * Resolve base URL and timeout from DSC Settings, falling back to defaults.
	 */
	function _resolveOpts(opts) {
		let baseUrl = (opts && opts.baseUrl) || DEFAULT_BASE_URL;
		let timeoutMs = (opts && opts.timeoutMs) || DEFAULT_TIMEOUT_MS;

		// Attempt to read settings stored on frappe.boot or via cached API
		try {
			const settings = _getCachedSettings();
			if (settings) {
				baseUrl = opts && opts.baseUrl ? opts.baseUrl : (settings.helper_url || DEFAULT_BASE_URL);
				timeoutMs = opts && opts.timeoutMs ? opts.timeoutMs : ((settings.request_timeout || 30) * 1000);
			}
		} catch (_e) {
			// Settings not available yet — use defaults
		}

		return { baseUrl: baseUrl, timeoutMs: timeoutMs };
	}

	/**
	 * Retrieve cached DSC Settings (set by signing_dialog on first load).
	 */
	function _getCachedSettings() {
		if (window._dsc_settings) {
			return window._dsc_settings;
		}
		// Fallback: try frappe.boot (if populated by a boot hook)
		if (frappe.boot && frappe.boot.dsc_settings) {
			return frappe.boot.dsc_settings;
		}
		return null;
	}

	/**
	 * fetch() wrapper with configurable timeout using AbortController.
	 */
	function _fetchWithTimeout(url, init, timeoutMs) {
		const controller = new AbortController();
		const timer = setTimeout(function () {
			controller.abort();
		}, timeoutMs);

		const fetchOpts = Object.assign({}, init, { signal: controller.signal });

		return fetch(url, fetchOpts).then(
			function (response) {
				clearTimeout(timer);
				return response;
			},
			function (err) {
				clearTimeout(timer);
				if (err && err.name === 'AbortError') {
					throw new Error(
						__('Request to DSC Helper timed out after {0} seconds.', [Math.round(timeoutMs / 1000)])
					);
				}
				throw err;
			}
		);
	}

	/**
	 * Parse JSON response, extracting error detail if the helper returned an
	 * HTTP error status.
	 */
	function _parseJson(response) {
		return response.text().then(function (rawText) {
			let data;
			try {
				data = JSON.parse(rawText);
			} catch (_e) {
				// Non-JSON response — treat as text error
				var statusText = rawText.substring(0, 500) || response.statusText;
				throw new Error(
					__('DSC Helper returned an unexpected response (HTTP {0}): {1}', [
						response.status,
						statusText,
					])
				);
			}

			if (!response.ok) {
				// Helper returned structured error per OpenAPI ErrorResponse
				const detail = (data && data.detail) ? data.detail : response.statusText;
				throw new Error(
					__('DSC Helper error (HTTP {0}): {1}', [response.status, detail])
				);
			}

			return data;
		});
	}

})(dsc);