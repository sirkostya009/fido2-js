/**
 * @template T
 * @param s {T}
 * @returns {T | string}
 */
export const quoteString = (s) => (typeof s === "string" ? `"${s}"` : s);

/**
 * Converts base64url or base64 string to either a Node.js Buffer (if available) or Uint8Array.
 *
 * @param {ArrayBuffer | Uint8Array | Base64URLString} value buffer-coercible
 * @param {string} [valueName] value name for better error logging
 * @returns {Uint8Array | Buffer} parsed or the very same buffer instance
 */
export function toBuffer(value, valueName) {
	try {
		if (value instanceof ArrayBuffer) {
			return new Uint8Array(value);
		}

		if (value instanceof Uint8Array) {
			return value;
		}

		if ("Buffer" in globalThis) {
			return Buffer.from(value, "base64");
		}

		if ("fromBase64" in Uint8Array) {
			// @ts-expect-error
			return Uint8Array.fromBase64(value);
		}

		return Uint8Array.from(atob(base64UrlToBase64(value)), (c) => c.charCodeAt(0));
	} catch (err) {
		throw new Error(
			(valueName ?? quoteString(value) ?? `value`) +
				" must be either an ArrayBuffer coercible or a base64 string",
			{ cause: err },
		);
	}
}

/** @returns {Base64URLString} */
export function bufferToBase64Url(/** @type {Buffer | Uint8Array} */ buffer) {
	if ("Buffer" in globalThis && buffer instanceof Buffer) {
		return buffer.toString("base64url");
	}

	if (buffer instanceof Uint8Array && "toBase64" in Uint8Array.prototype) {
		// @ts-expect-error
		return buffer.toBase64({ alphabet: "base64url" });
	}

	return base64ToBase64Url(btoa(String.fromCharCode(...buffer)));
}

/** @returns {Base64URLString} */
export function base64UrlToBase64(/** @type {Base64URLString} */ string) {
	return string.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (string.length % 4)) % 4);
}

/** @returns {Base64URLString} */
export function base64ToBase64Url(/** @type {Base64URLString} */ string) {
	return string.replaceAll("+", "-").replaceAll("/", "_").replace(/=*$/, "");
}

export function base64ToJSON(/** @type {string | Uint8Array | ArrayBuffer} */ s) {
	if ("Buffer" in globalThis && s instanceof Buffer) {
		// JSON.parse in node works on Buffer instances too
		return s;
	}

	if (s instanceof Uint8Array || s instanceof ArrayBuffer) {
		return new TextDecoder().decode(s);
	}

	if (typeof s === "string") {
		return atob(base64UrlToBase64(s));
	}
}
