/**
 * Converts base64url or base64 string to either a Node.js Buffer (if available) or Uint8Array.
 *
 * @param {ArrayBuffer | Uint8Array | Base64URLString} value buffer-coercible
 * @param {string} [valueName] value name for better error logging
 * @returns {Uint8Array | Buffer} parsed or the very same buffer instance
 */
export function toBuffer(value, valueName) {
	try {
		return value instanceof ArrayBuffer
			? new Uint8Array(value)
			: value instanceof Uint8Array
			? value
			: "Buffer" in globalThis
			? Buffer.from(value, "base64")
			: Uint8Array.from(atob(base64UrlToBase64(value)), (c) => c.charCodeAt(0));
	} catch (err) {
		throw new Error(
			(valueName ?? value ?? `"value"`) + " must be either an ArrayBuffer coercible or a base64 string",
			{ cause: err }
		);
	}
}

/** @returns {Base64URLString} */
export function bufferToBase64Url(/** @type {Buffer | Uint8Array} */ buffer) {
	return "Buffer" in globalThis && buffer instanceof Buffer
		? buffer.toString("base64url")
		: base64ToBase64Url(btoa(String.fromCharCode(...buffer)));
}

/** @returns {Base64URLString} */
export function base64UrlToBase64(/** @type {Base64URLString} */ string) {
	return string.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat(string.length % 4 && 1 - (string.length % 4));
}

/** @returns {Base64URLString} */
export function base64ToBase64Url(/** @type {Base64URLString} */ string) {
	return string.replaceAll("+", "-").replaceAll("/", "_").replace(/=*$/, "");
}
