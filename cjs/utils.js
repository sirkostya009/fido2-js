/**
 * @template T
 * @param s {T}
 * @returns {T | string}
 */
const quoteString = (s) => (typeof s === "string" ? `"${s}"` : s);

/**
 * Converts base64url or base64 string to either a Node.js Buffer (if available) or Uint8Array.
 *
 * @param {ArrayBuffer | Uint8Array | Base64URLString} value buffer-coercible
 * @param {string} [valueName] value name for better error logging
 * @returns {Uint8Array | Buffer} parsed or the very same buffer instance
 */
function toBuffer(value, valueName) {
	try {
		return value instanceof ArrayBuffer
			? new Uint8Array(value)
			: value instanceof Uint8Array
			? value
			: "Buffer" in globalThis
			? Buffer.from(value, "base64")
			: "fromBase64" in Uint8Array
			? Uint8Array.fromBase64(value)
			: Uint8Array.from(atob(base64UrlToBase64(value)), (c) => c.charCodeAt(0));
	} catch (err) {
		throw new Error(
			(valueName ?? quoteString(value) ?? `"value"`) +
				" must be either an ArrayBuffer coercible or a base64 string",
			{ cause: err }
		);
	}
}

/** @returns {Base64URLString} */
function bufferToBase64Url(/** @type {Buffer | Uint8Array} */ buffer) {
	return "Buffer" in globalThis && buffer instanceof Buffer
		? buffer.toString("base64url")
		: "toBase64" in Uint8Array.prototype
		? buffer.toBase64({ alphabet: "base64url" })
		: base64ToBase64Url(btoa(String.fromCharCode(...buffer)));
}

/** @returns {Base64URLString} */
function base64UrlToBase64(/** @type {Base64URLString} */ string) {
	return string.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat(string.length % 4 && 1 - (string.length % 4));
}

/** @returns {Base64URLString} */
function base64ToBase64Url(/** @type {Base64URLString} */ string) {
	return string.replaceAll("+", "-").replaceAll("/", "_").replace(/=*$/, "");
}

/** @returns {string=} */
function base64ToJSON(/** @type {string | Uint8Array | ArrayBuffer} */ s) {
	return "Buffer" in globalThis && s instanceof Buffer
		? s // JSON.parse in node works on Buffer instances too
		: s instanceof Uint8Array
		? String.fromCharCode(...s)
		: s instanceof ArrayBuffer
		? String.fromCharCode(...new Uint8Array(s))
		: typeof s === "string"
		? atob(base64UrlToBase64(s))
		: undefined;
}

module.exports.quoteString = quoteString;
module.exports.toBuffer = toBuffer;
module.exports.bufferToBase64Url = bufferToBase64Url;
module.exports.base64UrlToBase64 = base64UrlToBase64;
module.exports.base64ToBase64Url = base64ToBase64Url;
module.exports.base64ToJSON = base64ToJSON;
