/** @import { OKP, EC, RSA, JWK } from './parse' */

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
			(valueName ?? value ?? `"value"`) +
				" must be either an ArrayBuffer coercible or a base64 string: " +
				err.message,
			{
				cause: err,
			}
		);
	}
}

/**
 * Converts parsed COSE credentialPublicKey in authenticator data to JWK
 *
 * This is useful if you wish to export the public key to a more portable format
 *
 * You don't need to call this explicitly. You can access the readonly `jwk` property of `credentialPublicKey` in authenticator data
 *
 * @param {OKP | EC | RSA} cose The COSE `credentialPublicKey`
 * @returns {JWK} The JWK representation of the key
 */
export function coseToJwk(cose) {
	/** @type {Record<number, JWK["kty"]>} */
	const keyTypes = [, "OKP", "EC", "RSA"];

	/** @type {Record<number, JWK["crv"]>} */
	const ellipticCurves = [, "P-256", "P-384", "P-521", "X25519", "X448", "Ed25519", "Ed448", "secp256k1"];

	/** @type {Record<number, JWK["alg"]>} */
	const algorithms = {
		[-7]: "ES256",
		[-35]: "ES384",
		[-36]: "ES512",
		[-8]: "EdDSA",
		[-257]: "RS256",
		[-258]: "RS384",
		[-259]: "RS512",
		[-39]: "PS512",
		[-38]: "PS384",
		[-37]: "PS256",
	};

	/** @type {JWK} */
	const jwk = {
		kty: keyTypes[cose[1]],
		alg: algorithms[cose[3]],
	};

	switch (cose[1]) {
		case 2: // EC
			if (cose[-3]) jwk.y = cose[-3] instanceof Uint8Array ? bufferToBase64Url(cose[-3]) : cose[-3];
		case 1: // OKP
			jwk.crv = ellipticCurves[cose[-1]];
			if (cose[-2]) jwk.x = bufferToBase64Url(cose[-2]);
			if (cose[-4]) jwk.d = bufferToBase64Url(cose[-4]);
			break;
		case 3: // RSA
			if (cose[-1]) jwk.n = bufferToBase64Url(cose[-1]);
			if (cose[-2]) jwk.e = bufferToBase64Url(cose[-2]);
			if (cose[-3]) jwk.d = bufferToBase64Url(cose[-3]);
			if (cose[-4]) jwk.p = bufferToBase64Url(cose[-4]);
			if (cose[-5]) jwk.q = bufferToBase64Url(cose[-5]);
	}

	return jwk;
}

/**
 * @param {Buffer | Uint8Array} buffer
 * @returns {Base64URLString}
 */
export function bufferToBase64Url(buffer) {
	return "Buffer" in globalThis && buffer instanceof Buffer
		? buffer.toString("base64url")
		: base64ToBase64Url(btoa(String.fromCharCode(...buffer)));
}

/**
 * @param {Base64URLString} string
 * @returns {Base64URLString}
 */
export function base64UrlToBase64(string) {
	return string.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat(string.length % 4 && 1 - (string.length % 4));
}

/**
 * @param {Base64URLString} string
 * @returns {Base64URLString}
 */
export function base64ToBase64Url(string) {
	return string.replaceAll("+", "-").replaceAll("/", "_").replace(/=*$/, "");
}

/**
 * Parses an Algorithm object from a JWK. Useful for converting JWK to CryptoKey using `crypto.subtle.importKey`.
 *
 * Example:
 * ```js
 * const key = await crypto.subtle.importKey('jwk', jwk, getAlgorithmFromKey(jwK), true, ['verify'])
 *
 * await crypto.subtle.verify(key.algorithm, key, signature, data)
 * ```
 * @param {JWK} jwk
 * @returns {Algorithm}
 * @throws {Error} On unsupported key type
 */
export function getAlgorithmFromKey(jwk) {
	switch (jwk.kty) {
		case "RSA":
			return {
				name: "RSASSA-PKCS1-v1_5",
				hash: { name: `SHA-${jwk.alg.slice(-3)}` },
			};
		case "OKP":
			return { name: jwk.crv };
		case "EC":
			return {
				name: "ECDSA",
				hash: { name: `SHA-${jwk.alg.slice(-3)}` },
				namedCurve: jwk.crv,
			};
		default:
			throw new Error(`Unsupported key type: ${jwk.kty}`);
	}
}
