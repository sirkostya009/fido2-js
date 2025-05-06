const { getAlgorithmFromKey, parse } = require("./parse.js");
const { toBuffer } = require("./utils.js");
/** @import { AuthenticatorData, AssertionResponse, AttestationResponse, AttestationObject, AssertionObject, COSE, JWK, AssertionOptions, AttestationOptions } from '../types' */

const quoteString = (s) => (typeof s === "string" ? `"${s}"` : s);

/**
 * Parses and validates attestation responses
 *
 * @param {AttestationResponse} a
 * @param {Base64URLString | Uint8Array} challenge The challenge that was previously used for the attestation
 * @param {AttestationOptions} [opts] Optional yet important additional checks
 * @returns {Promise<AttestationObject>}
 * @throws {Error}
 */
async function attestation(a, challenge, opts = {}) {
	const { response, rawAuthenticatorData, rawClientData } = parse(a);

	if (response.clientData.type !== "webauthn.create") {
		throw new Error(
			`Invalid client data type, expected: "webauthn.create", got: ${quoteString(response.clientData.type)}`
		);
	}

	verifyChallenge(response.clientData.challenge, challenge);

	switch (response.attestationObject.fmt) {
		case "packed": // TODO: https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation
			break;
		case "tpm": // TODO: https://www.w3.org/TR/webauthn-2/#sctn-tpm-attestation
			break;
		case "android-key": // TODO: https://www.w3.org/TR/webauthn-2/#sctn-android-key-attestation
			break;
		case "android-safetynet": // TODO: https://www.w3.org/TR/webauthn-2/#sctn-android-safetynet-attestation
			break;
		case "fido-u2f": // TODO: https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation
			break;
		case "apple": // TODO: https://www.w3.org/TR/webauthn-2/#sctn-apple-anonymous-attestation
			break;
		case "none":
			break;
	}

	if ("userFactor" in opts) verifyUserFactor(response.attestationObject.authData.flags, opts.userFactor);
	if ("origins" in opts) verifyOrigins(response.clientData.origin, opts.origins);
	if ("rpId" in opts) await verifyRpId(response.attestationObject.authData.rpIdHash, opts.rpId);

	return response;
}

/**
 * Parses and validates assertion responses
 *
 * @param {AssertionResponse} a
 * @param {Base64URLString | Uint8Array} challenge The challenge that was previously used for the assertion
 * @param {COSE | JWK | CryptoKey} publicKey Previously acquired key from attestation
 * @param {AssertionOptions} [opts] Optional yet important additional checks
 * @returns {Promise<AssertionObject>}
 * @throws {Error}
 */
async function assertion(a, challenge, publicKey, opts = {}) {
	const { response, rawAuthenticatorData, rawClientData } = parse(a);

	if (response.clientData.type !== "webauthn.get") {
		throw new Error(
			`Invalid client data type, expected: "webauthn.get", got: ${quoteString(response.clientData.type)}`
		);
	}

	verifyChallenge(response.clientData.challenge, challenge);

	let key = publicKey;

	if ("1" in key) {
		key = coseToJwk(key);
	}
	if ("kty" in key) {
		key = Object.defineProperty(
			await crypto.subtle.importKey("jwk", key, getAlgorithmFromKey(key), true, ["verify"]),
			"algorithm",
			{
				value: getAlgorithmFromKey(key),
			}
		);
	}
	if (!(key instanceof CryptoKey)) {
		throw new Error(
			`Expected publicKey to be CryptoKey-coercible (CryptoKey, COSE, JWK), got: ${quoteString(key)}`
		);
	}

	const hash = new Uint8Array(await crypto.subtle.digest("sha-256", rawClientData));
	const data = new Uint8Array(rawAuthenticatorData.length + hash.length);
	data.set(rawAuthenticatorData);
	data.set(hash, rawAuthenticatorData.length);

	if (!(await crypto.subtle.verify(key.algorithm, key, toBuffer(response.signature, "signature"), data))) {
		throw new Error("Signature verification failed");
	}

	if ("userFactor" in opts) verifyUserFactor(response.authenticatorData.flags, opts.userFactor);
	if ("origins" in opts) verifyOrigins(response.clientData.origin, opts.origins);
	if ("rpId" in opts) await verifyRpId(response.authenticatorData.rpIdHash, opts.rpId);
	if ("userHandle" in opts) verifyUserHandle(response.userHandle, opts.userHandle);
	if ("signCount" in opts) verifySignCount(response.authenticatorData.signCount, opts.signCount);

	return response;
}

/**
 * @param {Uint8Array | ArrayBuffer} a1
 * @param {Uint8Array | ArrayBuffer} a2
 * @returns {boolean}
 */
function equals(a1, a2) {
	if (a1 instanceof ArrayBuffer) {
		a1 = new Uint8Array(a1);
	}
	if (a2 instanceof ArrayBuffer) {
		a2 = new Uint8Array(a2);
	}
	if ("Buffer" in globalThis) {
		return Buffer.compare(a1, a2) === 0;
	}
	if (a1.byteLength !== a2.byteLength) {
		return false;
	}

	for (let i = 0; i < a1.byteLength; ++i) {
		if (a1[i] !== a2[i]) {
			return false;
		}
	}

	return true;
}

/**
 * @param {Base64URLString} clientChallenge
 * @param {Base64URLString} challenge
 */
function verifyChallenge(clientChallenge, challenge) {
	if (
		challenge !== clientChallenge &&
		!equals(toBuffer(challenge, "challenge"), toBuffer(clientChallenge, "clientData.challenge"))
	) {
		throw new Error(
			`Challenge mismatch, got: ${quoteString(clientChallenge)}, expected: ${quoteString(challenge)}`
		);
	}
}

/**
 * @param {AuthenticatorData['flags']}
 * @param {string} userFactor
 */
function verifyUserFactor({ uv, up }, userFactor) {
	if (userFactor === "either") {
		if (!uv && !up) {
			throw new Error("User was not present nor verified");
		}
	} else if (Array.isArray(userFactor) && userFactor.length > 0) {
		if (!uv && userFactor.includes("verified")) {
			throw new Error("User not present");
		}

		if (!up && userFactor.includes("present")) {
			throw new Error("User not verified");
		}
	} else {
		throw new Error(`userFactor must be an array with at least one element or a string "either"`);
	}
}

/**
 * @param {string} origin
 * @param {string[]} origins
 */
function verifyOrigins(origin, origins) {
	if (!Array.isArray(origins) || origins.length === 0) {
		throw new Error("origins must be an array with at least one element");
	}

	if (!origins.includes(origin)) {
		throw new Error(`Origin ${quoteString(clientData.origin)} not allowed`);
	}
}

/**
 * @param {Uint8Array | Buffer} rpIdHash
 * @param {string} rpId
 */
async function verifyRpId(rpIdHash, rpId) {
	const hash = await crypto.subtle.digest(
		"sha-256",
		Uint8Array.from(rpId, (c) => c.charCodeAt(0))
	);

	if (!equals(hash, rpIdHash)) {
		throw new Error(`rpId hash doesn't match`);
	}
}

/**
 * @param {Uint8Array | Buffer} userHandle
 * @param {Base64URLString | ArrayBuffer | Uint8Array} uh
 */
function verifyUserHandle(userHandle, uh) {
	if (!userHandle) {
		throw new Error("No user handle provided");
	}

	uh = toBuffer(uh, "options.userHandle");

	if (!equals(userHandle, uh)) {
		throw new Error(`userHandle don't match`);
	}
}

/**
 * @param {number} signCount
 * @param {number} counter
 */
function verifySignCount(signCount, counter) {
	if (signCount < counter) {
		throw new Error(`signCount lower than provided, got: ${signCount}, expected: ${counter}`);
	} else if (signCount === counter) {
		throw new Error(`signCount equal to provided`);
	} else if (signCount > counter + 1) {
		throw new Error(`signCount higher than provided+1, got: ${signCount}, expected: ${counter + 1}`);
	}
}

module.exports.attestation = attestation;
module.exports.assertion = assertion;
