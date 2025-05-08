import { getAlgorithmFromKey, parse } from "./parse.js";
import { toBuffer } from "./utils.js";
/** @import { AuthenticatorData, AssertionResponse, AttestationResponse, AttestationObject, AssertionObject, COSE, JWK, AssertionOptions, AttestationOptions } from '../types' */

const quoteString = (s) => (typeof s === "string" ? `"${s}"` : s);

/**
 * Parses and validates attestation responses
 *
 * @returns {Promise<AttestationObject>}
 * @throws {Error}
 */
export async function attestation(/** @type {AttestationResponse} */ a, /** @type {AttestationOptions} */ opts) {
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
 * @returns {Promise<AssertionObject>}
 * @throws {Error}
 */
export async function assertion(/** @type {AssertionResponse} */ a, /** @type {AssertionOptions} */ opts) {
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

function equals(/** @type {Uint8Array | ArrayBuffer} */ a1, /** @type {Uint8Array | ArrayBuffer} */ a2) {
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

function verifyChallenge(/** @type {Base64URLString} */ clientChallenge, /** @type {Base64URLString} */ challenge) {
	if (
		challenge !== clientChallenge &&
		!equals(toBuffer(challenge, "challenge"), toBuffer(clientChallenge, "clientData.challenge"))
	) {
		throw new Error(
			`Challenge mismatch, got: ${quoteString(clientChallenge)}, expected: ${quoteString(challenge)}`
		);
	}
}

function verifyUserFactor(/** @type {AuthenticatorData['flags']} */ { uv, up }, /** @type {string} */ userFactor) {
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

function verifyOrigins(/** @type {string} */ origin, /** @type {string[]} */ origins) {
	if (!Array.isArray(origins) || origins.length === 0) {
		throw new Error("origins must be an array with at least one element");
	}

	if (!origins.includes(origin)) {
		throw new Error(`Origin ${quoteString(clientData.origin)} not allowed`);
	}
}

async function verifyRpId(/** @type {Uint8Array | Buffer} */ rpIdHash, /** @type {string} */ rpId) {
	const hash = await crypto.subtle.digest(
		"sha-256",
		Uint8Array.from(rpId, (c) => c.charCodeAt(0))
	);

	if (!equals(hash, rpIdHash)) {
		throw new Error(`rpId hash doesn't match`);
	}
}

function verifyUserHandle(
	/** @type {Uint8Array | Buffer} */ userHandle,
	/** @type {Base64URLString | ArrayBuffer | Uint8Array} */ uh
) {
	if (!userHandle) {
		throw new Error("No user handle provided");
	}

	uh = toBuffer(uh, "options.userHandle");

	if (!equals(userHandle, uh)) {
		throw new Error(`userHandle don't match`);
	}
}

function verifySignCount(/** @type {number} */ signCount, /** @type {number} */ counter) {
	if (signCount < counter) {
		throw new Error(`signCount lower than provided, got: ${signCount}, expected: ${counter}`);
	} else if (signCount === counter) {
		throw new Error(`signCount equal to provided`);
	} else if (signCount > counter + 1) {
		throw new Error(`signCount higher than provided+1, got: ${signCount}, expected: ${counter + 1}`);
	}
}
