const { coseToJwk, getAlgorithmFromKey, parse } = require("./parse.js");
const { toBuffer } = require("./utils.js");
/** @import { AuthenticatorData, AssertionResponse, AttestationResponse, AttestationObject, AssertionObject, AssertionOptions, AttestationOptions, FIDO2U2FAttestation } from '../types' */
/** @import { PackedAttestation, TPMAttestation, AndroidKeyAttestation, AndroidSafetyNetAttestation, AppleAttestation, CompoundAttestation } from '../types' */

const quoteString = (s) => (typeof s === "string" ? `"${s}"` : s);

/**
 * Parses and validates attestation responses
 *
 * @param {AttestationResponse} a
 * @param {AttestationOptions} opts
 * @returns {Promise<AttestationObject>}
 * @throws {Error}
 */
async function attestation(a, opts) {
	const { response, rawAuthenticatorData, rawClientData } = parse(a);

	if (response.clientData.type !== "webauthn.create") {
		throw new Error(
			`Invalid client data type, expected: "webauthn.create", got: ${quoteString(response.clientData.type)}`
		);
	}

	verifyChallenge(response.clientData.challenge, opts.challenge);

	await {
		packed: verifyPacked,
		tpm: verifyTpm,
		["android-key"]: verifyAndroidKey,
		["android-safetynet"]: verifyAndroidSafetyNet,
		["fido-u2f"]: verifyFidoU2f,
		none() {},
		apple: verifyApple,
		compound: verifyCompound,
	}[response.attestationObject.fmt](response.attestationObject.attStmt);

	if ("userFactor" in opts) verifyUserFactor(response.attestationObject.authData.flags, opts.userFactor);
	if ("origins" in opts) verifyOrigins(response.clientData.origin, opts.origins);
	if ("rpId" in opts) await verifyRpId(response.attestationObject.authData.rpIdHash, opts.rpId);

	return response;
}

async function verifyPacked(/** @type {PackedAttestation['attStmt']} */ stmt) {}

async function verifyTpm(/** @type {TPMAttestation['attStmt']} */ stmt) {}

async function verifyAndroidKey(/** @type {AndroidKeyAttestation['attStmt']} */ stmt) {}

async function verifyAndroidSafetyNet(/** @type {AndroidSafetyNetAttestation['attStmt']} */ stmt) {}

async function verifyFidoU2f(/** @type {FIDO2U2FAttestation['attStmt']} */ stmt) {}

async function verifyApple(/** @type {AppleAttestation['attStmt']} */ stmt) {}

async function verifyCompound(/** @type {CompoundAttestation['attStmt']} */ stmt) {}

/**
 * Parses and validates assertion responses
 *
 * @param {AssertionResponse} a
 * @param {AssertionOptions} opts
 * @returns {Promise<AssertionObject>}
 * @throws {Error}
 */
async function assertion(a, opts) {
	const { response, rawAuthenticatorData, rawClientData } = parse(a);

	if (response.clientData.type !== "webauthn.get") {
		throw new Error(
			`Invalid client data type, expected: "webauthn.get", got: ${quoteString(response.clientData.type)}`
		);
	}

	verifyChallenge(response.clientData.challenge, opts.challenge);

	let key = opts.publicKey;

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

function verifyChallenge(
	/** @type {Base64URLString} */ clientChallenge,
	/** @type {Base64URLString | Uint8Array} */ challenge
) {
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
		throw new Error(`Origin ${quoteString(origin)} not allowed`);
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

module.exports.attestation = attestation;
module.exports.assertion = assertion;
