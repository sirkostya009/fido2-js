import { X509Certificate } from "@peculiar/x509";
import { coseToJwk, getAlgorithmFromKey, parse } from "./parse.js";
import { base64ToJSON, bufferToBase64Url, toBuffer } from "./utils.js";
/** @import { AuthenticatorData, AssertionResponse, AttestationResponse, AttestationObject, AssertionObject, AssertionOptions, AttestationOptions, FIDO2U2FAttestation, AttestedCredentialData, JWK } from '../types' */
/** @import { PackedAttestation, TPMAttestation, AndroidKeyAttestation, AndroidSafetyNetAttestation, AppleAttestation, CompoundAttestation } from '../types' */

const quoteString = (s) => (typeof s === "string" ? `"${s}"` : s);

const verifiers = {
	packed: verifyPacked,
	tpm: verifyTpm,
	["android-key"]: verifyAndroidKey,
	["android-safetynet"]: verifyAndroidSafetyNet,
	["fido-u2f"]: verifyFidoU2f,
	none() {},
	apple: verifyApple,
	compound: verifyCompound,
};

/**
 * Parses and validates attestation responses
 *
 * @param {AttestationResponse} a
 * @param {AttestationOptions} opts
 * @returns {Promise<AttestationObject>}
 * @throws {Error}
 */
export async function attestation(a, opts) {
	const { response, rawAuthenticatorData, rawClientData } = parse(a);

	if (response.clientData.type !== "webauthn.create") {
		throw new Error(
			`Invalid client data type, expected: "webauthn.create", got: ${quoteString(response.clientData.type)}`
		);
	}

	verifyChallenge(response.clientData.challenge, opts.challenge);

	try {
		await verifiers[response.attestationObject.fmt](response, rawAuthenticatorData, rawClientData);
	} catch (cause) {
		throw new Error(`Failed to verify ${quoteString(response.attestationObject.fmt)} attestation format`, {
			cause,
		});
	}

	if ("userFactor" in opts) verifyUserFactor(response.attestationObject.authData.flags, opts.userFactor);
	if ("origins" in opts) verifyOrigins(response.clientData.origin, opts.origins);
	if ("rpId" in opts) await verifyRpId(response.attestationObject.authData.rpIdHash, opts.rpId);

	return response;
}

async function signeeData(/** @type {Uint8Array} */ rawAuthenticatorData, /** @type {Uint8Array} */ rawClientData) {
	const hash = new Uint8Array(await crypto.subtle.digest("sha-256", rawClientData));
	const data = new Uint8Array(rawAuthenticatorData.length + hash.length);
	data.set(rawAuthenticatorData);
	data.set(hash, rawAuthenticatorData.length);
	return data;
}

async function coerceCryptoKey(/** @type {AttestedCredentialData['credentialPublicKey'] | JWK | CryptoKey} */ key) {
	if ("1" in key) {
		key = coseToJwk(key);
	}
	if ("kty" in key) {
		return Object.defineProperty(
			await crypto.subtle.importKey("jwk", key, getAlgorithmFromKey(key), true, ["verify"]),
			"algorithm",
			{
				value: getAlgorithmFromKey(key),
			}
		);
	}
	return key;
}

async function verifyPacked(
	/** @type {AttestationObject<PackedAttestation>} */ {
		attestationObject: {
			attStmt,
			authData: {
				attestedCredentialData: { credentialPublicKey },
			},
		},
	},
	/** @type {Uint8Array} */ rawAuth,
	/** @type {Uint8Array} */ rawClient
) {
	/** @type {CryptoKey} */
	let key;
	if (!("x5c" in attStmt) || !attStmt.x5c.length) {
		if (credentialPublicKey[3] !== attStmt.alg) {
			throw new Error(
				`Base packed attestation signature algorithm mismatch, got: ${quoteString(
					attStmt.alg
				)}, expected: ${quoteString(credentialPublicKey[3])}`
			);
		}
		key = coerceCryptoKey(credentialPublicKey);
	} else {
		key = await new X509Certificate(attStmt.x5c[0]).publicKey.export();
	}

	const data = await signeeData(rawAuth, rawClient);

	if (!(await crypto.subtle.verify(key.algorithm, key, attStmt.sig, data))) {
		throw new Error("Packed attestation verification failed");
	}
}

async function verifyTpm(
	/** @type {AttestationObject<TPMAttestation>} */ { attestationObject: { attStmt } },
	/** @type {Uint8Array} */ rawAuth,
	/** @type {Uint8Array} */ rawClient
) {
	if ("2.0" !== attStmt.ver) {
		throw new Error(`TPM attestation ver is not "2.0"`);
	}
}

async function verifyAndroidKey(
	/** @type {AttestationObject<AndroidKeyAttestation>} */ { attestationObject: { attStmt } },
	/** @type {Uint8Array} */ rawAuth,
	/** @type {Uint8Array} */ rawClient
) {
	const key = await new X509Certificate(attStmt.x5c[0]).publicKey.export();

	const data = await signeeData(rawAuth, rawClient);
	if (!(await crypto.subtle.verify(key.algorithm, key, attStmt.sig, data))) {
		throw new Error("Android Key attestation signature verification failed");
	}
}

async function verifyAndroidSafetyNet(
	/** @type {AttestationObject<AndroidSafetyNetAttestation>} */ { attestationObject: { attStmt } },
	/** @type {Uint8Array} */ rawAuth,
	/** @type {Uint8Array} */ rawClient
) {
	if (!attStmt.response) {
		throw new Error("Android SafetyNet attestation missing response");
	}

	const jws = new TextDecoder().decode(attStmt.response);
	const [_header, _payload, _signature] = jws.split(".");
	if (!_header || !_payload || !_signature) {
		throw new Error("Invalid SafetyNet JWS format");
	}

	const payload = JSON.parse(base64ToJSON(_payload));
	const data = await signeeData(rawAuth, rawClient);
	const hash = new Uint8Array(await crypto.subtle.digest("sha-256", data));
	const expectedNonce = bufferToBase64Url(hash);

	if (payload.nonce !== expectedNonce) {
		throw new Error("SafetyNet nonce mismatch");
	}

	if (!payload.ctsProfileMatch) {
		throw new Error("SafetyNet ctsProfileMatch is false");
	}

	const header = JSON.parse(base64ToJSON(_header));
	const signedData = jws.substring(0, jws.lastIndexOf("."));
	const signature = toBuffer(_signature);
	const certKey = await new X509Certificate(header.x5c[0]).publicKey.export();

	if (
		!(await crypto.subtle.verify(
			header.alg,
			certKey,
			signature,
			Uint8Array.from(signedData, (s) => s.charCodeAt(0))
		))
	) {
		throw new Error(`Android SafetyNet attestation verification failed`);
	}
}

async function verifyFidoU2f(
	/** @type {AttestationObject<FIDO2U2FAttestation>} */ {
		attestationObject: {
			attStmt,
			authData: {
				attestedCredentialData: { credentialId, credentialIdLength, credentialPublicKey },
				rpIdHash,
			},
		},
	},
	/** @type {Uint8Array} */ rawAuth,
	/** @type {Uint8Array} */ rawClient
) {
	const signedData = new Uint8Array(
		1 +
			rpIdHash.length +
			32 +
			credentialIdLength +
			1 +
			credentialPublicKey["-2"].length +
			credentialPublicKey["-3"].length
	);

	signedData.set(rpIdHash, 1);
	signedData.set(await crypto.subtle.digest("sha-256", rawClient), 1 + rpIdHash.length);
	signedData.set(credentialId, 33 + rpIdHash.length);
	signedData.set(0x04, 33 + rpIdHash.length + credentialIdLength);
	signedData.set(credentialPublicKey["-2"], 34 + rpIdHash.length + credentialIdLength);
	signedData.set(
		credentialPublicKey["-3"],
		34 + rpIdHash.length + credentialIdLength + credentialPublicKey["-2"].length
	);

	const cert = new X509Certificate(attStmt.x5c[0]);

	if (!(await crypto.subtle.verify(cert.signatureAlgorithm, cert.publicKey.export(), attStmt.sig, signedData))) {
		throw new Error(`Fido U2F attestation verification failed`);
	}
}

async function verifyApple(
	/** @type {AttestationObject<AppleAttestation>} */ { attestationObject: { attStmt } },
	/** @type {Uint8Array} */ rawAuth,
	/** @type {Uint8Array} */ rawClient
) {
	const cert = new X509Certificate(attStmt.x5c[0]);
	const data = await signeeData(rawAuth, rawClient);

	if (!(await crypto.subtle.verify(cert.signatureAlgorithm, cert.publicKey.export(), attStmt.sig, data))) {
		throw new Error("Apple attestation signature verification failed");
	}
}

async function verifyCompound(
	/** @type {AttestationObject<CompoundAttestation>} */ response,
	/** @type {Uint8Array} */ rawAuth,
	/** @type {Uint8Array} */ rawClient
) {
	let copy = {
		...response,
		attestationObject: { ...response.attestationObject, attStmt: undefined, fmt: undefined },
	};
	try {
		for (const stmt of response.attestationObject.attStmt) {
			Object.assign(copy.attestationObject, stmt);
			await verifiers[stmt.fmt](copy, rawAuth, rawClient);
		}
	} catch (cause) {
		throw new Error(`Compound attestation verification failed`, { cause });
	}
}

/**
 * Parses and validates assertion responses
 *
 * @param {AssertionResponse} a
 * @param {AssertionOptions} opts
 * @returns {Promise<AssertionObject>}
 * @throws {Error}
 */
export async function assertion(a, opts) {
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

	const data = await signeeData(rawAuthenticatorData, rawClientData);

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
