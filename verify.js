import { toBuffer, coseToJwk, getAlgorithmFromKey } from "./utils.js";

/** @import { AssertionObject, AttestationObject, VerifyOptions } from './parse' */

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
 * @param {AssertionObject | AttestationObject} parsed
 * @param {VerifyOptions} options
 * @throws {Error}
 */
export async function verify(
	parsed,
	{ origins, challenge, publicKey, counter, userFactor, userHandle: uh, rpId, type }
) {
	let { clientData, authenticatorData, attestationObject, userHandle, signature } = parsed;

	if (!Array.isArray(origins) || origins.length === 0) {
		throw new Error("'origins' must be an array with at least one element");
	}

	if (!origins.includes(clientData.origin)) {
		throw new Error(`Origin ${clientData.origin} not allowed`);
	}

	challenge = toBuffer(challenge, "options.challenge");

	if (!equals(challenge, toBuffer(clientData.challenge, "response.clientData.challenge"))) {
		throw new Error(`Challenge mismatch, got: ${clientData.challenge}, expected: ${challenge}`);
	}

	if (counter) {
		const { signCount } = authenticatorData || attestationObject.authData;

		if (signCount < counter) {
			throw new Error(`'signCount' lower than provided, got: ${signCount}, expected: ${counter}`);
		} else if (signCount === counter) {
			throw new Error("'signCount' equal to provided");
		} else if (signCount > counter + 1) {
			throw new Error(`'signCount' higher than provided+1, got: ${signCount}, expected: ${counter + 1}`);
		}
	}

	if (userFactor) {
		const { uv, up } = (authenticatorData || attestationObject.authData).flags;

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
			throw new Error("'userFactor' must be an array with at least one element or a string 'either'");
		}
	}

	if (rpId) {
		const { rpIdHash } = authenticatorData || attestationObject.authData;

		const hash = await crypto.subtle.digest(
			"sha-256",
			Uint8Array.from(rpId, (c) => c.charCodeAt(0))
		);

		if (!equals(hash, rpIdHash)) {
			throw new Error("'rpId' hash doesn't match");
		}
	}

	if (clientData.type !== type) {
		throw new Error(`Unexpected client data type, got: ${clientData.type}, expected ${type}`);
	}

	if (clientData.type === "webauthn.get") {
		if (uh) {
			if (!userHandle) {
				throw new Error("No user handle provided");
			}

			userHandle = toBuffer(userHandle, "response.userHandle");
			uh = toBuffer(uh, "options.userHandle");

			if (!equals(userHandle, uh)) {
				throw new Error(`userHandle mismatch, got: ${userHandle}, expected: ${uh}`);
			}
		}

		if (publicKey) {
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
				throw new Error(`Expected publicKey to be CryptoKey-coercible (CryptoKey, COSE, JWK), got: ${key}`);
			}

			if (!signature) {
				throw new Error("No signature provided");
			}
			signature = toBuffer(signature, "response.signature");

			const hash = new Uint8Array(await crypto.subtle.digest("sha-256", parsed.rawClientData));
			const data = new Uint8Array(parsed.rawAuthenticatorData.length + hash.length);
			data.set(parsed.rawAuthenticatorData);
			data.set(hash, parsed.rawAuthenticatorData.length);

			if (!(await crypto.subtle.verify(key.algorithm, key, signature, data))) {
				throw new Error("Signature verification failed");
			}
		}
	} else if (clientData.type === "webauthn.create") {
		switch (attestationObject.fmt) {
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
	}
}
