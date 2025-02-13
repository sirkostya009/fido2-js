import type {
	AssertionResponse,
	AttestationResponse,
	ClientDataType,
	ParsedAssertionResponse,
	ParsedAttestationResponse,
} from "./parse";
import { toBuffer, coseToJwk, type base64, jwkToCryptoKey } from "./utils";

export interface JWK {
	kty: "OKP" | "EC" | "RSA";
	crv?:
		| "P-256"
		| "P-384"
		| "P-521"
		| "X25519"
		| "X448"
		| "Ed25519"
		| "Ed448"
		| "secp256k1";
	alg?:
		| "ES256"
		| "ES384"
		| "ES512"
		| "EdDSA"
		| "RS256"
		| "RS384"
		| "RS512"
		| "PS512"
		| "PS384"
		| "PS256";
	[k: string]: string | undefined;
}

export interface OKP {
	/** Key type */
	[1]: 1;
	/** Algorithm type */
	[3]: -8;
	/** Curvature */
	[-1]: 1 | 2 | 3;
	/** Public key x coordinate */
	[-2]: Uint8Array | Buffer;
	/** Private key */
	[-3]?: Uint8Array | Buffer;
}

export interface EC {
	/** Key type */
	[1]: 2;
	/** Algorithm type */
	[3]: -7 | -35 | -36;
	/** Curvature */
	[-1]: 1 | 2 | 3;
	/** Public key x coordinate */
	[-2]: Uint8Array | Buffer;
	/** Public key y coordinate */
	[-3]: Uint8Array | Buffer;
	/** Private key */
	[-4]?: Uint8Array | Buffer;
}

export interface RSA {
	/** Key type */
	[1]: 3;
	/** Curvature */
	[3]: -257 | -258 | -259;
	/** RSA modulus */
	[-1]: Uint8Array | Buffer;
	/** RSA public exponent */
	[-2]: Uint8Array | Buffer;
	/** RSA private exponent */
	[-3]?: Uint8Array | Buffer;
	/** RSA prime factor p of n */
	[-4]?: Uint8Array | Buffer;
	/** RSA modulus */
	[-5]?: Uint8Array | Buffer;
}

function equals(a1: Uint8Array | ArrayBuffer, a2: Uint8Array | ArrayBuffer) {
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
		// @ts-expect-error
		if (a1[i] !== a2[i]) {
			return false;
		}
	}

	return true;
}

export interface VerifyOptions {
	/** The type of client data to verify, create for attestations and get for assertions */
	type: ClientDataType;
	/** Challenge to check for equality in clientData */
	challenge: base64 | ArrayBuffer | Uint8Array;
	/** Array of origins to validate against */
	origins: string[];
	/** Either a COSE, a JWK or a `CryptoKey` object representing the public key */
	publicKey?: OKP | EC | RSA | JWK | CryptoKey;
	/** Previous count of performed validation/attestations. */
	counter?: number;
	/** User's factor in authenticator. Checks if the respective flag bits are set. */
	userFactor?: ("verified" | "present")[] | "either";
	/** User's id as returned by the relying party. */
	userHandle?: base64 | ArrayBuffer | Uint8Array;
	/** Relying party's id as was passed to the authenticator */
	rpId?: string;
}

/**
 * Verifies (validates) assertion and attestation requests
 *
 * Throws on failure
 *
 * @param parsed The parsed assertion/attestation response
 * @param options
 * @param options.challenge The challenge to validate. Must be a base64 string. Required
 * @param options.origins An array of allowed origins. Required
 * @param options.publicKey Pass a public key to validate the signature with it. Use for assertion requests
 * @param options.counter Count of previous attestations/assertions. Currently, not in use
 * @param options.userFactor Test of user verification/presence. Checks the bit 0 and 2 of the flags byte
 * @param options.userHandle Checks for equality of user's id (handle)
 * @param options.rpId Checks if hashed relying party is equal to the hashed provided one
 * @throws {Error} If one of the provided predicates fail, including verification of the signature
 */
export async function verify<T extends AssertionResponse | AttestationResponse>(
	{
		response: {
			clientData,
			// @ts-expect-error
			authenticatorData,
			// @ts-expect-error
			attestationObject,
			// @ts-expect-error
			userHandle,
			// @ts-expect-error
			signature,
		},
		rawClientData,
		rawAuthenticatorData,
	}: // @ts-expect-error
	ParsedAssertionResponse<T> | ParsedAttestationResponse<T>,
	{
		origins,
		challenge,
		publicKey,
		counter,
		userFactor,
		userHandle: uh,
		rpId,
		type,
	}: VerifyOptions
) {
	if (!Array.isArray(origins) || origins.length === 0) {
		throw new Error("'origins' must be an array with at least one element");
	}

	if (!origins.includes(clientData.origin)) {
		throw new Error(`Origin ${clientData.origin} not allowed`);
	}

	challenge = toBuffer(challenge, "options.challenge");

	if (
		!equals(
			challenge,
			toBuffer(
				clientData.challenge,
				"parsed.response.clientData.challenge"
			)
		)
	) {
		throw new Error(
			`Challenge mismatch, got: ${clientData.challenge}, expected: ${challenge}`
		);
	}

	if (counter) {
		const { signCount } = authenticatorData || attestationObject.authData;

		if (signCount < counter) {
			throw new Error(
				`'signCount' lower than provided, got: ${signCount}, expected: ${counter}`
			);
		} else if (signCount === counter) {
			throw new Error("'signCount' equal to provided");
		} else if (signCount > counter + 1) {
			throw new Error(
				`'signCount' higher than provided+1, got: ${signCount}, expected: ${
					counter + 1
				}`
			);
		}
	}

	if (userFactor) {
		const { uv, up } = (authenticatorData || attestationObject.authData)
			.flags;

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
			throw new Error(
				"'userFactor' must be an array with at least one element or a string 'either'"
			);
		}
	}

	if (clientData.type !== type) {
		throw new Error(
			`Unexpected client data type, got: ${clientData.type}, expected ${type}`
		);
	}

	if (clientData.type === "webauthn.get") {
		if (uh) {
			if (!userHandle) {
				throw new Error("No user handle provided");
			}

			userHandle = toBuffer(userHandle, "parsed.response.userHandle");
			uh = toBuffer(uh, "options.userHandle");

			if (!equals(userHandle, uh)) {
				throw new Error(
					`userHandle mismatch, got: ${userHandle}, expected: ${uh}`
				);
			}
		}

		if (publicKey) {
			let key = publicKey;

			if ("1" in key) {
				key = coseToJwk(key as EC | OKP | RSA);
			}
			if ("kty" in key) {
				key = await jwkToCryptoKey(key);
			}
			if (!(key instanceof CryptoKey)) {
				throw new Error(
					`Expected publicKey to be CryptoKey-coercible (CryptoKey, COSE, JWK), got: ${key}`
				);
			}

			if (!signature) {
				throw new Error("No signature provided");
			}
			signature = toBuffer(signature, "parsed.response.signature");

			if (
				typeof rawClientData !== "function" ||
				typeof rawAuthenticatorData !== "function"
			) {
				throw new Error(
					`Expected rawClientData, rawAuthenticatorData to be functions, got: ${rawClientData}, ${rawAuthenticatorData}, respectively`
				);
			}

			const rawAuthData = rawAuthenticatorData();
			const hash = new Uint8Array(
				await crypto.subtle.digest("sha-256", rawClientData())
			);
			const data = new Uint8Array(rawAuthData.length + hash.length);
			data.set(rawAuthData);
			data.set(hash, rawAuthData.length);

			console.log("rawAuthData", rawAuthData);
			console.log("hash", hash);
			console.log("data", data);
			const algorithm =
				key.algorithm.name === "ECDSA"
					? {
							...key.algorithm,
							hash: {
								// @ts-expect-error
								name: `SHA-${key.algorithm.namedCurve.slice(
									-3
								)}`,
							},
					  }
					: key.algorithm;
			if (
				!(await crypto.subtle.verify(algorithm, key, signature, data))
			) {
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
			case "none": // yeah no todo here
				break;
			case "apple": // TODO: https://www.w3.org/TR/webauthn-2/#sctn-apple-anonymous-attestation
				break;
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
}
