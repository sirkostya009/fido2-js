import { decode, decodeMultiple } from "cbor-x/decode-no-eval";
import { base64ToJSON, bufferToBase64Url, toBuffer } from "./utils.js";
/** @import { ClientData, AuthenticatorData, AssertionResponse, AttestationResponse, AssertionObject, AttestationObject, COSE, JWK } from '../types.js' */

/**
 * Parsing function used by `assertion` and `attestation` functions.
 *
 * This is great for playing and figuring out with WebAuthn, in production codebases use the two aforementioned alternatives as they also do verification.
 *
 * @param {AttestationResponse | AssertionResponse} response
 * @returns {{ response: AssertionObject | AttestationObject, rawClientData: Uint8Array | Buffer, rawAuthenticatorData: Uint8Array | Buffer }}
 * @throws {Error}
 */
export function parse(response) {
	const clientDataJSON = response.clientDataJSON;

	/** @type {ClientData} */
	const clientData = JSON.parse(base64ToJSON(clientDataJSON));

	switch (clientData.type) {
		case "webauthn.create":
			if (!("attestationObject" in response)) {
				throw new Error(`attestationObject not present on a "webauthn.create" type`);
			}

			const { attestationObject } = response;

			const { fmt, attStmt, authData } = decode(toBuffer(attestationObject, "response.attestationObject"));

			const parsedAuthData = parseAuthenticatorData(authData);

			return {
				response: {
					clientData,
					attestationObject: {
						fmt,
						attStmt,
						authData: parsedAuthData,
					},
					/** @this {AttestationObject} */
					jwk() {
						return coseToJwk(this.attestationObject.authData.attestedCredentialData.credentialPublicKey);
					},
				},
				rawClientData: toBuffer(clientDataJSON),
				rawAuthenticatorData: authData,
			};
		case "webauthn.get":
			if (!("authenticatorData" in response)) {
				throw new Error(`authenticatorData not present on a "webauthn.get" type`);
			}

			const { authenticatorData, signature, userHandle } = response;
			const rawAuthenticatorData = toBuffer(authenticatorData, "response.authenticatorData");

			return {
				response: {
					clientData,
					authenticatorData: parseAuthenticatorData(rawAuthenticatorData),
					signature: toBuffer(signature),
					userHandle: toBuffer(userHandle),
				},
				rawClientData: toBuffer(clientDataJSON),
				rawAuthenticatorData,
			};
		default:
			throw new Error("Unknown clientData type: " + clientData.type);
	}
}

export default parse;

/**
 * Converts parsed COSE credentialPublicKey in authenticator data to JWK
 *
 * This is useful if you wish to export the public key to a more portable format
 *
 * You don't need to call this explicitly. You can access the readonly `jwk` property of `credentialPublicKey` in authenticator data
 *
 * @param {COSE} cose The COSE `credentialPublicKey`
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
			jwk.y = cose[-3] instanceof Uint8Array ? bufferToBase64Url(cose[-3]) : cose[-3];
		case 1: // OKP
			jwk.crv = ellipticCurves[cose[-1]];
			jwk.x = bufferToBase64Url(cose[-2]);
			if (cose[-4]) jwk.d = bufferToBase64Url(cose[-4]);
			break;
		case 3: // RSA
			jwk.n = bufferToBase64Url(cose[-1]);
			jwk.e = bufferToBase64Url(cose[-2]);
			if (cose[-3]) jwk.d = bufferToBase64Url(cose[-3]);
			if (cose[-4]) jwk.p = bufferToBase64Url(cose[-4]);
			if (cose[-5]) jwk.q = bufferToBase64Url(cose[-5]);
	}

	return jwk;
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
 * @returns {Algorithm}
 * @throws {Error} On unsupported key type
 */
export function getAlgorithmFromKey(/** @type {JWK} */ jwk) {
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

function parseAuthenticatorData(/** @type {Buffer | Uint8Array} */ buf) {
	/** @type {AuthenticatorData} */
	const result = {
		rpIdHash: buf.subarray(0, 32),
		flags: {
			up: !!(buf[32] & 1),
			rfu1: !!(buf[32] & (1 << 1)),
			uv: !!(buf[32] & (1 << 2)),
			be: !!(buf[32] & (1 << 3)),
			bs: !!(buf[32] & (1 << 4)),
			rfu2: !!(buf[32] & (1 << 5)),
			at: !!(buf[32] & (1 << 6)),
			ed: !!(buf[32] & (1 << 7)),
		},
		signCount: (buf[33] << 24) | (buf[34] << 16) | (buf[35] << 8) | buf[36],
	};

	/** @type {any[] | any} */
	let decoded;
	if (result.flags.at) {
		const credentialIdLength = (buf[53] << 8) | buf[54];
		const subarray = buf.subarray(55 + credentialIdLength);

		result.attestedCredentialData = {
			aaguid: buf.subarray(37, 37 + 16),
			credentialIdLength,
			credentialId: buf.subarray(55, 55 + credentialIdLength),
			credentialPublicKey: result.flags.ed ? (decoded = decodeMultiple(subarray))[0] : decode(subarray),
		};
	}

	if (result.flags.ed) {
		result.extensions = result.flags.at ? decoded[1] : decode(buf.subarray(37));
	}

	return result;
}
