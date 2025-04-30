const { decode, decodeMultiple } = require("cbor-x/decode-no-eval");
const { toBuffer, coseToJwk } = require("./utils.js");

/** @import { ClientData, AuthenticatorData, AssertionResponse, AttestationResponse, AttestationObject } from './parse.js' */

/**
 * @param {Buffer | Uint8Array} buf
 */
function parseAuthenticatorData(buf) {
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

/**
 * @param {AttestationResponse | AssertionResponse} response
 * @returns {AssertionObject | AttestationObject}
 */
function parse(response) {
	const clientDataJSON = response.clientDataJSON;

	/** @type {ClientData} */
	const clientData = JSON.parse(
		"Buffer" in globalThis && clientDataJSON instanceof Buffer
			? clientDataJSON
			: clientDataJSON instanceof Uint8Array
			? String.fromCharCode(...clientDataJSON)
			: clientDataJSON instanceof ArrayBuffer
			? String.fromCharCode(...new Uint8Array(clientDataJSON))
			: typeof clientDataJSON === "string"
			? atob(clientDataJSON)
			: undefined
	);

	switch (clientData.type) {
		case "webauthn.create":
			if (!("attestationObject" in response)) {
				throw new Error(`attestationObject not present on a "webauthn.create" type`);
			}

			const { attestationObject } = response;

			const { fmt, attStmt, authData } = decode(toBuffer(attestationObject, "response.attestationObject"));

			const parsedAuthData = parseAuthenticatorData(authData);

			return Object.defineProperties(
				{
					clientData,
					attestationObject: {
						fmt,
						attStmt,
						authData: parsedAuthData,
					},
					/** @this {AttestationObject} */
					getJWK() {
						return coseToJwk(this.attestationObject.authData.attestedCredentialData.credentialPublicKey);
					},
				},
				{
					rawClientData: {
						value: toBuffer(clientDataJSON),
						configurable: false,
						enumerable: false,
						writable: false,
					},
					rawAuthenticatorData: {
						value: authData,
						configurable: false,
						enumerable: false,
						writable: false,
					},
				}
			);
		case "webauthn.get":
			if (!("authenticatorData" in response)) {
				throw new Error(`authenticatorData not present on a "webauthn.get" type`);
			}

			const { authenticatorData, signature, userHandle } = response;

			return Object.defineProperties(
				{
					clientData,
					authenticatorData: parseAuthenticatorData(
						toBuffer(authenticatorData, "response.authenticatorData")
					),
					signature,
					userHandle,
				},
				{
					rawClientData: {
						value: toBuffer(clientDataJSON),
						configurable: false,
						enumerable: false,
						writable: false,
					},
					rawAuthenticatorData: {
						value: toBuffer(authenticatorData),
						configurable: false,
						enumerable: false,
						writable: false,
					},
				}
			);
		default:
			throw new Error("Unknown clientData type: " + clientData.type);
	}
}

exports.parse = parse;
