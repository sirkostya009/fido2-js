import type { base64 } from "./utils";
import CBOR = require("cbor-x/decode");
import { toBuffer, coseToJwk } from "./utils";
import type { JWK, OKP, EC, RSA } from "./verify";

export type ClientDataType = "webauthn.create" | "webauthn.get";

/**
 * Data that was passed to the authenticator
 *
 * [MDN Reference](https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorResponse/clientDataJSON)
 */
export interface ClientData {
	type: ClientDataType;
	challenge: base64;
	origin: string;
	crossOrigin?: boolean;
	tokenBinding?: {
		status: "supported" | "present";
		id: string;
	};
	topOrigin?: string;
	androidPackageName?: string;
}

/**
 * Data about the authenticator and the public key
 *
 * [MDN Reference](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Authenticator_data)
 */
export interface AuthenticatorData {
	rpIdHash: Uint8Array | Buffer;
	flags: {
		up: boolean;
		rfu1: boolean;
		uv: boolean;
		be: boolean;
		bs: boolean;
		rfu2: boolean;
		at: boolean;
		ed: boolean;
	};
	signCount: number;
	attestedCredentialData?: {
		aaguid: Uint8Array | Buffer;
		credentialIdLength: number;
		credentialId: Uint8Array | Buffer;
		credentialPublicKey: OKP | EC | RSA;
	};
	extensions?: any;
}

export interface ResponseType<T> {
	response: T & {
		clientDataJSON: base64 | Uint8Array | ArrayBuffer | Buffer;
	};
}

export type AttestationResponse = ResponseType<{
	attestationObject: base64 | Uint8Array | ArrayBuffer | Buffer;
}>;

export type ParsedResponseType<
	T extends AssertionResponse | AttestationResponse,
	S
> = Omit<T, "response"> & {
	response: Omit<
		T["response"],
		"clientDataJSON" | "authenticatorData" | "attestationObject"
	> &
		S & {
			clientData: ClientData;
		};
	rawClientData(): Uint8Array | Buffer;
	rawAuthenticatorData(): Uint8Array | Buffer;
};

export type ParsedAttestationResponse<T extends AttestationResponse> =
	ParsedResponseType<
		T,
		{
			/**
			 * Object containing details about the attestation
			 *
			 * [MDN Reference](https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse/attestationObject)
			 */
			attestationObject: {
				fmt:
					| "packed"
					| "tpm"
					| "android-key"
					| "android-safetynet"
					| "fido-u2f"
					| "apple"
					| "none";
				attStmt: any;
				authData: AuthenticatorData;
			};
		}
	> & { jwk(): JWK };

export type AssertionResponse = ResponseType<{
	authenticatorData: base64 | Uint8Array | ArrayBuffer | Buffer;
}>;

export type ParsedAssertionResponse<T extends AssertionResponse> =
	ParsedResponseType<T, { authenticatorData: AuthenticatorData }>;

function parseAuthenticatorData(buf: Buffer | Uint8Array): AuthenticatorData {
	const result: AuthenticatorData = {
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

	let decoded: any[] | any;
	if (result.flags.at) {
		const credentialIdLength = (buf[53] << 8) | buf[54];
		const subarray = buf.subarray(55 + credentialIdLength);

		result.attestedCredentialData = {
			aaguid: buf.subarray(37, 37 + 16),
			credentialIdLength,
			credentialId: buf.subarray(55, 55 + credentialIdLength),
			credentialPublicKey: result.flags.ed
				? (decoded = CBOR.decodeMultiple(subarray) as any[])[0]
				: CBOR.decode(subarray),
		};
	}

	if (result.flags.ed) {
		result.extensions = result.flags.at
			? decoded[1]
			: CBOR.decode(buf.subarray(37));
	}

	return result;
}

/**
 * Method that parses attestation responses
 *
 * @param obj The object to be parsed. `clientDataJSON` is expected to be a base64 representation of a JSON-encoded string or a buffer
 * @throws {Error} On malformed input or if clientData isn't equal to `webauthn.create`
 */
// @ts-expect-error i hate typescript
export declare function parse<T extends AttestationResponse>(
	obj: T
): ParsedAttestationResponse<T>;

/**
 * Method that parses assertion responses
 *
 * @param obj The object to be parsed. `clientDataJSON` is expected to be a base64 representation of a JSON-encoded string or a buffer
 * @throws {Error} On malformed input or if clientData isn't equal to `webauthn.get`
 */
// @ts-expect-error i hate typescript
export declare function parse<T extends AssertionResponse>(
	obj: T
): ParsedAssertionResponse<T>;

/**
 * Method that parses attestation and assertion responses
 *
 * @param obj The object to be parsed. ClientDataJSON is expected to be a base64 representation of a JSON-encoded string.
 * @throws {Error} On malformed input or if clientData isn't of type `webauthn.create` or `webauthn.get`
 */
export function parse<T extends AttestationResponse | AssertionResponse>(
	obj: T
): T extends AttestationResponse
	? ParsedAttestationResponse<T>
	: T extends AssertionResponse
	? ParsedAssertionResponse<T>
	: never {
	if (!obj || typeof obj !== "object") {
		throw new Error("Cannot parse " + obj);
	}

	const {
		response: {
			// @ts-expect-error
			attestationObject,
			clientDataJSON,
			// @ts-expect-error
			authenticatorData,
			...response
		},
		...rest
	} = obj;

	const clientData = JSON.parse(
		// @ts-expect-error Buffer is JSON-parseable by Node.js
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
			const { fmt, attStmt, authData } = CBOR.decode(
				toBuffer(attestationObject, "response.attestationObject")
			);

			const parsedAuthData = parseAuthenticatorData(authData);

			// @ts-expect-error
			return <ParsedAttestationResponse<T>>{
				...rest,
				response: {
					...response,
					clientData,
					attestationObject: {
						fmt,
						attStmt,
						authData: parsedAuthData,
					},
				},
				rawClientData() {
					return toBuffer(clientDataJSON, "clientDataJSON");
				},
				rawAuthenticatorData() {
					return CBOR.decode(
						toBuffer(attestationObject, "attestationObject")
					).authData;
				},
				jwk() {
					// @ts-expect-error
					return coseToJwk(parsedAuthData.attestedCredentialData);
				},
			};
		case "webauthn.get":
			// @ts-expect-error
			return <ParsedAssertionResponse<T>>{
				...rest,
				response: {
					...response,
					clientData,
					authenticatorData: parseAuthenticatorData(
						toBuffer(
							authenticatorData,
							"response.authenticatorData"
						)
					),
				},
				rawAuthenticatorData() {
					return toBuffer(authenticatorData, "authenticatorData");
				},
				rawClientData() {
					return toBuffer(clientDataJSON, "clientDataJSON");
				},
			};
		default:
			throw new Error("Unknown clientData type: " + clientData.type);
	}
}
