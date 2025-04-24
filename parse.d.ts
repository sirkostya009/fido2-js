/**
 * Data that was passed to the authenticator.
 *
 * [MDN Reference](https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorResponse/clientDataJSON)
 */
export interface ClientData {
	type: "webauthn.create" | "webauthn.get";
	challenge: Base64URLString;
	origin: string;
	crossOrigin?: boolean;
	tokenBinding?: {
		status: "supported" | "present";
		id: string;
	};
	topOrigin?: string;
	androidPackageName?: string;
}

export interface JWK {
	kty: "OKP" | "EC" | "RSA";
	crv?: "P-256" | "P-384" | "P-521" | "X25519" | "X448" | "Ed25519" | "Ed448" | "secp256k1";
	alg?: "ES256" | "ES384" | "ES512" | "EdDSA" | "RS256" | "RS384" | "RS512" | "PS512" | "PS384" | "PS256";
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

export interface AttestedCredentialData {
	aaguid: Uint8Array | Buffer;
	credentialIdLength: number;
	credentialId: Uint8Array | Buffer;
	credentialPublicKey: OKP | EC | RSA;
}

/**
 * Data about the authenticator and the public key.
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
	attestedCredentialData?: AttestedCredentialData;
	extensions?: any;
}

export type AttestationResponse =
	| AuthenticatorAttestationResponse
	| {
			clientDataJSON: Base64URLString | Uint8Array;
			attestationObject: Base64URLString | Uint8Array;
	  };

export interface AttestationObject {
	clientData: ClientData & { type: "webauthn.create" };
	attestationObject: {
		fmt: "packed" | "tpm" | "android-key" | "android-safetynet" | "fido-u2f" | "apple" | "none";
		attStmt: any;
		authData: AuthenticatorData & {
			attestedCredentialData: AttestedCredentialData;
		};
	};
	getJWK(): JWK;
}

export type AssertionResponse =
	| AuthenticatorAssertionResponse
	| {
			clientDataJSON: Base64URLString | Uint8Array;
			authenticatorData: Base64URLString | Uint8Array;
			signature: Base64URLString | Uint8Array;
			userHandle?: Base64URLString | Uint8Array | null;
	  };

export interface AssertionObject {
	clientData: ClientData & { type: "webauthn.get" };
	authenticatorData: AuthenticatorData;
	signature: Uint8Array | Buffer;
	userHandle: Uint8Array | Buffer | null;
}

/**
 * Method that parses attestation.
 *
 * @throws {Error} On malformed input or if clientData isn't of type `webauthn.create` or `webauthn.get`
 */
export declare function parse(r: AttestationResponse): AttestationObject;

/**
 * Method that parses assertion responses.
 *
 * @throws {Error} On malformed input or if clientData isn't of type `webauthn.create` or `webauthn.get`
 */
export declare function parse(r: AssertionResponse): AssertionObject;
