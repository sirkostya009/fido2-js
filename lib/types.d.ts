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

export type JWK =
	| {
			kty: "OKP";
			crv: "X25519" | "X448" | "Ed25519" | "Ed448";
			alg: "EdDSA" | "PS256" | "PS384" | "PS512";
			x: Base64URLString;
			d?: Base64URLString;
	  }
	| {
			kty: "EC";
			crv: "P-256" | "P-384" | "P-521" | "secp256k1";
			alg: "ES256" | "ES384" | "ES512";
			x: Base64URLString;
			y: Base64URLString;
			d?: Base64URLString;
	  }
	| {
			kty: "RSA";
			alg: "RS256" | "RS384" | "RS512";
			n: Base64URLString;
			e: Base64URLString;
			d?: Base64URLString;
			p?: Base64URLString;
			q?: Base64URLString;
	  };

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

export type COSE = OKP | EC | RSA;

export interface AttestedCredentialData {
	aaguid: Uint8Array | Buffer;
	credentialIdLength: number;
	credentialId: Uint8Array | Buffer;
	credentialPublicKey: COSE;
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

export interface PackedAttestation {
	fmt: "packed";
	attStmt: {
		alg: number;
		sig: Uint8Array;
		x5c: [Uint8Array, ...Uint8Array[]] | [];
	};
}

export interface TPMAttestation {
	fmt: "tpm";
	attStmt: {
		ver: "2.0";
		alg?: number;
		x5c?: [Uint8Array, ...Uint8Array[]] | [];
		sig: Uint8Array;
		certInfo: Uint8Array;
		pubArea: Uint8Array;
	};
}

export interface AndroidKeyAttestation {
	fmt: "android-key";
	attStmt: {
		alg: number;
		sig: Uint8Array;
		x5c: [Uint8Array, ...Uint8Array[]] | [];
	};
}

export interface AndroidSafetyNetAttestation {
	fmt: "android-safetynet";
	attStmt: {
		ver: string;
		response: Uint8Array;
	};
}

export interface FIDO2U2FAttestation {
	fmt: "fido-u2f";
	attStmt: {
		x5c: [Uint8Array];
		sig: Uint8Array;
	};
}

export interface NoneAttestation {
	fmt: "none";
	attStmt: {};
}

export interface AppleAttestation {
	fmt: "apple";
	attStmt: {
		x5c: [Uint8Array, ...Uint8Array[]];
	};
}

export interface CompoundAttestation {
	fmt: "compound";
	attStmt: (CompoundAttestation & { fmt: Exclude<string, "compound">; [k: string]: any })[];
}

export interface AttestationObject<
	Attestation =
		| PackedAttestation
		| TPMAttestation
		| AndroidKeyAttestation
		| AndroidSafetyNetAttestation
		| FIDO2U2FAttestation
		| NoneAttestation
		| AppleAttestation
		| CompoundAttestation,
> {
	clientData: ClientData & { type: "webauthn.create" };
	attestationObject: Attestation & {
		authData: AuthenticatorData & {
			attestedCredentialData: AttestedCredentialData;
		};
	};
	jwk(): JWK;
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

export interface AttestationOptions {
	/** The challenge used for attestation/assertion */
	challenge: Base64URLString | Uint8Array;
	/** Array of origins to validate against */
	origins?: string[];
	/** User's factor in authenticator. Checks if the respective flags are set. */
	userFactor?: ("verified" | "present")[] | "either";
	/** Relying party's id as was passed to the authenticator */
	rpId?: string;
}

export interface AssertionOptions extends AttestationOptions {
	/** Public key acquired from attestation */
	publicKey: COSE | JWK | CryptoKey;
	/** Previous count of performed validation/attestations. */
	signCount?: number;
	/** User's id as returned by the relying party. */
	userHandle?: Base64URLString | ArrayBuffer | Uint8Array;
}
