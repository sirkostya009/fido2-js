type base64 = string;

type U8Buffer = Uint8Array | Buffer;

type ClientDataType = 'webauthn.create' | 'webauthn.get';

/**
 * Data that was passed to the authenticator
 *
 * [MDN Reference](https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorResponse/clientDataJSON)
 */
export declare interface ClientData {
	type: ClientDataType,
	challenge: base64,
	origin: string,
	crossOrigin?: boolean,
	tokenBinding?: {
		status: 'supported' | 'present',
		id: string,
	},
	topOrigin?: string,
	androidPackageName?: string,
}

export declare interface JWK {
	kty: 'OKP' | 'EC' | 'RSA',
	crv: 'P-256' | 'P-384' | 'P-521' | 'X25519' | 'X448' | 'Ed25519' | 'Ed448',
	alg?: 'ES256' | 'ES384' | 'ES512' | 'EdDSA' | 'RS256' | 'RS384' | 'RS512',
	[k: string]: string | undefined,
}

export declare interface OKP {
	/** Key type */
	[1]: 1,
	/** Algorithm type */
	[3]: -8,
	/** Curvature */
	[-1]: 1 | 2 | 3,
	/** Public key x coordinate */
	[-2]: U8Buffer,
	/** Private key */
	[-3]?: U8Buffer,
}

export declare interface EC {
	/** Key type */
	[1]: 2,
	/** Algorithm type */
	[3]: -7 | -35 | -36,
	/** Curvature */
	[-1]: 1 | 2 | 3,
	/** Public key x coordinate */
	[-2]: U8Buffer,
	/** Public key y coordinate */
	[-3]: U8Buffer,
	/** Private key */
	[-4]?: U8Buffer,
}

export declare interface RSA {
	/** Key type */
	[1]: 3,
	/** Curvature */
	[3]: -257 | -258 | -259,
	/** RSA modulus */
	[-1]: U8Buffer,
	/** RSA public exponent */
	[-2]: U8Buffer,
	/** RSA private exponent */
	[-3]?: U8Buffer,
	/** RSA prime factor p of n */
	[-4]?: U8Buffer,
	/** RSA modulus */
	[-5]?: U8Buffer,
}

/**
 * Data about the authenticator and the public key
 *
 * [MDN Reference](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Authenticator_data)
 */
export declare interface AuthenticatorData {
	rpIdHash: U8Buffer,
	flags: {
		up:   boolean,
		rfu1: boolean,
		uv:   boolean,
		be:   boolean,
		bs:   boolean,
		rfu2: boolean,
		at:   boolean,
		ed:   boolean,
	},
	signCount: number,
	attestedCredentialData?: {
		aaguid: U8Buffer,
		credentialIdLength: number,
		credentialId: U8Buffer,
		credentialPublicKey: OKP | EC | RSA,
	},
	extensions?: any,
}

interface ResponseType<T> {
	response: T & { clientDataJSON: base64 | U8Buffer },
}

export declare type AttestationResponse = ResponseType<{ attestationObject: base64 | U8Buffer }>;

type ParsedResponseType<T extends AssertionResponse | AttestationResponse, S> = Omit<T, 'response'> & {
	response: Omit<T['response'], 'clientDataJSON' | 'authenticatorData' | 'attestationObject'> & S & { clientData: ClientData },
	rawClientData(): U8Buffer,
	rawAuthenticatorData(): U8Buffer,
};

export declare type ParsedAttestationResponse<T extends AttestationResponse> = ParsedResponseType<T, {
	/**
	 * Object containing details about the attestation
	 *
	 * [MDN Reference](https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse/attestationObject)
	 */
	attestationObject: {
		fmt: 'packed' | 'tpm' | 'android-key' | 'android-safetynet' | 'fido-u2f' | 'apple' | 'none',
		attStmt: any,
		authData: AuthenticatorData,
	},
}> & { jwk(): JWK };

export declare type AssertionResponse = ResponseType<{ authenticatorData: base64 | U8Buffer }>;

export declare type ParsedAssertionResponse<T extends AssertionResponse> = ParsedResponseType<T, { authenticatorData: AuthenticatorData }>;

/**
 * Method that parses attestation responses
 *
 * @param t The object to be parsed. ClientDataJSON is expected to be a base64 representation of a JSON-encoded string. If passed as a buffer or a string, the object is expected to be JSON-parseable.
 * @throws On malformed input or if clientData isn't of type `webauthn.create` or `webauthn.get`
 */
export declare function parse<T extends AttestationResponse>(t: T | ArrayBuffer | Uint8Array | string): ParsedAttestationResponse<T>;

/**
 * Method that parses assertion responses
 *
 * @param t The object to be parsed. ClientDataJSON is expected to be a base64 representation of a JSON-encoded string. If passed as a buffer or a string, the object is expected to be JSON-parseable.
 * @throws On malformed input or if clientData isn't of type `webauthn.create` or `webauthn.get`
 */
export declare function parse<T extends AssertionResponse>(t: T | ArrayBuffer | Uint8Array | string): ParsedAssertionResponse<T>;

export declare interface VerifyOptions {
	/** The type of client data to verify, create for attestations and get for assertions */
	type: ClientDataType,
	/** Challenge to check for equality in clientData */
	challenge: base64 | ArrayBuffer | Uint8Array,
	/** Array of origins to validate against */
	origins: string[],
	/** Either a COSE, a JWK or a `CryptoKey` object representing the public key */
	publicKey?: OKP | EC | RSA | JWK | CryptoKey,
	/** Previous count of performed validation/attestations. */
	counter?: number,
	/** User's factor in authenticator. Checks if the respective flag bits are set. */
	userFactor?: ('verified' | 'present')[] | 'either',
	/** User's id as returned by the relying party. */
	userHandle?: base64 | ArrayBuffer | Uint8Array,
	/** Relying party's id as was passed to the authenticator */
	rpId?: string,
}

/**
 * Verifies (validates) assertion and attestation requests
 *
 * Throws on failure
 *
 * @param {ParsedAssertionResponse<unknown> | ParsedAttestationResponse<unknown>} parsed The parsed assertion/attestation response
 * @param options
 * @param {base64 | ArrayBuffer | Uint8Array} options.challenge The challenge to validate. Must be a base64 string. Required
 * @param {string[]} options.origins An array of allowed origins. Required
 * @param {OKP | EC | RSA | JWK | CryptoKey} options.publicKey Pass a public key to validate the signature with it. Use for assertion requests
 * @param {number} options.counter Count of previous attestations/assertions. Currently, not in use
 * @param {('verified' | 'present')[] | 'either'} options.userFactor Test of user verification/presence. Checks the bit 0 and 2 of the flags byte
 * @param {base64 | ArrayBuffer | Uint8Array} options.userHandle Checks for equality of user's id (handle)
 * @param {string} options.rpId Checks if hashed relying party is equal to the hashed provided one
 * @throws Error If one of the provided predicates fail, including verification of the signature
 */
export declare function verify(
	parsed: ParsedAssertionResponse<AssertionResponse> | ParsedAttestationResponse<AttestationResponse>,
	options: VerifyOptions
): Promise<void>;

/**
 * Converts parsed COSE credentialPublicKey in authenticator data to JWK
 *
 * This is useful if you wish to export the public key to a more portable format
 *
 * You don't need to call this explicitly. You can access the readonly `jwk` property of `credentialPublicKey` in authenticator data
 *
 * @param {OKP | EC | RSA} cose The COSE `credentialPublicKey`
 * @returns {JWK} The JWK representation of the key
 */
export declare function coseToJwk(cose: OKP | EC | RSA): JWK;

export declare function toBuffer(data: base64 | ArrayBuffer | Uint8Array): Uint8Array;
