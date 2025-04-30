import type { AssertionObject, AttestationObject, COSE, JWK } from "./parse";

export interface VerifyOptions {
	/** The type of client data to verify, "webauthn.create" for attestations and "webauthn.get" for assertions */
	type: "webauthn.create" | "webauthn.get";
	/** Challenge to check for equality in clientData */
	challenge: Base64URLString | ArrayBuffer | Uint8Array;
	/** Array of origins to validate against */
	origins: string[];
	/** Either a COSE, a JWK or a `CryptoKey` object representing the public key */
	publicKey?: COSE | JWK | CryptoKey;
	/** Previous count of performed validation/attestations. */
	counter?: number;
	/** User's factor in authenticator. Checks if the respective flags are set. */
	userFactor?: ("verified" | "present")[] | "either";
	/** User's id as returned by the relying party. */
	userHandle?: Base64URLString | ArrayBuffer | Uint8Array;
	/** Relying party's id as was passed to the authenticator */
	rpId?: string;
}

/**
 * Verified the parsed attestation object.
 *
 * @throws {Error} If one of the provided predicates fail, including verification of the signature
 */
export declare function verify(o: AttestationObject, opts: VerifyOptions & { type: "webauthn.create" }): Promise<void>;

/**
 * Verified the parsed assertion object.
 *
 * @throws {Error} If one of the provided predicates fail, including verification of the signature
 */
export declare function verify(o: AssertionObject, opts: VerifyOptions & { type: "webauthn.get" }): Promise<void>;
