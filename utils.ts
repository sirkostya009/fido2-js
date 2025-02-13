import type { EC, JWK, OKP, RSA } from "./verify";

export type base64 = string;

/**
 * @param value buffer-convertible
 * @param valueName value name for better error logging
 * @returns parsed or the very same buffer instance
 */
export function toBuffer(
	value: ArrayBuffer | Uint8Array | base64,
	valueName: string
): Uint8Array | Buffer {
	try {
		return value instanceof ArrayBuffer
			? new Uint8Array(value)
			: value instanceof Uint8Array
			? value
			: "Buffer" in globalThis
			? Buffer.from(value, "base64")
			: Uint8Array.from(atob(base64UrlToBase64(value)), (c) =>
					c.charCodeAt(0)
			  );
	} catch (err) {
		throw new Error(
			valueName +
				" must be either an ArrayBuffer coercible or a base64 string: " +
				// @ts-expect-error
				err.message
		);
	}
}
// @ts-expect-error
const keyTypes: Record<number, JWK["kty"]> = [, "OKP", "EC", "RSA"];
const ellipticCurves: Record<number, JWK["crv"]> = [
	,
	"P-256",
	"P-384",
	"P-521",
	"X25519",
	"X448",
	"Ed25519",
	"Ed448",
	"secp256k1",
];
const algorithms: Record<number, JWK["alg"]> = {
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

/**
 * Converts parsed COSE credentialPublicKey in authenticator data to JWK
 *
 * This is useful if you wish to export the public key to a more portable format
 *
 * You don't need to call this explicitly. You can access the readonly `jwk` property of `credentialPublicKey` in authenticator data
 *
 * @param cose The COSE `credentialPublicKey`
 * @returns The JWK representation of the key
 */
export function coseToJwk(cose: OKP | EC | RSA): JWK {
	const jwk: JWK = {
		kty: keyTypes[cose[1]],
		alg: algorithms[cose[3]],
	};

	// TODO: REWRITE THIS ENTIRE BLOCK TO WORK WITH Uint8Array
	switch (cose[1]) {
		case 2: // EC
			if (cose[-3])
				jwk.y =
					cose[-3] instanceof Uint8Array
						? bufferToBase64Url(cose[-3])
						: cose[-3];
		case 1: // OKP
			jwk.crv = ellipticCurves[cose[-1]];
			if (cose[-2]) jwk.x = bufferToBase64Url(cose[-2]);
			if (cose[-4]) jwk.d = bufferToBase64Url(cose[-4]);
			break;
		case 3: // RSA
			if (cose[-1]) jwk.n = bufferToBase64Url(cose[-1]);
			if (cose[-2]) jwk.e = bufferToBase64Url(cose[-2]);
			if (cose[-3]) jwk.d = bufferToBase64Url(cose[-3]);
			if (cose[-4]) jwk.p = bufferToBase64Url(cose[-4]);
			if (cose[-5]) jwk.q = bufferToBase64Url(cose[-5]);
	}

	return jwk;
}

function bufferToBase64Url(buffer: Buffer | Uint8Array): base64 {
	return "Buffer" in globalThis
		? buffer.toString("base64url")
		: base64ToBase64Url(btoa(String.fromCharCode(...buffer)));
}

export function base64UrlToBase64(string: base64): base64 {
	return (
		string.replace("-", "+").replace("_", "/") +
		"=".repeat(string.length % 4 && 4 - (string.length % 4))
	);
}

export function base64ToBase64Url(string: base64): base64 {
	return string
		.replace("+", "-")
		.replace("/", "_")
		.slice(0, string.length - (string.length % 4));
}

export async function jwkToCryptoKey(jwk: JWK): Promise<CryptoKey> {
	let algorithm:
		| RsaHashedImportParams
		| EcKeyImportParams
		| Algorithm
		| RsaPssParams
		| RsaOaepParams;

	const copy = { ...jwk };

	switch (jwk.kty) {
		case "RSA":
			algorithm = <RsaHashedImportParams>{
				name: "RSASSA-PKCS1-v1_5",
				hash: { name: `SHA-${jwk.alg!.slice(-3)}` },
			};
			break;
		case "OKP":
			algorithm = <Algorithm>{
				name: jwk.crv!,
			};
			break;
		case "EC":
			algorithm = <EcdsaParams>{
				name: "ECDSA",
				hash: { name: `SHA-${jwk.alg!.slice(-3)}` },
				namedCurve: jwk.crv,
			};
			break;
		default:
			throw new Error(`Unsupported key type: ${jwk.kty}`);
	}

	return crypto.subtle.importKey("jwk", copy, algorithm, true, ["verify"]);
}
