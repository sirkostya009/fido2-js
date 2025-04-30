import { test } from "node:test";
import { parse, verify } from "../esm/index.js";

test("main", async function () {
	const attestation = parse({
		clientDataJSON:
			"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVzI5aWFtVmpkQ0JCY25KaGVVSjFabVpsY2wwIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo1NTAwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0=",
		attestationObject:
			"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAAiYcFjK3EuBtuEw3lDcvpYAIKaanj9Z2nDjOcbFgTKWEUD3fq6eMdQ0V0bUN2MnIy68pQECAyYgASFYIGsGWLc2e2gCyX8yBAxgiOggYaajnziK1bpE9YE+mxbMIlgg1xFrTD6P8ay6qqacucmycMH4lLqw8qneqwcoNTVVsrY=",
	});

	console.log("attestation", attestation);

	await verify(attestation, {
		type: "webauthn.create",
		challenge: "W29iamVjdCBBcnJheUJ1ZmZlcl0=",
		origins: ["http://localhost:5500"],
		userFactor: ["verified", "present"],
	});

	const assertion = parse({
		clientDataJSON:
			"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiVzI5aWFtVmpkQ0JCY25KaGVVSjFabVpsY2wwIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo1NTAwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0=",
		authenticatorData: "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MFAAAAAg==",
		signature: "MEUCIQCSRurZwBUIbSBFQmLPBnGJLPcFLnf6EyIML/D54AGFlAIgag1hkkxK1ZBtRP7+AyaiYbkpms05G5VKfh9eQDYQ+XU=",
		userHandle: "BA==",
	});

	console.log("assertion", assertion);

	await verify(assertion, {
		type: "webauthn.get",
		challenge: "W29iamVjdCBBcnJheUJ1ZmZlcl0=",
		origins: ["http://localhost:5500"],
		publicKey: attestation.attestationObject.authData.attestedCredentialData.credentialPublicKey,
		counter: 0,
		userFactor: ["verified", "present"],
		userHandle: "BA==",
		rpId: "localhost",
	});
});
