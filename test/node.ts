import { test } from "node:test";
import * as fido from "../lib/index.js";

test("main", async function () {
	const attestation = await fido.attestation(
		{
			authenticatorAttachment: "cross-platform",
			clientExtensionResults: {},
			id: "85aZFgJgAy5RX3yVcs8D9A",
			rawId: "85aZFgJgAy5RX3yVcs8D9A",
			response: {
				attestationObject:
					"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAOqbjWZNAR0hPOS2tIy1ddQAEPOWmRYCYAMuUV98lXLPA_SlAQIDJiABIVgghW_yHWex7opZNDXpbN3IHp7jCXpBkHLrF7GriSAGBGsiWCBxe6nCTSBRGzpYcZo1HDT1sddN7fEejThl-u5axyUDEQ",
				authenticatorData:
					"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAOqbjWZNAR0hPOS2tIy1ddQAEPOWmRYCYAMuUV98lXLPA_SlAQIDJiABIVgghW_yHWex7opZNDXpbN3IHp7jCXpBkHLrF7GriSAGBGsiWCBxe6nCTSBRGzpYcZo1HDT1sddN7fEejThl-u5axyUDEQ",
				clientDataJSON:
					"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiRVRXRVZ2cG5uLWhqMVMxVzV4eW5XWkg2MndPRVVvRUFYTWlLVko0amZTQSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTUwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
				publicKey:
					"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhW_yHWex7opZNDXpbN3IHp7jCXpBkHLrF7GriSAGBGtxe6nCTSBRGzpYcZo1HDT1sddN7fEejThl-u5axyUDEQ",
				publicKeyAlgorithm: -7,
				transports: ["hybrid", "internal"],
			},
			type: "public-key",
		}.response,
		{
			challenge: new Uint8Array([
				17, 53, 132, 86, 250, 103, 159, 232, 99, 213, 45, 86, 231, 28, 167, 89, 145, 250, 219, 3, 132, 82, 129,
				0, 92, 200, 138, 84, 158, 35, 125, 32,
			]),
			userFactor: ["verified", "present"],
			origins: ["http://localhost:5500"],
			rpId: "localhost",
		}
	);

	console.log("attestation", attestation);

	const assertion = await fido.assertion(
		{
			authenticatorAttachment: "cross-platform",
			clientExtensionResults: {},
			id: "85aZFgJgAy5RX3yVcs8D9A",
			rawId: "85aZFgJgAy5RX3yVcs8D9A",
			response: {
				authenticatorData: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA",
				clientDataJSON:
					"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiVzloUExkaXRGcUNHRXhBSnhGbDkxZHc5dWw3QlNJY19BNlh1YzhZd2gtcyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTUwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
				signature:
					"MEQCIC9c84TW8NDvnFxoHpbaRSiLOvWIlXCTNdUxPztVYhh0AiBeCEaJdDTGWedhdaiI8RY36sfLdbvASYaCqHykjDvTaw",
			},
			type: "public-key",
		}.response,
		{
			challenge: new Uint8Array([
				91, 216, 79, 45, 216, 173, 22, 160, 134, 19, 16, 9, 196, 89, 125, 213, 220, 61, 186, 94, 193, 72, 135,
				63, 3, 165, 238, 115, 198, 48, 135, 235,
			]),
			publicKey: attestation.jwk(),
			userFactor: ["verified", "present"],
			origins: ["http://localhost:5500"],
			rpId: "localhost",
			signCount: 0,
			userHandle: "BA==",
		}
	);

	console.log("assertion", assertion);
});
