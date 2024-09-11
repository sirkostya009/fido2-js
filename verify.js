const crypto = require('crypto');
const { toBuffer, coseToJwk } = require('./utils');

function verify({ response: { clientData, authenticatorData, attestationObject, userHandle, signature }, rawClientData, rawAuthenticatorData },
				{ origins, challenge, publicKey, counter, userFactor, userHandle: uh, rpId, type }) {
	if (!Array.isArray(origins) || origins.length === 0) {
		throw new Error("'origins' must be an array with at least one element");
	}

	if (!origins.includes(clientData.origin)) {
		throw new Error(`Origin ${clientData.origin} not allowed`);
	}

	challenge = toBuffer(challenge, 'options.challenge');

	if (!challenge.equals(toBuffer(clientData.challenge, 'parsed.response.clientData.challenge'))) {
		throw new Error(`Challenge mismatch, got: ${clientData.challenge}, expected: ${challenge.toString('base64')}`);
	}

	if (counter) {
		const { signCount } = authenticatorData || attestationObject.authData;

		if (signCount < counter) {
			throw new Error(`'signCount' lower than provided, got: ${signCount}, expected: ${counter}`);
		} else if (signCount === counter) {
			throw new Error("'signCount' equal to provided");
		} else if (signCount > counter + 1) {
			throw new Error(`'signCount' higher than provided+1, got: ${signCount}, expected: ${counter + 1}`);
		}
	}

	if (userFactor) {
		const { uv, up } = (authenticatorData || attestationObject.authData).flags;

		if (userFactor === 'either') {
			if (!uv && !up) {
				throw new Error("User was not present nor verified");
			}
		} else if (Array.isArray(userFactor) && userFactor.length > 0) {
			if (!uv && userFactor.includes('verified')) {
				throw new Error("User not present");
			}

			if (!up && userFactor.includes('present')) {
				throw new Error("User not verified");
			}
		} else {
			throw new Error("'userFactor' must be an array with at least one element or a string 'either'");
		}
	}

	if (clientData.type !== type) {
		throw new Error(`Unexpected client data type, got: ${clientData.type}, expected ${type}`);
	}

	if (clientData.type === 'webauthn.get') {
		if (uh) {
			if (!userHandle) {
				throw new Error("No user handle provided");
			}

			userHandle = toBuffer(userHandle, 'parsed.response.userHandle');
			uh = toBuffer(uh, 'options.userHandle');

			if (!userHandle.equals(uh)) {
				throw new Error(`User handle mismatch, got: ${userHandle.toString('base64')}, expected: ${uh.toString('base64')}`);
			}
		}

		if (publicKey) {
			let key = publicKey;

			if (key[1]) {
				key = coseToJwk(key);
			}
			if (key.kty) {
				key = { key, format: 'jwk' };
			}

			if (!signature) {
				throw new Error("No signature provided");
			}
			signature = toBuffer(signature, 'parsed.response.signature');

			if (typeof rawClientData !== 'function' || typeof rawAuthenticatorData !== 'function') {
				throw new Error(`Expected rawClientData, rawAuthenticatorData to be functions, got ${rawClientData}, ${rawAuthenticatorData} respectively`);
			}

			const data = Buffer.concat([
				rawAuthenticatorData(),
				crypto.createHash('sha256').update(rawClientData()).digest(),
			]);

			if (!crypto.verify(null, data, key, signature)) {
				throw new Error("Signature verification failed");
			}
		}
	} else if (clientData.type === 'webauthn.create') switch (attestationObject.fmt) {
		case 'packed': // TODO: https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation
			break;
		case 'tpm': // TODO: https://www.w3.org/TR/webauthn-2/#sctn-tpm-attestation
			break;
		case 'android-key': // TODO: https://www.w3.org/TR/webauthn-2/#sctn-android-key-attestation
			break;
		case 'android-safetynet': // TODO: https://www.w3.org/TR/webauthn-2/#sctn-android-safetynet-attestation
			break;
		case 'fido-u2f': // TODO: https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation
			break;
		case 'none': // TODO: https://www.w3.org/TR/webauthn-2/#sctn-none-attestation
			break;
		case 'apple': // TODO: https://www.w3.org/TR/webauthn-2/#sctn-apple-anonymous-attestation
			break;
	}

	if (rpId) {
		const { rpIdHash } = authenticatorData || attestationObject.authData;

		const hash = crypto.createHash('sha256').update(rpId).digest();

		if (!hash.equals(rpIdHash)) {
			throw new Error("'rpId' hash doesn't match");
		}
	}
}

module.exports = {
	verify,
};
