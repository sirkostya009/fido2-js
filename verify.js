const { toBuffer, coseToJwk } = require('./utils');

function equals(a1, a2) {
	if (a1.length !== a2.length) {
		return false;
	}

	for (let i = 0; i < a1.length; ++i) {
		if (a1[i] !== a2[i]) {
			return false;
		}
	}

	return true;
}

async function verify({ response: { clientData, authenticatorData, attestationObject, userHandle, signature }, rawClientData, rawAuthenticatorData },
                      { origins, challenge, publicKey, counter, userFactor, userHandle: uh, rpId, type }) {
	if (!Array.isArray(origins) || origins.length === 0) {
		throw new Error("'origins' must be an array with at least one element");
	}

	if (!origins.includes(clientData.origin)) {
		throw new Error(`Origin ${clientData.origin} not allowed`);
	}

	challenge = toBuffer(challenge, 'options.challenge');

	if (!equals(challenge, toBuffer(clientData.challenge, 'parsed.response.clientData.challenge'))) {
		throw new Error(`Challenge mismatch, got: ${clientData.challenge}, expected: ${challenge}`);
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

			if (!equals(userHandle, uh)) {
				throw new Error(`User handle mismatch, got: ${userHandle}, expected: ${uh}`);
			}
		}

		if (publicKey) {
			let key = publicKey;

			if (key[1]) {
				key = coseToJwk(key);
			}
			if (key.kty) {
				key = await crypto.subtle.importKey('jwk', key, 'SHA-256', true, ['verify']);
			}

			if (!signature) {
				throw new Error("No signature provided");
			}
			signature = toBuffer(signature, 'parsed.response.signature');

			if (typeof rawClientData !== 'function' || typeof rawAuthenticatorData !== 'function') {
				throw new Error(`Expected rawClientData, rawAuthenticatorData to be functions, got ${rawClientData}, ${rawAuthenticatorData} respectively`);
			}

			/** @type {Uint8Array} */
			const data = rawAuthenticatorData();
			data.length += 32;
			data.set(await crypto.subtle.digest('sha256', rawClientData()), data.length - 32);

			if (!(await crypto.subtle.verify('sha256', key, signature, data))) {
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

		const hash = await crypto.subtle.digest('sha256', rpId);

		if (!equals(hash, rpIdHash)) {
			throw new Error("'rpId' hash doesn't match");
		}
	}
}

module.exports = {
	verify,
};
