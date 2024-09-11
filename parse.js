const CBOR = require('cbor-x');
const { toBuffer, coseToJwk } = require('./utils');

function parseAuthenticatorData(buf) {
	const result = {
		rpIdHash: buf.subarray(0, 32),
		flags: {
			up:   !!(buf[32] & 1),
			rfu1: !!(buf[32] & 1 << 1),
			uv:   !!(buf[32] & 1 << 2),
			be:   !!(buf[32] & 1 << 3),
			bs:   !!(buf[32] & 1 << 4),
			rfu2: !!(buf[32] & 1 << 5),
			at:   !!(buf[32] & 1 << 6),
			ed:   !!(buf[32] & 1 << 7),
		},
		signCount: buf.readInt32BE(33),
	};

	let decoded;
	if (result.flags.at) {
		const credentialIdLength = buf.readUInt16BE(53);
		const subarray = buf.subarray(55 + credentialIdLength);

		result.attestedCredentialData = {
			aaguid: buf.subarray(37, 37 + 16),
			credentialIdLength,
			credentialId: buf.subarray(55, 55 + credentialIdLength),
			credentialPublicKey: result.flags.ed ? (decoded = CBOR.decodeMultiple(subarray))[0] : CBOR.decode(subarray),
		};
	}

	if (result.flags.ed) {
		result.extensions = result.flags.at ? decoded[1] : CBOR.decode(buf.subarray(37));
	}

	return result;
}

function parse(obj) {
	if (typeof obj === 'string' || Buffer.isBuffer(obj)) {
		obj = JSON.parse(obj);
	} else if (typeof obj !== 'object') {
		throw new Error(`Cannot parse ${obj}`);
	}

	const { response: { attestationObject, clientDataJSON, authenticatorData, ...response }, ...rest } = obj;

	const result = {
		...rest,
		response: {
			...response,
			clientData: JSON.parse(toBuffer(clientDataJSON, 'response.clientDataJSON')),
		},
		rawClientData() {
			return toBuffer(clientDataJSON, 'clientDataJSON');
		},
		rawAuthenticatorData() {},
	};

	if (result.response.clientData.type === 'webauthn.create') {
		const { fmt, attStmt, authData } = CBOR.decode(toBuffer(attestationObject, 'response.attestationObject'));

		result.response.attestationObject = {
			fmt,
			attStmt,
			authData: parseAuthenticatorData(authData),
		};

		result.jwk = () => coseToJwk(result.response.attestationObject.authData.attestedCredentialData.credentialPublicKey);
		result.rawAuthenticatorData = () => CBOR.decode(toBuffer(attestationObject, 'attestationObject')).authData;
	} else if (result.response.clientData.type === 'webauthn.get') {
		result.response.authenticatorData = parseAuthenticatorData(
			toBuffer(authenticatorData, 'response.authenticatorData')
		);

		result.rawAuthenticatorData = () => toBuffer(authenticatorData, 'authenticatorData');
	} else {
		throw new Error(`Unsupported clientData type: ${result.response.clientData.type}`);
	}

	return result;
}

module.exports = {
	parse,
};
