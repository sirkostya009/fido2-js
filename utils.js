function toBuffer(value, valueName) {
	try {
		return Buffer.isBuffer(value)
			? value
			: Buffer.from(value, typeof value === 'string' ? 'base64' : undefined);
	} catch (err) {
		throw new Error(`'${valueName}' must be either a BufferSource coercible or a base64-encoded string`);
	}
}

const keyTypes = [, 'OKP', 'EC', 'RSA'];
const ellipticCurves = [, 'P-256', 'P-384', 'P-521', 'X25519', 'X448', 'Ed25519', 'Ed448', 'secp256k1'];
const algorithms = {
	[-7]: 'ES256',
	[-35]: 'ES384',
	[-36]: 'ES512',
	[-8]: 'EdDSA',
	[-257]: 'RS256',
	[-258]: 'RS384',
	[-259]: 'RS512',
	[-39]: 'PS512',
	[-38]: 'PS384',
	[-37]: 'PS256',
};

function coseToJwk(cose) {
	const jwk = {
		kty: keyTypes[cose[1]],
		alg: algorithms[cose[3]],
	};

	switch (cose[1]) {
	case 2: // EC
		if (cose[-3]) jwk.y = Buffer.isBuffer(cose[-3]) ? cose[-3].toString('base64') : cose[-3];
	case 1: // OKP
		jwk.crv = ellipticCurves[cose[-1]];
		if (cose[-2]) jwk.x = cose[-2].toString('base64');
		if (cose[-4]) jwk.d = cose[-4].toString('base64');
		break;
	case 3: // RSA
		if (cose[-1]) jwk.n = cose[-1].toString('base64');
		if (cose[-2]) jwk.e = cose[-2].toString('base64');
		if (cose[-3]) jwk.d = cose[-3].toString('base64');
		if (cose[-4]) jwk.p = cose[-4].toString('base64');
		if (cose[-5]) jwk.q = cose[-5].toString('base64');
	}

	return jwk;
}

module.exports = {
	toBuffer,
	coseToJwk,
};
