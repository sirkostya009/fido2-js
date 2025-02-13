import { toBuffer, coseToJwk, jwkToCryptoKey } from "./utils";
function equals(a1, a2) {
    if (a1 instanceof ArrayBuffer) {
        a1 = new Uint8Array(a1);
    }
    if (a2 instanceof ArrayBuffer) {
        a2 = new Uint8Array(a2);
    }
    if (a1.byteLength !== a2.byteLength) {
        return false;
    }
    for (let i = 0; i < a1.byteLength; ++i) {
        if (a1[i] !== a2[i]) {
            return false;
        }
    }
    return true;
}
export async function verify({ response: { clientData, authenticatorData, attestationObject, userHandle, signature, }, rawClientData, rawAuthenticatorData, }, { origins, challenge, publicKey, counter, userFactor, userHandle: uh, rpId, type, }) {
    if (!Array.isArray(origins) || origins.length === 0) {
        throw new Error("'origins' must be an array with at least one element");
    }
    if (!origins.includes(clientData.origin)) {
        throw new Error(`Origin ${clientData.origin} not allowed`);
    }
    challenge = toBuffer(challenge, "options.challenge");
    if (!equals(challenge, toBuffer(clientData.challenge, "parsed.response.clientData.challenge"))) {
        throw new Error(`Challenge mismatch, got: ${clientData.challenge}, expected: ${challenge}`);
    }
    if (counter) {
        const { signCount } = authenticatorData || attestationObject.authData;
        if (signCount < counter) {
            throw new Error(`'signCount' lower than provided, got: ${signCount}, expected: ${counter}`);
        }
        else if (signCount === counter) {
            throw new Error("'signCount' equal to provided");
        }
        else if (signCount > counter + 1) {
            throw new Error(`'signCount' higher than provided+1, got: ${signCount}, expected: ${counter + 1}`);
        }
    }
    if (userFactor) {
        const { uv, up } = (authenticatorData || attestationObject.authData)
            .flags;
        if (userFactor === "either") {
            if (!uv && !up) {
                throw new Error("User was not present nor verified");
            }
        }
        else if (Array.isArray(userFactor) && userFactor.length > 0) {
            if (!uv && userFactor.includes("verified")) {
                throw new Error("User not present");
            }
            if (!up && userFactor.includes("present")) {
                throw new Error("User not verified");
            }
        }
        else {
            throw new Error("'userFactor' must be an array with at least one element or a string 'either'");
        }
    }
    if (clientData.type !== type) {
        throw new Error(`Unexpected client data type, got: ${clientData.type}, expected ${type}`);
    }
    if (clientData.type === "webauthn.get") {
        if (uh) {
            if (!userHandle) {
                throw new Error("No user handle provided");
            }
            userHandle = toBuffer(userHandle, "parsed.response.userHandle");
            uh = toBuffer(uh, "options.userHandle");
            if (!equals(userHandle, uh)) {
                throw new Error(`userHandle mismatch, got: ${userHandle}, expected: ${uh}`);
            }
        }
        if (publicKey) {
            let key = publicKey;
            if ("1" in key) {
                key = coseToJwk(key);
            }
            if ("kty" in key) {
                key = await jwkToCryptoKey(key);
            }
            if (!(key instanceof CryptoKey)) {
                throw new Error(`Expected publicKey to be CryptoKey-coercible (CryptoKey, COSE, JWK), got: ${key}`);
            }
            if (!signature) {
                throw new Error("No signature provided");
            }
            signature = toBuffer(signature, "parsed.response.signature");
            if (typeof rawClientData !== "function" ||
                typeof rawAuthenticatorData !== "function") {
                throw new Error(`Expected rawClientData, rawAuthenticatorData to be functions, got: ${rawClientData}, ${rawAuthenticatorData}, respectively`);
            }
            const rawAuthData = rawAuthenticatorData();
            const hash = new Uint8Array(await crypto.subtle.digest("sha-256", rawClientData()));
            const data = new Uint8Array(rawAuthData.length + hash.length);
            data.set(rawAuthData);
            data.set(hash, rawAuthData.length);
            console.log("rawAuthData", rawAuthData);
            console.log("hash", hash);
            console.log("data", data);
            const algorithm = key.algorithm.name === "ECDSA"
                ? {
                    ...key.algorithm,
                    hash: {
                        name: `SHA-${key.algorithm.namedCurve.slice(-3)}`,
                    },
                }
                : key.algorithm;
            if (!(await crypto.subtle.verify(algorithm, key, signature, data))) {
                throw new Error("Signature verification failed");
            }
        }
    }
    else if (clientData.type === "webauthn.create") {
        switch (attestationObject.fmt) {
            case "packed":
                break;
            case "tpm":
                break;
            case "android-key":
                break;
            case "android-safetynet":
                break;
            case "fido-u2f":
                break;
            case "none":
                break;
            case "apple":
                break;
        }
    }
    if (rpId) {
        const { rpIdHash } = authenticatorData || attestationObject.authData;
        const hash = await crypto.subtle.digest("sha-256", Uint8Array.from(rpId, (c) => c.charCodeAt(0)));
        if (!equals(hash, rpIdHash)) {
            throw new Error("'rpId' hash doesn't match");
        }
    }
}
