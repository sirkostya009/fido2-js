const CBOR = require("cbor-x/decode");
import { toBuffer, coseToJwk } from "./utils";
function parseAuthenticatorData(buf) {
    const result = {
        rpIdHash: buf.subarray(0, 32),
        flags: {
            up: !!(buf[32] & 1),
            rfu1: !!(buf[32] & (1 << 1)),
            uv: !!(buf[32] & (1 << 2)),
            be: !!(buf[32] & (1 << 3)),
            bs: !!(buf[32] & (1 << 4)),
            rfu2: !!(buf[32] & (1 << 5)),
            at: !!(buf[32] & (1 << 6)),
            ed: !!(buf[32] & (1 << 7)),
        },
        signCount: (buf[33] << 24) | (buf[34] << 16) | (buf[35] << 8) | buf[36],
    };
    let decoded;
    if (result.flags.at) {
        const credentialIdLength = (buf[53] << 8) | buf[54];
        const subarray = buf.subarray(55 + credentialIdLength);
        result.attestedCredentialData = {
            aaguid: buf.subarray(37, 37 + 16),
            credentialIdLength,
            credentialId: buf.subarray(55, 55 + credentialIdLength),
            credentialPublicKey: result.flags.ed
                ? (decoded = CBOR.decodeMultiple(subarray))[0]
                : CBOR.decode(subarray),
        };
    }
    if (result.flags.ed) {
        result.extensions = result.flags.at
            ? decoded[1]
            : CBOR.decode(buf.subarray(37));
    }
    return result;
}
export function parse(obj) {
    if (!obj || typeof obj !== "object") {
        throw new Error("Cannot parse " + obj);
    }
    const { response: { attestationObject, clientDataJSON, authenticatorData, ...response }, ...rest } = obj;
    const clientData = JSON.parse("Buffer" in globalThis && clientDataJSON instanceof Buffer
        ? clientDataJSON
        : clientDataJSON instanceof Uint8Array
            ? String.fromCharCode(...clientDataJSON)
            : clientDataJSON instanceof ArrayBuffer
                ? String.fromCharCode(...new Uint8Array(clientDataJSON))
                : typeof clientDataJSON === "string"
                    ? atob(clientDataJSON)
                    : undefined);
    switch (clientData.type) {
        case "webauthn.create":
            const { fmt, attStmt, authData } = CBOR.decode(toBuffer(attestationObject, "response.attestationObject"));
            const parsedAuthData = parseAuthenticatorData(authData);
            return {
                ...rest,
                response: {
                    ...response,
                    clientData,
                    attestationObject: {
                        fmt,
                        attStmt,
                        authData: parsedAuthData,
                    },
                },
                rawClientData() {
                    return toBuffer(clientDataJSON, "clientDataJSON");
                },
                rawAuthenticatorData() {
                    return CBOR.decode(toBuffer(attestationObject, "attestationObject")).authData;
                },
                jwk() {
                    return coseToJwk(parsedAuthData.attestedCredentialData);
                },
            };
        case "webauthn.get":
            return {
                ...rest,
                response: {
                    ...response,
                    clientData,
                    authenticatorData: parseAuthenticatorData(toBuffer(authenticatorData, "response.authenticatorData")),
                },
                rawAuthenticatorData() {
                    return toBuffer(authenticatorData, "authenticatorData");
                },
                rawClientData() {
                    return toBuffer(clientDataJSON, "clientDataJSON");
                },
            };
        default:
            throw new Error("Unknown clientData type: " + clientData.type);
    }
}
