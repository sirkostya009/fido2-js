# FIDO2.js

`fido2-js` is a low-level library for parsing and verifying FIDO2 attestation and assertion responses.

Works in browsers and Node.js.

Doesn't provide means of generating requests for the client, but that isn't hard to do on your own anyway.

## Example

```js
const { parse, verify } = require('fido2-js');
// or
import { parse, verify } from 'fido2-js';

try {
    // for the returned object to actually be of attestation,
    // client data type must be 'webauthn.create'.
    // it should be also stated that parse method can throw on malformed input
    const parsedAttestation = parse({ ... });

    await verify(parsedAttestation, {
        type: 'webauthn.create',
        challenge,
        origins: [origin],
        userFactor: ['verified', 'present'],
    });

    publicKey = parsedAttestation.jwk();

    console.log('assertion succeeded');
} catch (err) {
    console.error('assertion failed', err.message);
}

try {
    await verify(
        parse({ ... }),
        {
            type: 'webauthn.get',
            challenge,
            origins: [origin],
            publicKey, // can also pass a raw credentialPublicKey or a CryptoKey object
            counter: 0,
            userFactor: ['verified', 'present'], // can also just pass 'either'
            userHandle: /* base64 string or some byte array */,
        },
    );

    console.log('attestation succeeded');
} catch (err) {
    console.error('attestation failed', err.message);
}
```

## Security considerations

This library is not perfect. `parse` can potentially clog Node's event loop if the
provided CBOR takes too long to parse, opening up a possibility for DoS attacks.
To mitigate that you could try limiting the payload size your server can receive;
rate limiting webauthn endpoints, etc.

## TODO:
- Verify attestation formats. Help needed!
- Support more key types in JWK parser. (Currently only EC, OKP and RSA are supported).

## Contributing

If you encounter any bugs or imperfections, don't hesitate to open a GitHub issue.

Also, if you're knowledgeable in FIDO2 protocol, you're invited to audit the code and in case of finding
nuances or potential for improvement open a PR. If it is parsing or verification that you're changing,
then supply a link to the respective WebAuthn resource according to which you made the change.

## License

MIT.
