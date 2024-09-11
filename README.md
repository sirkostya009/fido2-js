# FIDO2.js

`fido2-js` is a low-level library for parsing and verifying FIDO2 attestation and assertion responses on the server.

Depends on `cbor-x`, Node.js `Buffer` and `crypto` module. Hence, can't run in the browser.

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

    verify(parsedAttestation, {
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
    // will return the thrown Error object on failure, if any
    verify(
        parse({ ... }),
        {
            type: 'webauthn.get',
            challenge,
            origins: [origin],
            publicKey, // can also pass a jwk or anything that would usually go in node:crypto.verify
            counter: 0,
            userFactor: ['verified', 'present'], // can also just pass 'either'
            userHandle: /* base64 string or some byte array */,
        },
    );

    if (err) {
        console.error('attestation failed', err.message);
    } else {
        console.log('attestation succeeded');
    }
}
```

## Security considerations

This library is not perfect. `parse` and `verify` methods are synchronous,
opening up a possibility of a DoS attack that may clog Node's event loop.
To mitigate that you could try limiting the payload size your server can receive;
rate limiting webauthn endpoints, etc.

## TODO:
- Verify attestation formats. Help needed!
- Support more key types in JWK parser. (Currently only EC, OKP and RSA are supported).

## Contributing

Web security is a sensitive topic. This package, unfortunately, cannot be considered
to be most progressive at it. If you encounter any bugs or imperfections, don't hesitate to open a GitHub issue.

Also, if you're knowledgeable in FIDO2 protocol, you're invited to audit the code and in case of finding
nuances or potential for improvement open a PR. If it is parsing or verification that you're changing,
then supply a link to the respective WebAuthn resource according to which you made the change.

## License

MIT.
