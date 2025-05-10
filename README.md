# FIDO2.js

`fido2-js` is a simple library for parsing and verifying FIDO2 attestation and assertion responses.

Depends on `cbor-x`, and `SubtleCrypto` API. Works in browsers.

Doesn't provide means of generating requests for the client, but that isn't hard to do on your own anyway.

Supports common methods of attestation such as EC, OKP and RSA.

## Usage

### Attestation

```js
const { attestation } = require('fido2-js');
// or
import { attestation } from 'fido2-js';

// for the returned object to actually be of attestation,
// client data type must be 'webauthn.create'.
// it should be also stated that parse method can throw on malformed input
const parsed = await attestation(
    {
        clientDataJSON: '...',
        attestationObject: '...',
    },
    {
        challenge,
        origins: [origin],
        userFactor: ['verified', 'present'],
    }
).catch(err => err);

if (parsed instanceof Error) { // safe to assume Error
    console.error(parsed);
} else {
    publicKey = parsed.jwk();

    console.log('attestation succeeded', parsed);
}
```

### Assertion

```js
const { assertion } = require('fido2-js');
// or
import { assertion } from 'fido2-js';

const parsed = await assertion(
    {
        clientDataJSON: '...',
        authenticatorData: '...',
        signature: '...',
        userHandle: '...',
    },
    {
        challenge,
        origins: [origin],
        publicKey, // can also pass a COSE credentialPublicKey or a CryptoKey object
        counter: 0,
        userFactor: ['verified', 'present'], // can also just pass 'either'
        userHandle: /* base64 string or some byte array */,
    }
).catch(err => err);

if (parsed instanceof Error) { // safe to assume Error
    console.error(parsed);
} else {
    console.log('assertion succeeded', parsed);
}
```

### Browser

You can easily pull this library from jsdeliver:

```html
<script type="module">
    import { assertion, attestation } from 'https://cdn.jsdelivr.net/npm/fido2-js@2.0.0/+esm';
    import parse from 'https://cdn.jsdelivr.net/npm/fido2-js@2.0.0/parse.js/+esm';

    // ...
</script>
```

If you don't use a fancy CDN that automatically minifies and bundles libraries (like jsdelivr), you will have to provide an importmap for `cbor-x`.

```html
<script type="importmap">
    {
        "imports": {
            "cbor-x/decode-no-eval": "https://cdn.jsdelivr.net/npm/cbor-x@1.6.0/decode.min.js"
        }
    }
</script>
<script>
    // note the /esm/ folder for ESM imports
    import {} from '/path/to/lib/esm/index.js';
    import parse from '/path/to/lib/esm/parse.js';

    // ...
</script>
```

### Bonus

There's plenty of WebAuthn tutorials out there, but most of them only show basic flow of authentication, without revealing the much-needed-to-know details.

If you're new to FIDO2 WebAuthn, I suggest playing with the `parse` function to better understand the protocol and how it works.
MDN's WebAuthn documentation is your best friend for this: [Web Authentication API | MDN](https://developer.mozilla.org/docs/Web/API/Web_Authentication_API)

```js
import parse from 'fido2-js/parse';

// the parse function lets you only parse the response returned by authenticator,
// letting you a view into the structure of said object and visually understand
// what you're working with, I wish I had this when starting out!

// mere example. your function (endpoint on the server) implementation would be different
function endpoint(body) {
    // a very detailed explanation of all of these things can found at https://www.w3.org/TR/webauthn-3/
    // the response variable is returned by assertion and attestation functions
    const { response, rawAuthenticatorData, rawClientData } = parse(body);

    console.log(response, rawAuthenticatorData, rawClientData);
}
```

You can also view a browser-only example at [browser.html](/test/browser.html).

> **Note:**  
> On Linux, if you don't have a physical security key available, you may need an authenticator emulator. Check out [virtual-fido](https://github.com/bulwarkid/virtual-fido).

## License

MIT.
