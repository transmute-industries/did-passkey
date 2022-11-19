/* eslint-disable max-len */
const defaultWebCryptoKeyAlgorithm = {
  name: 'ECDSA',
  namedCurve: 'P-256',
};

const defaultWebCryptoSignatureAlgorithm = {
  name: 'ECDSA',
  hash: {name: 'SHA-256'},
};

const pubKeyCredParams = [
  {
    type: 'public-key',
    alg: -7, // "ES256" as registered in the IANA COSE Algorithms registry
  },
  {
    type: 'public-key',
    alg: -257, // Value registered by this specification for "RS256"
  },
];

function b64URLenc(buf) {
  return btoa(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

const getRandomChallenge = () => {
  const randomChallenge = new Uint8Array(16);
  window.crypto.getRandomValues(randomChallenge);
  return randomChallenge;
};

const getUserHandleId = (text) => {
  return new TextEncoder().encode(text);
};

const encodeRawCredentialId = (rawId) => {
  return window.btoa(rawId);
};

const decodeRawCredentialId = (id) => {
  return Uint8Array.from(window.atob(id), (c) => c.charCodeAt(0));
};

const getLocalExcludeCredentials = () => {
  const item = localStorage.getItem('did-passkey');
  if (item) {
    return [
      {
        id: decodeRawCredentialId(item),
        type: 'public-key',
      },
    ];
  }
  return [];
};

// TODO: rename, this is just a caching layer on platform authenticator credential
async function getLocalPasskey() {
  const item = localStorage.getItem('passkey');
  if (item) {
    return JSON.parse(item);
  }
  const randomChallenge = getRandomChallenge();
  const cred = await navigator.credentials.create({
    publicKey: {
      // https://www.w3.org/TR/webauthn-2/#sctn-sample-registration
      challenge: randomChallenge,
      rp: {
        // id: https://www.w3.org/TR/webauthn-2/#rp-id
        name: 'Cloud Wallet',
      },
      user: {
        id: getUserHandleId('demo-user'),
        name: 'alice@cloud.example',
        displayName: 'Alice 💎',
      },
      pubKeyCredParams,
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'discouraged',
      },
      attestation: 'none',
      timeout: 60000,
      // Don’t re-register any authenticator that has one of these credentials
      excludeCredentials: getLocalExcludeCredentials(),
    },
  });
  const encodedRawId = encodeRawCredentialId(cred.rawId);
  const publicKey = await window.crypto.subtle.importKey(
      'spki',
      cred.response.getPublicKey(),
      defaultWebCryptoKeyAlgorithm,
      true,
      ['verify'],
  );
  const publicKeyJwk = await window.crypto.subtle.exportKey('jwk', publicKey);
  delete publicKeyJwk.ext;
  publicKeyJwk.kid = `did:passkey:${encodedRawId}`;
  return publicKeyJwk;
}

// TODO: rename... initialize?
async function generate() {
  const publicKeyJwk = await getLocalPasskey();
  localStorage.setItem('passkey', JSON.stringify(publicKeyJwk));
  return publicKeyJwk;
}

async function sign(content) {
  const ac = await navigator.credentials.get({
    publicKey: {
      allowCredentials: [],
      timeout: 60000,
      challenge: await crypto.subtle.digest('SHA-256', content),
    },
  });
  return {
    authenticatorData: new Uint8Array(ac.response.authenticatorData),
    clientDataJSON: new Uint8Array(ac.response.clientDataJSON),
    signature: new Uint8Array(ac.response.signature),
  };
}

const validateChallenge = async ({content, clientDataJSON}) => {
  const clientDataObj = JSON.parse(new TextDecoder().decode(clientDataJSON));
  const challenge = b64URLenc(
      String.fromCharCode.apply(
          null,
          new Uint8Array(await crypto.subtle.digest('SHA-256', content)),
      ),
  );
  return clientDataObj.challenge !== challenge;
};

const getDetachedSignature = async ({
  signature,
  clientDataJSON,
  authenticatorData,
}) => {
  const clientDataJSON_sha256 = new Uint8Array(
      await crypto.subtle.digest('SHA-256', clientDataJSON),
  );
  const data = new Uint8Array(
      authenticatorData.length + clientDataJSON_sha256.length,
  );
  data.set(authenticatorData);
  data.set(clientDataJSON_sha256, authenticatorData.length);
  // https://gist.github.com/philholden/50120652bfe0498958fd5926694ba354
  const rStart = signature[4] === 0 ? 5 : 4;
  const rEnd = rStart + 32;
  const sStart = signature[rEnd + 2] === 0 ? rEnd + 3 : rEnd + 2;
  const r = signature.slice(rStart, rEnd);
  const s = signature.slice(sStart);
  const detachedSignature = new Uint8Array([...r, ...s]);
  return {data, detachedSignature};
};

async function verify({
  content,
  signature,
  authenticatorData,
  clientDataJSON,
  publicKeyJwk,
}) {
  const isValid = await validateChallenge({content, clientDataJSON});
  if (isValid) {
    throw new Error('ClientDataJSON validation failed.');
  }
  const publicKey = await window.crypto.subtle.importKey(
      'jwk',
      publicKeyJwk,
      defaultWebCryptoKeyAlgorithm,
      true,
      ['verify'],
  );
  const {detachedSignature, data} = await getDetachedSignature({
    signature,
    clientDataJSON,
    authenticatorData,
  });
  const result = await window.crypto.subtle.verify(
      defaultWebCryptoSignatureAlgorithm,
      publicKey,
      detachedSignature,
      data,
  );
  return result;
}

module.exports = {generate, sign, verify};
