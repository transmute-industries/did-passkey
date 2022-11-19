
import {useEffect, useState } from 'react';
import { Button } from '@mui/material';
import  AppPage from './AppPage'

import passkey from 'did-passkey'

const message = 'It’s a dangerous business, Frodo, going out your door. 🧠💎';
const content = new TextEncoder().encode(message);

function App() {

  const [publicKeyJwk, setPublicKeyJwk] = useState(null)
  const [signatureObject, setSignatureObject] = useState(null)

  async function signAndVerify() {
    const {signature, authenticatorData, clientDataJSON} = await passkey.web.sign(content);
    const verification = await passkey.web.verify({
      publicKeyJwk,
      content,
      signature,
      authenticatorData,
      clientDataJSON,
    });
    if (verification) {
      alert('verification succeeded');
    } else {
      alert('signature validation failed');
    }
    setSignatureObject({
      verification,
      signature: btoa(signature),
      authenticatorData: btoa(authenticatorData),
      clientDataJSON: btoa(clientDataJSON),
    })
  }
  
  useEffect(()=>{
    (async ()=>{
      const publicKeyJwk = await passkey.web.generate();
      setPublicKeyJwk(publicKeyJwk)
    })()
  }, [])

  return (
    <AppPage>
      <pre>
        {JSON.stringify(publicKeyJwk, null, 2)}
      </pre>
      <Button onClick={signAndVerify}>Sign & Verify</Button>
      <pre>
        {JSON.stringify({message, ...signatureObject}, null, 2)}
      </pre>
    </AppPage>
    
  );
}

export default App;
