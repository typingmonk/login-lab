function registerWebAuthn(event) {
    event.preventDefault();
    const form = event.target;
    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());

    $.post('/auth/registerWebAuthn',
      JSON.stringify(data),  
      function(publicKeyOptions) {
        createWebAuthnCredential(publicKeyOptions);
      },
      'json'
    )
}

async function createWebAuthnCredential(publicKeyOptions) {
  publicKeyOptions.challenge = base64toArrayBuffer(publicKeyOptions.challenge);
  publicKeyOptions.user.id = base64toArrayBuffer(publicKeyOptions.user.id);

  //create credentials using WebAuthn API
  const credential = await navigator.credentials.create({
    publicKey: publicKeyOptions
  });

  //prepare credentialData for sending to the server
  const credentialData = {
    id: credential.id,
    rawId: arrayBufferToBase64(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: arrayBufferToBase64(credential.response.attestationObject),
      clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON)
    },
    csrf_token: $('input[name="csrf_token"]').val(),
  };

  //send credentail to the server
  sendCredentialToServer(credentialData);
}

function sendCredentialToServer(credentialData) {
  $.post({
    url: '/auth/verifyWebAuthnRegistration',
    data: JSON.stringify(credentialData),
    contentType: 'application/json',
    dataType: 'json'
  })
  .done(function (res) {
    if (res.success) {
      alert(res.message);
      window.location.reload();
    } else {
      alert('error: ' + (res.error || 'unknown error'));
    }
  })
}

function base64toArrayBuffer(base64Url) {
  //base64Url to base64
  let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const padding = '='.repeat((4 - base64.length % 4) % 4);
  base64 = base64 + padding;

  //convert to ArrayBuffter
  const binaryString = window.atob(base64);
  const arr = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    arr[i] = binaryString.charCodeAt(i);
  }

  return arr;
}

function arrayBufferToBase64(arrayBuffer) {
  //convert ArrayBuffer to binary string
  const bytes = new Uint8Array(arrayBuffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }

  //convert binary string to base64
  let base64 = window.btoa(binary);

  //base64 to base64Url
  base64 = base64.replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');

  return base64;
}
