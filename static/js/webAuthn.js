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

  // Create credentials using WebAuthn API
  const credential = await navigator.credentials.create({
    publicKey: publicKeyOptions
  });

  // Successful creation - no immediate server communication as requested
  return credential;
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
