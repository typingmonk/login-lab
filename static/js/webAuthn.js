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

function createWebAuthnCredential(publicKeyOptions) {
  console.log(publicKeyOptions);
}
