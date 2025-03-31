function requestWebAuthn(event) {
    event.preventDefault();
    const form = event.target;
    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());
    
    $.post('/auth/requestWebAuthn',
      JSON.stringify(data),
      getWebAuthnCredential,
      'json'
    );
}

function getWebAuthnCredential(publicKeyOptions) {
    console.log(publicKeyOptions);
    //TODO using navigator.credentials.get
}
