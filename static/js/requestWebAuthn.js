function requestWebAuthn(event) {
    event.preventDefault();
    const form = event.target;
    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());
    
    $.post('/auth/requestWebAuthn',
      JSON.stringify(data),
      function(publicKeyOptions) {
          console.log(publicKeyOptions);
      },
      'json'
    )
}
