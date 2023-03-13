function auth() {

  fetch('http://localhost:8080/register_start/' + encodeURIComponent("extension"), {
    method: 'POST',
    credentials: "include",
  })
    .then(async response => {
      const json = await response.json();
      return {
        token: response.headers.get('authorization'),
        ...json
      };
    })
    .then(async credentialCreationOptions => {
      credentialCreationOptions.publicKey.challenge = Base64.toUint8Array(credentialCreationOptions.publicKey.challenge);
      credentialCreationOptions.publicKey.user.id = Base64.toUint8Array(credentialCreationOptions.publicKey.user.id);

      const created = await navigator.credentials.create({
        publicKey: credentialCreationOptions.publicKey,
      });

      return {
        token: credentialCreationOptions.token,
        credential: created,
      };
    })
    .then((credential_other) => {
      const { credential, token } = credential_other;
      fetch('http://localhost:8080/register_finish', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `${token}`
        },
        credentials: "include",
        body: JSON.stringify({
          id: credential.id,
          rawId: Base64.fromUint8Array(new Uint8Array(credential.rawId), true),
          type: credential.type,
          response: {
            attestationObject: Base64.fromUint8Array(new Uint8Array(credential.response.attestationObject), true),
            clientDataJSON: Base64.fromUint8Array(new Uint8Array(credential.response.clientDataJSON), true),
          },
        })
      })
        .then((response) => {
          if (response.ok){
            console.log("Response OK, registered");
          } else {
            console.log("Something went wrong during reg");
          }
        });
    })
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById("somebutton").addEventListener('click', auth);
});
