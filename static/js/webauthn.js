function b64enc(buf) {
    return base64js.fromByteArray(buf)
                   .replace(/\+/g, "-")
                   .replace(/\//g, "_")
                   .replace(/=/g, "");
}

function b64RawEnc(buf) {
    return base64js.fromByteArray(buf)
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function hexEncode(buf) {
    return Array.from(buf)
                .map(function(x) {
                    return ("0" + x.toString(16)).substr(-2);
				})
                .join("");
}

async function fetch_json(url, options) {
    const response = await fetch(url, options);
    const body = await response.json();
    if(body.fail)
        throw body.fail;
    return body;
}



// for registration

const didClickRegister = async (e) => {
    e.preventDefault();

    const form = document.querySelector('#testform');
    const formData = new FormData(form);
    let credentialCreateOptionsFromServer;
    try {
        credentialCreateOptionsFromServer = await getCredentialCreateOptionsFromServer(formData);
    } catch (err) {
        return console.error("Failed to generate credential request options:", err);
    } // get credential
    const publicKeyCredentialCreateOptions = transformCredentialCreateOptions(credentialCreateOptionsFromServer);
    console.log(publicKeyCredentialCreateOptions);
    const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreateOptions
    });
    
    
    //done
    let newAssertionForServer;
    try {
        newAssertionForServer = transformNewAssertionForServer(credential);
    } catch (err) {
        return console.error("Failed to transform assertion:", err);
    }
    
    console.log(newAssertionForServer);

    let assertionValidationResponse;
    try {
        assertionValidationResponse = await postNewAssertionToServer(newAssertionForServer);
    } catch (err) {
        return console.error("Server validation of credential failed:", err);
    }
    window.alert('Success Registration.')
    window.location.reload();
}

const getCredentialCreateOptionsFromServer = async (formData) => {
    return await fetch_json(
        "/getCredential",
        {
            method: "post",
            body: formData
        }
    );
} // fetch the json from the form

const postNewAssertionToServer = async (credentialDataForServer) => {
    const formData = new FormData();
    Object.entries(credentialDataForServer).forEach(([key, value]) => {
        formData.set(key, value);
    });
    console.log(credentialDataForServer)
    return await fetch_json(
        "/verify_credential_info", {
        method: "POST",
        body: formData
    });
}

const transformCredentialCreateOptions = (credentialCreateOptionsFromServer) => {
    let {challenge, user, excludeCredentials} = credentialCreateOptionsFromServer;
    user.id = Uint8Array.from(
        atob(credentialCreateOptionsFromServer.user.id
            .replace(/\_/g, "/")
            .replace(/\-/g, "+")
            ), 
        c => c.charCodeAt(0));

    challenge = Uint8Array.from(
        atob(credentialCreateOptionsFromServer.challenge
            .replace(/\_/g, "/")
            .replace(/\-/g, "+")
            ),
        c => c.charCodeAt(0));
    
    excludeCredentials[0].id = Uint8Array.from(
        atob(credentialCreateOptionsFromServer.excludeCredentials[0].id
            .replace(/\_/g, "/")
            .replace(/\-/g, "+")
            ),
        c => c.charCodeAt(0));
        
    const transformedCredentialCreateOptions = Object.assign(
            {}, credentialCreateOptionsFromServer,
            {challenge, user, excludeCredentials});

    return transformedCredentialCreateOptions;
}

const transformNewAssertionForServer = (newAssertion) => {
    const attObj = new Uint8Array(
        newAssertion.response.attestationObject);
    const clientDataJSON = new Uint8Array(
        newAssertion.response.clientDataJSON);
    const rawId = new Uint8Array(
        newAssertion.rawId);
    
    const registrationClientExtensions = newAssertion.getClientExtensionResults();

    return {
        id: newAssertion.id,
        rawId: b64enc(rawId),
        type: newAssertion.type,
        attObj: b64enc(attObj),
        clientData: b64enc(clientDataJSON),    
        registrationClientExtensions: JSON.stringify(registrationClientExtensions)
    };
}




// for login

const didClickLogin = async (e) => {
    e.preventDefault();
    // gather the data in the form
    const form = document.querySelector('#loginform');
    const formData = new FormData(form);

    // post the login data to the server to retrieve the PublicKeyCredentialRequestOptions
    let credentialRequestOptionsFromServer;
    try {
        credentialRequestOptionsFromServer = await getCredentialRequestOptionsFromServer(formData);
    } catch (err) {
        return console.error("Error when getting request options from server:", err);
    }

    // convert certain members of the PublicKeyCredentialRequestOptions into
    // byte arrays as expected by the spec.    
    const transformedCredentialRequestOptions = transformCredentialRequestOptions(
        credentialRequestOptionsFromServer);

    // request the authenticator to create an assertion signature using the
    // credential private key
    let assertion;
    try {
        assertion = await navigator.credentials.get({
            publicKey: transformedCredentialRequestOptions,
        });
    } catch (err) {
        return console.error("Error when creating credential:", err);
    }

    // we now have an authentication assertion! encode the byte arrays contained
    // in the assertion data as strings for posting to the server
    const transformedAssertionForServer = transformAssertionForServer(assertion);

    // post the assertion to the server for verification.
    let response;
    try {
        response = await postAssertionToServer(transformedAssertionForServer);
    } catch (err) {
        return console.error("Error when validating assertion on server:", err);
    }
    window.alert('Success Authentication.')
    window.location.reload();
};

const getCredentialRequestOptionsFromServer = async (formData) => {
    return await fetch_json(
        "/webauthn_begin_assertion",
        {
            method: "POST",
            body: formData
        }
    );
}

const transformCredentialRequestOptions = (credentialRequestOptionsFromServer) => {
    let {challenge, allowCredentials} = credentialRequestOptionsFromServer;

    challenge = Uint8Array.from(
        atob(challenge.replace(/\_/g, "/").replace(/\-/g, "+")), c => c.charCodeAt(0));

    allowCredentials = allowCredentials.map(credentialDescriptor => {
        let {id} = credentialDescriptor;
        id = id.replace(/\_/g, "/").replace(/\-/g, "+");
        id = Uint8Array.from(atob(id), c => c.charCodeAt(0));
        return Object.assign({}, credentialDescriptor, {id});
    });

    const transformedCredentialRequestOptions = Object.assign(
        {},
        credentialRequestOptionsFromServer,
        {challenge, allowCredentials});

    return transformedCredentialRequestOptions;
};

const transformAssertionForServer = (newAssertion) => {
    const authData = new Uint8Array(newAssertion.response.authenticatorData);
    const clientDataJSON = new Uint8Array(newAssertion.response.clientDataJSON);
    const rawId = new Uint8Array(newAssertion.rawId);
    const sig = new Uint8Array(newAssertion.response.signature);
    const userHandle = new Uint8Array(newAssertion.response.userHandle)
    const assertionClientExtensions = newAssertion.getClientExtensionResults();
    console.log(b64RawEnc(sig))
    return {
        id: newAssertion.id,
        rawId: b64enc(rawId),
        type: newAssertion.type,
        authData: b64RawEnc(authData),
        clientData: b64RawEnc(clientDataJSON),
        signature: b64RawEnc(sig),
        handle: hexEncode(userHandle),
        assertionClientExtensions: JSON.stringify(assertionClientExtensions)
    };

    // b64enc: MEYCIQDc2F-f9nAkEzdKmoD_Iql_F6CgDkhJt8bn0iVxpal0HAIhAJUkpIVU8t8fyMgzRJhh6H4UUYzBz6oevIk7b_YhhnpA
    // b64RawEnc: MEQCIAO0DPc0IN8zNl5aWDiPAkuc1RSxzxzTlKNAfHCuNzB6AiBvwmbinIdPftjfEuBykJXSsCICKtBi9UPr_h3QrrcyiQ==
    // example: iOHKX3erU5_OYP_r_9HLZ-CexCE4bQRrxM8WmuoKTDdhAnZSeTP0sjECjvjfeS8MJzN1ArmvV0H0C3yy_FdRFfcpUPZzdZ7bBcmPh1XPdxRwY747OrIzcTLTFQUPdn1U-izCZtP_78VGw9pCpdMsv4CUzZdJbEcRtQuRS03qUjqDaovoJhOqEBmxJn9Wu8tBi_Qx7A33RbYjlfyLm_EDqimzDZhyietyop6XUcpKarKqVH0M6mMrM5zTjp8xf3W7odFCadXEJg-ERZqFM0-9Uup6kJNLbr6C5J4NDYmSm3HCSA6lp2iEiMPKU8Ii7QZ61kybXLxsX4w4Dm3fOLjmDw
};

const postAssertionToServer = async (assertionDataForServer) => {
    const formData = new FormData();
    Object.entries(assertionDataForServer).forEach(([key, value]) => {
        formData.set(key, value);
    });
    
    return await fetch_json(
        "/verify_assertion", {
        method: "POST",
        body: formData
    });
}

document.addEventListener("DOMContentLoaded", e => {
    document.querySelector('#but1').addEventListener('click', didClickRegister);
    document.querySelector('#but2').addEventListener('click', didClickLogin);
});