import os
import json
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    UserVerificationRequirement,
    AuthenticationCredential,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    RegistrationCredential,
)
import queue
import random
import six
import string
import base64
import hashlib
import ecdsa
from flask import Flask
from flask import render_template
from flask import jsonify
from flask import make_response
from flask import request
app = Flask(__name__)

CHALLENGE_DEFAULT_BYTE_LEN = 32
UKEY_DEFAULT_BYTE_LEN = 20
USERNAME_MAX_LENGTH = 32
DISPLAY_NAME_MAX_LENGTH = 65

RP_ID = 'localhost'
RP_NAME = 'webauthn demo localhost'
ORIGIN = 'http://localhost:5000'
TRUST_ANCHOR_DIR = 'trusted_attestation_roots'
previous_username = queue.Queue()
user = dict()

@app.route("/")
def hello():
    return render_template('index.html')

@app.route("/getCredential", methods=['post', 'get'])
def getCredential():
    username = request.form.get('Username')
    # display = request.form.get('Display')

    challenge_bytes = os.urandom(CHALLENGE_DEFAULT_BYTE_LEN)
    challenge_base64 = base64.urlsafe_b64encode(challenge_bytes)	
    if not isinstance(challenge_base64, str):
        challenge_base64 = challenge_base64.decode('utf-8')
    # e_challenge.put(challenge_base64)

    ukey_bytes = os.urandom(UKEY_DEFAULT_BYTE_LEN)
    ukey_base64 = base64.urlsafe_b64encode(ukey_bytes)	
    if not isinstance(ukey_base64, str):
        ukey_base64 = ukey_base64.decode('utf-8')
    ukey = ukey_base64

    # make_credential_options = generate_registration_options(
    #     rp_id=RP_ID, rp_name=RP_NAME, user_id=ukey, user_name=username, user_display_name=display)
    
    make_credential_options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=ukey,
        user_name=username,
        attestation=AttestationConveyancePreference.DIRECT,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
            resident_key=ResidentKeyRequirement.REQUIRED,
        ),
        challenge=b"1234567890",
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=b"1234567890"),
        ],
        # supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_512],
        timeout=120000,
    )

    # e_challenge.put(json.loads(options_to_json(make_credential_options))['challenge'])
    print(json.loads(options_to_json(make_credential_options))['challenge'])

    previous_username.put(username)
    return options_to_json(make_credential_options)

@app.route("/verify_credential_info", methods=['post', 'get'])
def verifyCredential(): 
    formData = {"id": request.form.get('id'), "rawId": request.form.get('rawId'), "response": {"attestationObject": request.form.get('attObj'), "clientDataJSON": request.form.get('clientData')}, "type": request.form.get('type')}
    # e_c = e_challenge.get().rstrip('=')
    try:
        webauthn_credential = verify_registration_response(
                            credential=RegistrationCredential.parse_raw(json.dumps(formData)),
                            expected_challenge=b"1234567890",
                            expected_origin="http://localhost:5000",
                            expected_rp_id="localhost",
                            require_user_verification=True,    
                        )
    except Exception as e:
        return jsonify({'fail': 'Registration failed. Error: {}'.format(e)})
    
    print(json.loads(options_to_json(webauthn_credential)))
    user[previous_username.get()] = (json.loads(options_to_json(webauthn_credential))['credentialPublicKey'], json.loads(options_to_json(webauthn_credential))['credentialId'])
    user['credentialPublicKey'] = json.loads(options_to_json(webauthn_credential))['credentialPublicKey']
    user['credentialId'] = json.loads(options_to_json(webauthn_credential))['credentialId']
    return jsonify({'success': 1})

@app.route("/webauthn_begin_assertion", methods=['post', 'get'])
def begin_assertion():
    print(request.form.get('Username'))
    previous_username.put(request.form.get('Username'))
    authentication_options = generate_authentication_options(
        rp_id=RP_ID,
        challenge=b"1234567890",
        allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(user[request.form.get('Username')][1]))],
    )
    print(options_to_json(authentication_options))
    return options_to_json(authentication_options)

'''
{"challenge": "MTIzNDU2Nzg5MA", "timeout": 60000, "rpId": "localhost", "allowCredentials": [], "userVerification": "preferred"}
'''


@app.route("/verify_assertion", methods=['post', 'get'])
def verify_assertion():
    print("start authentication:")
    #try: 
    print(request.form.get('id'))
    try:
        authentication_verification = verify_authentication_response(
            credential=AuthenticationCredential.parse_raw( # Decodes Base64URL to bytes
                json.dumps({
                    "id": request.form.get('id'),
                    "rawId": request.form.get('rawId'),
                    "response": {
                        "authenticatorData": request.form.get('authData'),
                        "clientDataJSON": request.form.get('clientData'),
                        "signature": request.form.get('signature'),
                        "userHandle": request.form.get('handle')
                    },
                    "type": request.form.get('type'),
                    "clientExtensionResults": {}
                })
            ),
            expected_challenge=b"1234567890",
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=base64url_to_bytes(
               user[previous_username.get()][0]
            ),
            credential_current_sign_count=0,
            require_user_verification=True,
        )
    except Exception as e:
        return jsonify({'fail': 'Authentication failed. Error: {}'.format(e)})
    print('done')
    return jsonify({'success': 1})


if __name__ == '__main__':
        app.run(host='0.0.0.0', ssl_context='adhoc', debug=True)


'''
    id: newAssertion.id,
    rawId: b64enc(rawId),
    type: newAssertion.type,
    authData: b64RawEnc(authData),
    clientData: b64RawEnc(clientDataJSON),
    signature: hexEncode(sig),
    assertionClientExtensions: JSON.stringify(assertionClientExtensions)
'''
'''
credential=AuthenticationCredential.parse_raw(
            """{
                "id": "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s",
                "rawId": "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s",
                "response": {
                    "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAQ",
                    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaVBtQWkxUHAxWEw2b0FncTNQV1p0WlBuWmExekZVRG9HYmFRMF9LdlZHMWxGMnMzUnRfM280dVN6Y2N5MHRtY1RJcFRUVDRCVTFULUk0bWFhdm5kalEiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                    "signature": "iOHKX3erU5_OYP_r_9HLZ-CexCE4bQRrxM8WmuoKTDdhAnZSeTP0sjECjvjfeS8MJzN1ArmvV0H0C3yy_FdRFfcpUPZzdZ7bBcmPh1XPdxRwY747OrIzcTLTFQUPdn1U-izCZtP_78VGw9pCpdMsv4CUzZdJbEcRtQuRS03qUjqDaovoJhOqEBmxJn9Wu8tBi_Qx7A33RbYjlfyLm_EDqimzDZhyietyop6XUcpKarKqVH0M6mMrM5zTjp8xf3W7odFCadXEJg-ERZqFM0-9Uup6kJNLbr6C5J4NDYmSm3HCSA6lp2iEiMPKU8Ii7QZ61kybXLxsX4w4Dm3fOLjmDw",
                    "userHandle": "T1RWa1l6VXdPRFV0WW1NNVlTMDBOVEkxTFRnd056Z3RabVZpWVdZNFpEVm1ZMk5p"
                },
                "type": "public-key",
                "clientExtensionResults": {}
            }"""
        ),
        expected_challenge=base64url_to_bytes(
        "iPmAi1Pp1XL6oAgq3PWZtZPnZa1zFUDoGbaQ0_KvVG1lF2s3Rt_3o4uSzccy0tmcTIpTTT4BU1T-I4maavndjQ"
        ),
        expected_rp_id=RP_ID,
        expected_origin=ORIGIN,
        credential_public_key=base64url_to_bytes(
            "pAEDAzkBACBZAQDfV20epzvQP-HtcdDpX-cGzdOxy73WQEvsU7Dnr9UWJophEfpngouvgnRLXaEUn_d8HGkp_HIx8rrpkx4BVs6X_B6ZjhLlezjIdJbLbVeb92BaEsmNn1HW2N9Xj2QM8cH-yx28_vCjf82ahQ9gyAr552Bn96G22n8jqFRQKdVpO-f-bvpvaP3IQ9F5LCX7CUaxptgbog1SFO6FI6ob5SlVVB00lVXsaYg8cIDZxCkkENkGiFPgwEaZ7995SCbiyCpUJbMqToLMgojPkAhWeyktu7TlK6UBWdJMHc3FPAIs0lH_2_2hKS-mGI1uZAFVAfW1X-mzKL0czUm2P1UlUox7IUMBAAE"
        ),
        credential_current_sign_count=0,
        require_user_verification=True,
    )
'''