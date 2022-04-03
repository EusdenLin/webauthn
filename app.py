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

dict = {}
RP_ID = 'localhost'
RP_NAME = 'webauthn demo localhost'
ORIGIN = 'https://localhost:5000'
TRUST_ANCHOR_DIR = 'trusted_attestation_roots'
e_challenge = queue.Queue()
user = {}

@app.route("/")
def hello():
    return render_template('index.html')

@app.route("/getCredential", methods=['post', 'get'])
def getCredential():
    username = request.form.get('Username')
    display = request.form.get('Display')

    challenge_bytes = os.urandom(CHALLENGE_DEFAULT_BYTE_LEN)
    challenge_base64 = base64.urlsafe_b64encode(challenge_bytes)	
    if not isinstance(challenge_base64, str):
        challenge_base64 = challenge_base64.decode('utf-8')
    e_challenge.put(challenge_base64)

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
        user_display_name=display,
        attestation=AttestationConveyancePreference.DIRECT,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.REQUIRED,
        ),
        challenge=b"1234567890",
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=b"1234567890"),
        ],
        supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_512],
        timeout=12000,
    )

    e_challenge.put(json.loads(options_to_json(make_credential_options))['challenge'])
    print(json.loads(options_to_json(make_credential_options))['challenge'])

    user.clear()
    user['name'] = username
    return options_to_json(make_credential_options)

@app.route("/verify_credential_info", methods=['post', 'get'])
def verifyCredential(): 
    formData = {"id": request.form.get('id'), "rawId": request.form.get('rawId'), "response": {"attestationObject": request.form.get('attObj'), "clientDataJSON": request.form.get('clientData')}, "type": request.form.get('type')}
    e_c = e_challenge.get().rstrip('=')
    try:
        webauthn_credential = verify_registration_response(
                            credential=RegistrationCredential.parse_raw(json.dumps(formData)),
                            expected_challenge=base64url_to_bytes(
                                e_c
                                ),
                            expected_origin="http://localhost:5000",
                            expected_rp_id="localhost",
                            require_user_verification=True,    
                        )
    except Exception as e:
        return jsonify({'fail': 'Registration failed. Error: {}'.format(e)})
    
    print(json.loads(options_to_json(webauthn_credential)))
    user['credentialPublicKey'] = json.loads(options_to_json(webauthn_credential))['credentialPublicKey']
    user['credentialId'] = json.loads(options_to_json(webauthn_credential))['credentialId']
    return jsonify({'success': 1})

@app.route("/webauthn_begin_assertion", methods=['post', 'get'])
def begin_assertion():
    simple_authentication_options = generate_authentication_options(rp_id=RP_ID)
    print(simple_authentication_options)
    print(request.form.get('Username'))
    print(user)
    return options_to_json(simple_authentication_options)

@app.route("/verify_assertion", methods=['post', 'get'])
def verify_assertion():
    print('hello')

if __name__ == '__main__':
        app.run(host='0.0.0.0', ssl_context='adhoc', debug=True)
