import os
import json
import pytest
import requests
import betamax
import binascii
from datetime import datetime
from xbox.webapi.api.client import XboxLiveClient

current_dir = os.path.dirname(__file__)

with betamax.Betamax.configure() as config:
    config.cassette_library_dir = os.path.join(current_dir,
                                               'data/cassettes')
    config.default_cassette_options['record_mode'] = 'none'


@pytest.fixture(scope='session')
def redirect_url():
    return "https://login.live.com/oauth20_desktop.srf?lc=1033#access_token=AccessToken&token_type=bearer&" \
           "expires_in=86400&scope=service::user.auth.xboxlive.com::MBI_SSL&refresh_token=RefreshToken&" \
           "user_id=1005283eaccf208b"


@pytest.fixture(scope='session')
def jwt():
    return "eyJlSGVsbG9JYW1BVGVzdFRva2VuSnVzdEZvclRoZXNlVW5pdFRlc3Rz" \
           "X0hvcGVmdWxseUFsbFRoZVRlc3RzVHVybk91dEdvb2RfR29vZEx1Y2s="


@pytest.fixture(scope='session')
def token_datetime():
    return datetime(year=2099, month=10, day=11, hour=1)


@pytest.fixture(scope='session')
def token_timestring():
    return "2099-10-11T01:00:00.000000Z"


@pytest.fixture(scope='session')
def token_expired_timestring():
    return "2000-10-11T01:00:00.000000Z"


@pytest.fixture(scope='session')
def windows_live_authenticate_response():
    filepath = os.path.join(current_dir, 'data', 'wl_auth_response.html')
    with open(filepath, 'r') as f:
        return f.read()


@pytest.fixture(scope='session')
def windows_live_authenticate_response_two_js_obj():
    filepath = os.path.join(current_dir, 'data', 'wl_auth_response_two_js_obj.html')
    with open(filepath, 'r') as f:
        return f.read()


@pytest.fixture(scope='session')
def tokens_filepath():
    filepath = os.path.join(current_dir, 'data', 'tokens.json')
    return filepath


@pytest.fixture(scope='session')
def tokens_json(tokens_filepath):
    with open(tokens_filepath, 'r') as f:
        return json.load(f)


@pytest.fixture(scope='session')
def signature_datetime():
    return datetime.utcfromtimestamp(1500000000)


@pytest.fixture(scope='session')
def jwk_256_privkey():
    return {
        "crv": "P-256",
        "kty": "EC",
        "x": "2pXN3DYeXy7O6FoL3n7SXtV7B_m3iC2XDY8tFQwO-nM",
        "y": "wLE-kcSWLhFtXqpy8hExGzFICJ2LPHp67fDt3EAY0NE",
        "d": "b_fLAQQs781TgcYb6MRF_BXkSkluLOVsrvAC25prITI"
    }


@pytest.fixture(scope='session')
def jwk_256_pubkey():
    return {
        "crv": "P-256",
        "kty": "EC",
        "x": "2pXN3DYeXy7O6FoL3n7SXtV7B_m3iC2XDY8tFQwO-nM",
        "y": "wLE-kcSWLhFtXqpy8hExGzFICJ2LPHp67fDt3EAY0NE"
    }


@pytest.fixture(scope='session')
def secp256r1_der_privkey():
    return binascii.unhexlify(b'308187020100301306072a8648ce3d020106082a8648ce'
                              b'3d030107046d306b0201010420f5fc8d810f5aa5cd18f0'
                              b'c08d958344d83be8c6a805726545d00baa0015e0798ea1'
                              b'4403420004e2ae6657ad0b9452a3e873007779ba903dee'
                              b'155a0993a369f9e5e0b195aaa4caa27c9e541cfbedd845'
                              b'5943da3c1ba08702208c6e288d58698ed5e97ff919807b')


@pytest.fixture(scope='session')
def secp256r1_der_pubkey():
    return binascii.unhexlify(b'3059301306072a8648ce3d020106082a8648ce3d030107'
                              b'03420004e2ae6657ad0b9452a3e873007779ba903dee15'
                              b'5a0993a369f9e5e0b195aaa4caa27c9e541cfbedd84559'
                              b'43da3c1ba08702208c6e288d58698ed5e97ff919807b')


@pytest.fixture(scope='session')
def sample_xboxlive_auth_request():
    url = "https://title.auth.xboxlive.com"
    headers = {"x-xbl-contract-version": "1"}
    data = '{"RelyingParty":"http://auth.xboxlive.com",' \
           '"TokenType":"JWT","Properties":' \
           '{"AuthMethod":"RPS",' \
           '"DeviceToken":"someToken",' \
           '"SiteName":"user.auth.xboxlive.com",' \
           '"RpsTicket":"someTicket"}}'

    req = requests.Request('POST', url, data=data, headers=headers)
    return req.prepare()


@pytest.fixture(scope='session')
def xbl_client():
    return XboxLiveClient(
        userhash='012345679',
        auth_token='eyToken==',
        xuid='987654321'
    )
