import os
import pytest

import requests
from xbox.webapi.common import signing


def jwk_256_priv1():
    return {
        "crv": "P-256",
        "kty": "EC",
        "x": "2pXN3DYeXy7O6FoL3n7SXtV7B_m3iC2XDY8tFQwO-nM",
        "y": "wLE-kcSWLhFtXqpy8hExGzFICJ2LPHp67fDt3EAY0NE",
        "d": "b_fLAQQs781TgcYb6MRF_BXkSkluLOVsrvAC25prITI"
    }


def jwk_256_priv2():
    return {
        "crv": "P-256",
        "kty": "EC",
        "x": "FZEKHp93DEOJ2-bX7AQu8QhWJ9L1-obYBAu-7ERHOb4",
        "y": "sEUGZ9jm5SNKzBFcxuvDcm0Qc2LB85YjGxhTwZZ0OyQ",
        "d": "04xuFEbXdrLsdTuIXGWxQkkbIMsSQPr1c1IpG5ox36A"
    }


def jwk_256_pub1():
    return {
        "crv": "P-256",
        "kty": "EC",
        "x": "nogsLHmgt98ySVZv8zNpg6N9yM3saEtHloYvLpJgBks",
        "y": "dlbHjqk7W0a0m7u8I4dfN2SJuCizhvS-zKON59ExfDw"
    }


def sample_http_request():
    url = "https://title.auth.xboxlive.com"
    headers = {"x-xbl-contract-version": "1"}
    data = {
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT",
        "Properties": {
            "AuthMethod": "RPS",
            "DeviceToken": "someToken",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": "someTicket"
        }
    }

    req = requests.Request('POST', url, json=data, headers=headers)
    return req.prepare()


def test_signing_sign_stuff():
    timestamp = 132143628570000000

    provider = signing.JwkKeyProvider()

    json_key = jwk_256_priv1()
    jwk = signing.jwk.JWK(**json_key)
    key_context = provider.import_key(signing.SigningAlgorithmId.ES256, jwk)

    signature = key_context.sign_request(timestamp, sample_http_request(), signing.SigningPolicies.SERVICE_AUTH_XBOXLIVE)

    assert signature is not None
    assert isinstance(signature, bytes)
    assert signature == b'AAAAAQHVd+4YPvqAKIM6tRq8VQUadKlabQSX9hU36Zj0lVJSnxuK7LgyG/tpVlgiA+cjYSISdRvoPG4xeR25Qs+4HcHbXDnFqmpI2Q=='


def test_signing_sign_stuff_pub_fail():
    timestamp = 132143628570000000

    provider = signing.JwkKeyProvider()

    json_key = jwk_256_pub1()
    jwk = signing.jwk.JWK(**json_key)
    key_context = provider.import_key(signing.SigningAlgorithmId.ES256, jwk)

    with pytest.raises(Exception):
        key_context.sign_request(timestamp, sample_http_request(), signing.SigningPolicies.SERVICE_AUTH_XBOXLIVE)

def test_signing_get_key():
    provider = signing.JwkKeyProvider()

    key = provider.get_key(signing.SigningAlgorithmId.ES256)
    key2 = provider.get_key(signing.SigningAlgorithmId.ES256)

    assert key is not None
    assert type(key) is signing.JwkKeyContext

    assert key is key2


def test_signing_get_different_algos():
    provider = signing.JwkKeyProvider()

    key_384 = provider.get_key(signing.SigningAlgorithmId.ES384)
    key_256 = provider.get_key(signing.SigningAlgorithmId.ES256)

    assert key_384 is not None
    assert key_256 is not None

    assert type(key_384) is signing.JwkKeyContext
    assert type(key_256) is signing.JwkKeyContext

    assert key_256 is not key_384


def test_signing_key_generation():
    provider = signing.JwkKeyProvider()

    key_256 = provider.generate_jwk_ec(signing.SigningAlgorithmId.ES256)
    key_521 = provider.generate_jwk_ec(signing.SigningAlgorithmId.ES521)

    assert key_256 is not None
    assert key_521 is not None

    assert type(key_256) is signing.jwk.JWK
    assert type(key_521) is signing.jwk.JWK

    assert key_256.key_curve == 'P-256'
    assert key_256.key_type == 'EC'

    assert key_521.key_curve == 'P-521'
    assert key_521.key_type == 'EC'

    assert key_256.has_private is True
    assert key_521.has_private is True

    print(key_256.__dict__)


def test_signing_context_get_proof_key():
    provider = signing.JwkKeyProvider()
    key = provider.get_key(signing.SigningAlgorithmId.ES521)
    proof_key = key.get_proof_key()

    assert proof_key is not None
    assert type(proof_key) is dict

    assert 'alg' in proof_key
    assert 'use' in proof_key
    assert 'crv' in proof_key
    assert 'kty' in proof_key
    assert 'x' in proof_key
    assert 'y' in proof_key

    assert proof_key['alg'] == 'ES521'
    assert proof_key['use'] == 'sig'
    assert proof_key['crv'] == 'P-521'
    assert proof_key['kty'] == 'EC'

    assert type(proof_key['x']) is str
    assert type(proof_key['y']) is str