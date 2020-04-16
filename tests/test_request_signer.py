from xbox.webapi.common.request_signer import RequestSigner
from ecdsa import SigningKey

def test_signing():
    with open('tests/data/test_signing_key.pem') as f:
        signing_key = SigningKey.from_pem(f.read())

    signer = RequestSigner(signing_key)

    correct_proof = {
        'crv': 'P-256',
        'alg': 'ES256',
        'use': 'sig',
        'kty': 'EC',
        'x': 'OKyCQ9qH5U4lZcS0c5_LxIyKvOpKe0l3x4Eg5OgDbzc',
        'y': 'syjS0YE9vH3eBat61P9TkCpseo0qtL0weQKP-PJtIho'
    }
    assert signer.proof_field == correct_proof

    timestamp = 1586999965

    test_hash = signer._hash(method='POST', path_and_query='/path?query=1', body=b'thebodygoeshere',
                             authorization='XBL3.0 x=userid;jsonwebtoken', ts_bytes=timestamp.to_bytes(8, 'big'))
    assert test_hash.hex() == '9d3c6365f3a07b03de582d59f01c1e8265b25ca679ddef8ee58e9886a4fca10f'

    test_signature = signer.sign(method='POST', path_and_query='/path?query=1', body=b'thebodygoeshere',
                                 authorization='XBL3.0 x=userid;jsonwebtoken', timestamp=1586999965)

    assert(test_signature == 'AAAAAQAAAABel7Kd/FgavClh7YZK5qB0NVGcMPfP0NgNM2gPXiUB7PzXQewVq6D2M7nkEjMolOGkjnEm5pphuXSAtreYV14HPTJaDA==')
