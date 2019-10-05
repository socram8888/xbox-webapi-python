import base64
import pytest

from xbox.webapi.common.signing import SigningPolicies, SigningPolicy, SigningAlgorithmId,\
                                       JwkKeyProvider, JwkKeyContext, ec


def test_assemble_header(signature_datetime):
    key_ctx = JwkKeyProvider().get_key(SigningAlgorithmId.ES256)

    policy = SigningPolicy(1, [], 123, [])
    header_data = key_ctx._assemble_header(policy, signature_datetime)

    assert header_data == b'\x00\x00\x00\x01\x01\xd2\xfc\x4a\x7c\xe0\x00\x00'


def test_assemble_signature(secp256r1_der_privkey, signature_datetime, sample_xboxlive_auth_request):
    http_request = sample_xboxlive_auth_request
    key = JwkKeyProvider.deserialize_der_private_key(secp256r1_der_privkey)

    context = JwkKeyContext(key, SigningAlgorithmId.ES256)
    signature_data = context._assemble_signature_data(
        SigningPolicies.SERVICE_AUTH_XBOXLIVE,
        signature_datetime,
        http_request.method,
        http_request.path_url,
        http_request.body,
        http_request.headers)

    assert isinstance(signature_data, bytes)
    assert signature_data == base64.b64decode(b'AAAAAQAB0vxKfOAAAABQT1NUAC8AAHsiUmVseWluZ1BhcnR5IjoiaHR0cDovL2F1dGgueGJ'
                                              b'veGxpdmUuY29tIiwiVG9rZW5UeXBlIjoiSldUIiwiUHJvcGVydGllcyI6eyJBdXRoTWV0aG'
                                              b'9kIjoiUlBTIiwiRGV2aWNlVG9rZW4iOiJzb21lVG9rZW4iLCJTaXRlTmFtZSI6InVzZXIuY'
                                              b'XV0aC54Ym94bGl2ZS5jb20iLCJScHNUaWNrZXQiOiJzb21lVGlja2V0In19AA==')


def test_sign_stuff(secp256r1_der_privkey, signature_datetime, sample_xboxlive_auth_request):
    algo = SigningAlgorithmId.ES256

    provider = JwkKeyProvider()

    key = JwkKeyProvider.deserialize_der_private_key(secp256r1_der_privkey)
    key_context = provider.import_key(algo, key)

    signature = key_context.create_signature(SigningPolicies.SERVICE_AUTH_XBOXLIVE,
                                             signature_datetime, sample_xboxlive_auth_request)

    assert signature is not None
    assert isinstance(signature, bytes)

    expected = base64.b64decode(b'AAAAAQHS/Ep84AAAMEYCIQC4rN7knsj/IVHPcK27DNoYw8fOtXRC'
                                         b'zdM5T3gY/HHwnwIhAKZQ6vEg+WiSzgNSKeIXhCum9TN994Eifmy+'
                                         b'tbug6vMb')

    assert signature == expected


def test_signature_verification(secp256r1_der_privkey, signature_datetime, sample_xboxlive_auth_request):
    algo = SigningAlgorithmId.ES256

    provider = JwkKeyProvider()

    key = JwkKeyProvider.deserialize_der_private_key(secp256r1_der_privkey)
    key_context = provider.import_key(algo, key)

    signature = key_context.create_signature(SigningPolicies.SERVICE_AUTH_XBOXLIVE,
                                             signature_datetime, sample_xboxlive_auth_request)

    success = key_context.verify_signature(SigningPolicies.SERVICE_AUTH_XBOXLIVE,
                                           sample_xboxlive_auth_request, signature)

    assert success is True


def test_signature_verification_fail(secp256r1_der_privkey, signature_datetime, sample_xboxlive_auth_request):
    algo = SigningAlgorithmId.ES256

    provider = JwkKeyProvider()

    key = JwkKeyProvider.deserialize_der_private_key(secp256r1_der_privkey)
    key_context = provider.import_key(algo, key)

    signature = key_context.create_signature(SigningPolicies.SERVICE_AUTH_XBOXLIVE,
                                             signature_datetime, sample_xboxlive_auth_request)

    signature = bytearray(signature)
    signature[-1] = 0xFF
    signature[-2] = 0xFF
    signature[-3] = 0xFF
    signature = bytes(signature)

    success = key_context.verify_signature(SigningPolicies.SERVICE_AUTH_XBOXLIVE,
                                           sample_xboxlive_auth_request, signature)

    assert success is False


def test_sign_stuff_pub_fail(secp256r1_der_pubkey, signature_datetime, sample_xboxlive_auth_request):
    algo = SigningAlgorithmId.ES256

    provider = JwkKeyProvider()

    key = JwkKeyProvider.deserialize_der_public_key(secp256r1_der_pubkey)
    key_context = provider.import_key(algo, key)

    with pytest.raises(Exception):
        key_context.create_signature(SigningPolicies.SERVICE_AUTH_XBOXLIVE,
                                     signature_datetime, sample_xboxlive_auth_request)


def test_get_key():
    provider = JwkKeyProvider()

    key_ctx = provider.get_key(SigningAlgorithmId.ES256)
    key_ctx2 = provider.get_key(SigningAlgorithmId.ES256)

    assert key_ctx is not None
    assert isinstance(key_ctx, JwkKeyContext)

    assert key_ctx is key_ctx2


def test_get_different_algos():
    provider = JwkKeyProvider()

    key_ctx_384 = provider.get_key(SigningAlgorithmId.ES384)
    key_ctx_256 = provider.get_key(SigningAlgorithmId.ES256)

    assert key_ctx_384 is not None
    assert key_ctx_256 is not None

    assert type(key_ctx_384) is JwkKeyContext
    assert type(key_ctx_256) is JwkKeyContext

    assert key_ctx_256 is not key_ctx_384


def test_key_generation():
    provider = JwkKeyProvider()

    key_256 = provider.generate_jwk_ec(SigningAlgorithmId.ES256)
    key_521 = provider.generate_jwk_ec(SigningAlgorithmId.ES521)

    assert key_256 is not None
    assert key_521 is not None

    assert isinstance(key_256, ec.EllipticCurvePrivateKey)
    assert isinstance(key_521, ec.EllipticCurvePrivateKey)

    priv = JwkKeyProvider.serialize_der_private_key(key_256)
    pub = JwkKeyProvider.serialize_der_public_key(key_256.public_key())

    assert key_256.key_size == 256
    assert key_256.curve.name == 'secp256r1'

    assert key_521.key_size == 521
    assert key_521.curve.name == 'secp521r1'


def test_context_get_proof_key():
    provider = JwkKeyProvider()
    key_ctx = provider.get_key(SigningAlgorithmId.ES521)

    proof_key = key_ctx.get_proof_key()

    assert proof_key is not None
    assert isinstance(proof_key, dict)

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

    assert isinstance(proof_key['x'], str)
    assert isinstance(proof_key['y'], str)
