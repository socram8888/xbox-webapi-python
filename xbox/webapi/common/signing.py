"""
HTTP request signing

Generate Elliptic curve for Diffie Hellman key exchange
to sign token authentication requests.
"""

import logging
import struct
import json
import base64
from datetime import datetime
from hashlib import sha256, sha384, sha512
from urllib.parse import urlparse

from jwcrypto import jwk, jws
from xbox.webapi.common import filetimes

log = logging.getLogger('signer')


class SigningAlgorithm(object):
    def __init__(self, algorithm_name, key_type, curve, use, hash_method, key_size):
        self.algorithm_name = algorithm_name
        self.key_type = key_type
        self.curve = curve
        self.use = use
        self.hash_method = hash_method
        self.key_size = key_size

    def __repr__(self):
        return '<SigningAlgorithm name={} key_type={} curve={} use={} hash_method={} key_size={}'.format(
            self.algorithm_name, self.key_type, self.curve, self.use, self.hash_method, self.key_size)


class SigningPolicy(object):
    def __init__(self, policy_version, extra_headers, max_body_bytes, supported_algos):
        self.version = policy_version
        self.extra_headers = extra_headers
        self.max_body_bytes = max_body_bytes
        self.supported_algorithms = supported_algos


class SigningAlgorithmId(object):
    ES256 = SigningAlgorithm('ES256', 'EC', 'P-256', 'sig', sha256, 256)
    ES384 = SigningAlgorithm('ES384', 'EC', 'P-384', 'sig', sha384, 384)
    ES521 = SigningAlgorithm('ES521', 'EC', 'P-521', 'sig', sha512, 512)


class SigningPolicies(object):
    SERVICE_AUTH_XBOXLIVE = SigningPolicy(1, [], 9223372036854775807, [SigningAlgorithmId.ES256])
    DEVICE_AUTH_XBOXLIVE = SigningPolicy(1, [], 9223372036854775807, [SigningAlgorithmId.ES256])
    XSTS_AUTH_XBOXLIVE = SigningPolicy(1, [], 9223372036854775807, [SigningAlgorithmId.ES256])


class JwkKeyContext(object):
    def __init__(self, jwk_obj, signing_algorithm):
        """
        Initialized

        Args:
            jwk_obj (jwk.JWK):
            signing_algorithm (SigningAlgorithm):
        """
        self._jwk = jwk_obj
        self._algo = signing_algorithm

    def get_proof_key(self):
        """
        Get proof key

        Returns:
            dict: Proof key dict
        """
        # Assemble proof key
        proof_key = json.loads(self._jwk.export_public())

        """
        Following dict-keys need to be added manually
        """
        # Algorithm
        proof_key['alg'] = self._algo.algorithm_name  # e.g. 'ES256', 'ES256' etc
        # Use
        proof_key['use'] = 'sig'  # For signing

        return proof_key

    def sign_request(self, timestamp, request, signing_policy):
        """
        Create Signature header for authentication request.

        Args:
            timestamp (int): Timestamp as FILETIME
            request (requests.PreparedRequest): Prepared request
            signing_policy (SigningPolicy):

        Returns:
            str: Ready-to-use Signature header value
        """
        header = self._assemble_header(signing_policy, timestamp)
        payload = self._assemble_signature(signing_policy, timestamp, request.method,
                                           request.path_url, request.body, request.headers)
        signed_payload = self._sign_data(payload)

        final_signature = header + signed_payload

        return base64.b64encode(final_signature)

    def _assemble_header(self, policy, timestamp):
        """
        Assemble (plaintext) signature header

        Args:
            policy (SigningPolicy):
            timestamp (int):

        Returns:
            bytes: The header
        """
        header_data = b''
        header_data += struct.pack('!I', policy.version)
        header_data += struct.pack('!Q', timestamp)

        return header_data

    def _assemble_signature(self, policy, timestamp, http_method, http_path_and_query, http_body, http_headers):
        """
        Assemble payload to sign

        Args:
            policy (SigningPolicy):
            timestamp (int):
            http_method (str):
            http_path_and_query (str):
            http_body (bytes):
            http_headers (dict):

        Returns:
            bytes: Plaintext signature bytes
        """

        # Calculate how much body data to hash / sign
        body_size_to_hash = min(len(http_body), policy.max_body_bytes)

        # Assemble data stream to hash / sign
        data_to_sign = b''
        # Policy version in network byte-order
        data_to_sign += struct.pack('!I', policy.version) + b'\x00'
        # Timestamp in network byte-order
        data_to_sign += struct.pack('!Q', timestamp) + b'\x00'
        # HTTP method in uppercase
        data_to_sign += str.upper(http_method).encode('utf8') + b'\x00'
        # urlPathAndQuery string (including leading slash)
        data_to_sign += http_path_and_query.encode('utf8') + b'\x00'
        # Authorization header, if any - otherwise empty string
        data_to_sign += http_headers.get('Authorization', '').encode('utf8') + b'\x00'

        # Extra headers in order of signing policy
        for extra_header in policy.extra_headers:
            data_to_sign += http_headers.get(extra_header, '').encode('utf8') + b'\x00'

        # (Partitial) request body
        data_to_sign += http_body[:body_size_to_hash] + b'\x00'

        return data_to_sign

    def _sign_data(self, data):
        """
        Encrypt supplied data via private key.

        Args:
            data (bytes): Data to encrypt
            algo (SigningAlgorithm):
            keypair (jwk.JWK): Key to use for signing

        Returns:
            bytes: Encrypted data
        """
        jwt_obj = jws.JWS(data)
        jwt_obj.add_signature(self._jwk, alg=self._algo.algorithm_name)

        return jwt_obj.objects['signature']

class JwkKeyProvider(object):
    def __init__(self):
        """
        Initialize provider class
        """
        self.keypairs = {}

    def get_key(self, desired_algorithm):
        """
        Generate jwk of desired type

        Args:
            desired_algorithm (SigningAlgorithm): Desired algorithm to use

        Returns:
            JwkKeyContext: Context to use for ProofKey generation and signature creation
        """

        algo_name = desired_algorithm.algorithm_name

        # Check if there was already a supported key generated
        existing_keycontext = self.keypairs.get(algo_name)
        if existing_keycontext:
            log.debug('Found existing key context {}'.format(algo_name))
            return existing_keycontext

        # Generate new curve
        log.debug('Generating key {}'.format(algo_name))

        # Generate JWK and store its context
        jw_key = self.generate_jwk_ec(desired_algorithm)
        key_context = JwkKeyContext(jw_key, desired_algorithm)
        self.keypairs[algo_name] = key_context

        return key_context

    def import_key(self, algorithm, key):
        """
        Import existing key context, possibly overwriting existing one

        Args:
            algorithm (SigningAlgorithm): Used algorithm
            key(jwk.JWK): Key to import

        Returns:
            JwkKeyContext: Context to use for ProofKey generation and signature creation
        """
        if not isinstance(algorithm, SigningAlgorithm):
            raise TypeError('algorithm not of type SigningAlgorithm')
        elif not isinstance(key, jwk.JWK):
            raise TypeError('key not of type jwk.JWK')

        context = JwkKeyContext(key, algorithm)
        self.keypairs[algorithm.algorithm_name] = context

        return context

    @staticmethod
    def generate_jwk_ec(desired_algorithm):
        return jwk.JWK.generate(kty=desired_algorithm.key_type, crv=desired_algorithm.curve)
