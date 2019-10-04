"""
HTTP request signing

Generate Elliptic curve for Diffie Hellman key exchange
to sign token authentication requests.
"""

import logging
import struct
import base64
from datetime import datetime
from enum import Enum

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from xbox.webapi.common import filetimes

log = logging.getLogger('signer')


class SigningPolicy(object):
    def __init__(self, policy_version, extra_headers, max_body_bytes, supported_algos):
        """

        Args:
            policy_version (int): Policy version
            extra_headers (list): List of strings, containing additional http header values to hash/sign
            max_body_bytes (int): Max count of bytes to include while hashing
            supported_algos (list): List of supported signing algorithms
        """
        self.version = policy_version
        self.extra_headers = extra_headers
        self.max_body_bytes = max_body_bytes
        self.supported_algorithms = supported_algos


class SigningAlgorithmId(Enum):
    ES256 = 1
    ES384 = 2
    ES521 = 3


class SigningPolicies(object):
    SERVICE_AUTH_XBOXLIVE = SigningPolicy(1, [], 9223372036854775807, [SigningAlgorithmId.ES256])
    DEVICE_AUTH_XBOXLIVE = SigningPolicy(1, [], 9223372036854775807, [SigningAlgorithmId.ES256])
    XSTS_AUTH_XBOXLIVE = SigningPolicy(1, [], 9223372036854775807, [SigningAlgorithmId.ES256])


class JwkKeyContext(object):
    def __init__(self, private_key, signing_algorithm):
        """
        Initialized

        Args:
            private_key (ec.EllipticCurvePrivateKey): Private key
            signing_algorithm (SigningAlgorithmId): Signing algorithm
        """
        self._priv_key = private_key
        self._algo = signing_algorithm

    def get_proof_key(self):
        """
        Get proof key by serializing public key to JSON Web Key.
        Public Key X and Y get URL-safe base64 encoded.

        Returns:
            dict: Proof key dict
        """

        pub_x, pub_y = self.get_public_key_points(self._priv_key)
        curve = JwkKeyProvider.get_curve_name_for_algorithm(self._algo)
        key_type = JwkKeyProvider.get_key_type_for_algorithm_id(self._algo)

        proof_key = dict(
            alg=self._algo.name,
            use='sig',
            crv=curve,
            kty=key_type,
            x=base64.urlsafe_b64encode(pub_x).decode('utf8'),
            y=base64.urlsafe_b64encode(pub_y).decode('utf8')
        )

        return proof_key

    def sign_request(self, signing_policy, dt, request):
        """
        Create Signature header for authentication request.

        Args:
            signing_policy (SigningPolicy): Signing policy
            dt (datetime): Timestamp as datetime
            request (requests.PreparedRequest): Prepared request

        Returns:
            str: Ready-to-use Signature header value
        """
        header = self._assemble_header(signing_policy, dt)
        payload = self._assemble_signature_data(signing_policy, dt, request.method,
                                                request.path_url, request.body, request.headers)

        final_signature = header + self._sign_signature_data(payload)

        return base64.b64encode(final_signature)

    def _assemble_header(self, policy, dt):
        """
        Assemble (plaintext) signature header

        Args:
            policy (SigningPolicy): Signing policy
            dt (datetime): Timestamp

        Returns:
            bytes: The header
        """
        header_data = b''
        header_data += self.get_policy_version_buffer(policy.version)
        header_data += self.get_timestamp_buffer(dt)

        return header_data

    def _assemble_signature_data(self, policy, dt, http_method, http_path_and_query, http_body, http_headers):
        """
        Assemble payload to sign

        Args:
            policy (SigningPolicy): Signing policy
            dt (datetime): Datetime
            http_method (str): HTTP method (either GET or POST)
            http_path_and_query (str): HTTP path and query, including leading slash
            http_body (bytes): HTTP body
            http_headers (dict): Dict of HTTP headers

        Returns:
            bytes: Plaintext signature bytes
        """

        # Calculate how much body data to hash / sign
        body_size_to_hash = min(len(http_body), policy.max_body_bytes)

        def with_null_byte(data):
            """
            Return input data with appended null byte.
            If input is a string, encode it to UTF8 byte representation.

            Args:
                data: Input data

            Returns:
                bytes: Encoded data with trailing null byte
            """
            if isinstance(data, str):
                data = data.encode('utf8')

            if not isinstance(data, bytes):
                raise Exception('What to do with this data?')

            return data + b'\x00'

        # Assemble data stream to hash / sign
        data_to_sign = b''

        # Policy version in network byte-order
        data_to_sign += with_null_byte(self.get_policy_version_buffer(policy.version))

        # Timestamp in network byte-order
        data_to_sign += with_null_byte(self.get_timestamp_buffer(dt))

        # HTTP method in UPPERCASE
        data_to_sign += with_null_byte(str.upper(http_method))

        # urlPathAndQuery string (including leading slash)
        data_to_sign += with_null_byte(http_path_and_query)

        # Authorization header, if any - otherwise empty string
        data_to_sign += with_null_byte(http_headers.get('Authorization', ''))

        # Extra headers in order of signing policy
        for extra_header in policy.extra_headers:
            data_to_sign += with_null_byte(http_headers.get(extra_header, ''))

        # (Partitial) request body
        data_to_sign += with_null_byte(http_body[:body_size_to_hash])

        return data_to_sign

    def _sign_signature_data(self, data):
        """
        Sign provided data.

        Args:
            data (bytes): Data to sign

        Returns:
            bytes: Data signature
        """
        return self.sign_data(self._priv_key, self._algo, data)

    @staticmethod
    def get_policy_version_buffer(version):
        """
        Get policy version as bytes

        Args:
            version (int): Policy version

        Returns:
            bytes: Policy version (network order/big endian)
        """
        # Pack as UINT32
        return struct.pack('!I', version)

    @staticmethod
    def get_timestamp_buffer(dt):
        """
        Get usable buffer from datetime

        dt (datetime): Input datetime

        Returns:
            bytes: FILETIME buffer (network order/big endian)
        """
        filetime = filetimes.dt_to_filetime(dt)
        return struct.pack('!Q', filetime)

    @staticmethod
    def sign_data(private_key, algorithm_id, data):
        """
        Sign provided data.

        Args:
            private_key (ec.EllipticCurvePrivateKey): Private key to sign with
            algorithm_id (SigningAlgorithmId): Used algorithm
            data (bytes): Data to sign

        Returns:
            bytes: Data signature
        """
        hash_instance = JwkKeyProvider.get_hash_instance_for_algorithm(algorithm_id)
        ecdsa = ec.ECDSA(hash_instance)
        return private_key.sign(data, ecdsa)

    @staticmethod
    def get_public_key_points(private_key):
        """
        Get public key points X and Y

        Args:
            private_key (ec.EllipticCurvePrivateKey): Private key to derive from

        Returns:
            tuple: Tuple of bytes => EC points (x, y)
        """
        # Get public key obj
        public_key = private_key.public_key()

        # Serialize public key in DER format
        serialized_public = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Split into X and Y points
        keylen = len(serialized_public) // 2
        pub_x = serialized_public[:keylen]
        pub_y = serialized_public[keylen:]

        return pub_x, pub_y


class JwkKeyProvider(object):
    def __init__(self):
        """
        Initialize provider class
        """
        self.keys = {}

    def get_key(self, algorithm_id):
        """
        Generate jwk of desired type

        Args:
            algorithm_id (SigningAlgorithmId): Desired algorithm to use

        Returns:
            JwkKeyContext: Context to use for ProofKey generation and signature creation
        """
        if not isinstance(algorithm_id, SigningAlgorithmId):
            raise TypeError('desired_algorithm not of type SigningAlgorithmId')

        # Check if there was already a supported key generated
        existing_keycontext = self.keys.get(algorithm_id)
        if existing_keycontext:
            log.debug('Found existing key context {}'.format(algorithm_id))
            return existing_keycontext

        # Generate new curve
        log.debug('Generating key {}'.format(algorithm_id))

        # Generate JWK and store its context
        jw_key = self.generate_jwk_ec(algorithm_id)
        key_context = JwkKeyContext(jw_key, algorithm_id)
        self.keys[algorithm_id] = key_context

        return key_context

    def import_key(self, algorithm_id, key):
        """
        Import existing key context, possibly overwriting existing one

        Args:
            algorithm_id (SigningAlgorithmId): Used algorithm Id
            key(ec.EllipticCurvePrivateKey): Key to import

        Returns:
            JwkKeyContext: Context to use for ProofKey generation and signature creation
        """
        if not isinstance(algorithm_id, SigningAlgorithmId):
            raise TypeError('algorithm not of type SigningAlgorithmId')
        elif not isinstance(key, ec.EllipticCurvePrivateKey):
            raise TypeError('key not of type ec.EllipticCurvePrivateKey')

        context = JwkKeyContext(key, algorithm_id)
        self.keys[algorithm_id] = context

        return context

    @staticmethod
    def generate_jwk_ec(algorithm_id):
        """

        Args:
            algorithm_id (SigningAlgorithmId):

        Returns:
            ec.EllipticCurvePrivateKey: Generated key
        """
        curve = JwkKeyProvider.get_curve_instance_for_algorithm(algorithm_id)
        return ec.generate_private_key(curve, default_backend())

    @staticmethod
    def get_hash_instance_for_algorithm(algorithm_id):
        """
        Get hash instance for provided algorithm id

        Args:
            algorithm_id (SigningAlgorithmId):

        Returns:
            object: instance
        """
        if algorithm_id == SigningAlgorithmId.ES256:
            return hashes.SHA256()
        elif algorithm_id == SigningAlgorithmId.ES384:
            return hashes.SHA384()
        elif algorithm_id == SigningAlgorithmId.ES521:
            return hashes.SHA512()
        else:
            raise Exception('Unsupported algorithm_id: {}'.format(algorithm_id))

    @staticmethod
    def get_curve_instance_for_algorithm(algorithm_id):
        """
        Get curve instance for provided algorithm id

        Args:
            algorithm_id (SigningAlgorithmId):

        Returns:
            object: instance
        """
        if algorithm_id == SigningAlgorithmId.ES256:
            return ec.SECP256R1()
        elif algorithm_id == SigningAlgorithmId.ES384:
            return ec.SECP384R1()
        elif algorithm_id == SigningAlgorithmId.ES521:
            return ec.SECP521R1()
        else:
            raise Exception('Unsupported algorithm_id: {}'.format(algorithm_id))

    @staticmethod
    def get_curve_name_for_algorithm(algorithm_id):
        """
        Get curve name for provided algorithm id

        Args:
            algorithm_id (SigningAlgorithmId):

        Returns:
            str: Curve name
        """
        if algorithm_id == SigningAlgorithmId.ES256:
            return 'P-256'
        elif algorithm_id == SigningAlgorithmId.ES384:
            return 'P-384'
        elif algorithm_id == SigningAlgorithmId.ES521:
            return 'P-521'
        else:
            raise Exception('Unsupported algorithm_id: {}'.format(algorithm_id))

    @staticmethod
    def get_key_type_for_algorithm_id(algorithm_id):
        """
        Get curve name for provided private key

        Args:
            algorithm_id (SigningAlgorithmId):

        Returns:
            str: Key type
        """
        if algorithm_id == SigningAlgorithmId.ES256 or \
           algorithm_id == SigningAlgorithmId.ES384 or \
           algorithm_id == SigningAlgorithmId.ES521:
            return 'EC'

        else:
            raise Exception('Unsupported algorithm_id: {}'.format(algorithm_id))
