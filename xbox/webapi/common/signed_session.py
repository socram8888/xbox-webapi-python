"""
Signed Session

A wrapper around requests' Session which transparently calculates the "Signature" header.
"""

from requests import Session
from urllib.parse import urlsplit, urlunsplit
from xbox.webapi.common.request_signer import RequestSigner


class SignedSession(Session):

    def __init__(self, request_signer=None):
        super().__init__()
        self.request_signer = request_signer or RequestSigner()

    def prepare_request(self, request):
        prepared = super().prepare_request(request)

        parsed_url = urlsplit(prepared.url)
        path_and_query = urlunsplit(('', '', parsed_url.path, parsed_url.query, ''))
        authorization = prepared.headers.get('Authorization', '')

        if prepared.body:
            if not isinstance(prepared.body, bytes):
                prepared.body = prepared.body.encode('ascii')
            body = prepared.body
        else:
            body = b''

        signature = self.request_signer.sign(method=prepared.method, path_and_query=path_and_query,
                                             body=body, authorization=authorization)

        prepared.headers['Signature'] = signature
        return prepared
