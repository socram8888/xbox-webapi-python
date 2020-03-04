import os
import sys
import json
import argparse
import vcr

from xbox.webapi.authentication.manager import AuthenticationManager
from xbox.webapi.scripts import TOKENS_FILE
from xbox.webapi.api.client import XboxLiveClient

current_dir = os.path.dirname(__file__)
CASSETTE_LIBRARY_DIR = os.path.join(current_dir, 'data/cassettes/')


def recorder_session():
    """

    Returns:
        vcr.VCR: VCR session
    """


    """
    config.define_cassette_placeholder(
        "<UHS>", mgr.userinfo.userhash
    )
    config.define_cassette_placeholder(
        "<JWT>", mgr.xsts_token.jwt
    )
    config.define_cassette_placeholder(
        "<XUID>", str(mgr.userinfo.xuid)
    )
    """
    return vcr.VCR(
        serializer='json',
        cassette_library_dir=CASSETTE_LIBRARY_DIR,
        record_mode='new_episodes',
        match_on=['uri', 'method'],
        decode_compressed_response=False
    )


def main():
    parser = argparse.ArgumentParser(description="Search for Content on XBL")
    parser.add_argument('--tokens', '-t', default=TOKENS_FILE,
                        help="Token file, if file doesnt exist it gets created")
    args = parser.parse_args()

    mgr = AuthenticationManager.from_file(args.tokens)

    client = XboxLiveClient(mgr.userinfo.userhash,
                            mgr.xsts_token.jwt,
                            mgr.userinfo.xuid)

    """
    EDIT TO RECORD NEW API ENDPOINT
    """

    with recorder_session().use_cassette('test_recording.json'):
        r = client.titlehub.get_titles_batch(
            ['Microsoft.SeaofThieves_8wekyb3d8bbwe', 'Microsoft.XboxApp_8wekyb3d8bbwe']
        )
        print(r)


if __name__ == '__main__':
    main()
