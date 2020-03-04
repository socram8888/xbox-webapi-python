import sys
import os
import json
import gzip
import base64
import argparse
import logging

logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)


def _load_cassette(filepath):
    with open(filepath, mode='rt', encoding='utf-8') as fin:
        return json.load(fin)


def _dump_cassette(obj, filepath):
    with open(filepath, mode='wt') as fout:
        json.dump(obj, fout, indent=4)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('filepath', type=str,
                        help='File to convert from betamax to vcrpy format')
    parser.add_argument('-o', '--output', type=str,
                        help='Output filepath')
    args = parser.parse_args()

    if not os.path.isfile(args.filepath):
        LOGGER.error('File {0} does not exist'.format(args.filepath))
        sys.exit(1)

    # If not output arg given, overwrite input file
    output_filename = args.output if args.output else args.filepath

    print('[+] Handling cassette: \'{0}\''.format(args.filepath))
    cassette_content = _load_cassette(args.filepath)

    if 'recorded_with' not in cassette_content:
        LOGGER.error('Input file does not look like a betamax cassette ...')
        sys.exit(2)

    LOGGER.debug('[+] Delete recorded_with, add version')
    del cassette_content['recorded_with']
    cassette_content['version'] = 1

    LOGGER.debug('[+] Renaming http_interactions -> interactions')
    cassette_content['interactions'] = cassette_content['http_interactions'].copy()
    del cassette_content['http_interactions']

    """
    LOGGER.debug('[+] Iterating through interactions')
    for index, interaction in enumerate(cassette_content['interactions']):
        LOGGER.debug('[+] Converting interaction #{0}'.format(index))
        for http_interaction in ['request', 'response']:
            LOGGER.debug('[+] Handling HTTP {0}'.format(http_interaction))

            headers = interaction[http_interaction]['headers']
            body = interaction[http_interaction]['body']

            if 'base64_string' in body and len(body['base64_string']) > 0:
                b64_decoded = base64.b64decode(body['base64_string'])

                if 'Content-Encoding' in headers:
                    content_encoding = headers['Content-Encoding']
                    assert len(content_encoding) == 1, 'More than one content-encoding...'
                    assert 'gzip' in content_encoding, 'Unsupported encoding'
                    b64_decoded = gzip.decompress(b64_decoded)

                try:
                    body_str = b64_decoded.decode('utf-8')
                except UnicodeDecodeError:
                    LOGGER.error('[-] Failed to decode: {0}'.format(b64_decoded))
                    sys.exit(3)
            else:
                body_str = body['string']

            cassette_content['interactions'][index][http_interaction]['body'] = body_str
    """

    LOGGER.debug('[+] Writing out new cassette to {0}'.format(output_filename))
    _dump_cassette(cassette_content, output_filename)


if __name__ == '__main__':
    main()
