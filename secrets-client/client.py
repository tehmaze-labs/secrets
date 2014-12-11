#!/usr/bin/env python2

import binascii
import json
import os
import ssl
import sys
try:
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.poolmanager import PoolManager
    import libnacl
    from pyasn1.type import univ, namedtype, tag
    from pyasn1.codec.der import decoder as der_decoder
except ImportError:
    sys.stderr.write('Please install the missing dependancies (pip install)\n')
    raise

import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-c', '--cafile', default='../testdata/secrets.pem',
    help='CA certificates file')
parser.add_argument('-k', '--keyfile', default='testdata/client.box',
    help='box key file')
parser.add_argument('-u', '--url', default='https://localhost:6443/',
    help='server URL')
parser.add_argument('command', nargs=1)
parser.add_argument('args', nargs='*')

def usage():
    print('usage: %s [<options>] <command\n', sys.argv[0])
    print('''
commands:

    secrets-client ls [<group>]
    secrets-client cat <group> <key>
    secrets-client put <group> <key> [<file>]

options:
''')
    parser.usage()
    return 1

class SaneTLS(HTTPAdapter):
    def __init__(self, ca_certs):
        super(SaneTLS, self).__init__()

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(
                num_pools=connections,
                maxsize=maxsize,
                block=block,
                ssl_version=ssl.PROTOCOL_TLSv1,
        )


# Our sane requests handler
sane = requests.Session()


class Key(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('id', univ.ObjectIdentifier()),
        namedtype.NamedType('publicKey', univ.OctetString()),
        namedtype.OptionalNamedType('privateKey', univ.OctetString()),
    )


class Client(object):
    OIDPrivateKey = univ.ObjectIdentifier('1.3.6.1.4.1.27266.11.17.2')
    OIDPublicKey  = univ.ObjectIdentifier('1.3.6.1.4.1.27266.11.17.1')
    PEMPrivateKey = "SECRETS PRIVATE KEY"
    PEMPublicKey  = "SECRETS PUBLIC KEY"

    def __init__(self, keyfile, baseurl, verify=None):
        self.keyfile = keyfile
        self.baseurl = baseurl
        self.verify = verify
        self.key = Client.loadKeyFile(self.PEMPrivateKey, self.keyfile)

        if self.key.getComponentByName('id') != self.OIDPrivateKey:
            raise TypeError('Key file {0} does not contain a SECRETS private key'.format(keyfile))

        self.publicKey = self.key.getComponentByName('publicKey').asOctets()
        self.publicKeyBase64 = binascii.b2a_base64(self.publicKey).rstrip()
        self.privateKey = self.key.getComponentByName('privateKey').asOctets()

        if self.baseurl.endswith('/'):
            self.baseurl = self.baseurl.rstrip('/')

    @classmethod
    def loadKeyFile(cls, type, keyFile):
        with open(keyFile, "r") as fd:
            keyData = fd.read()
            derData = Client.parsePEM(type, keyData)
            return der_decoder.decode(derData, asn1Spec=Key())[0]

    @classmethod
    def parsePEM(cls, type, data):
        header = '-----BEGIN {0}-----'.format(type)
        footer = '-----END {0}-----'.format(type)
        parsed = []
        keep = False
        for line in data.splitlines():
            line = line.strip()
            if keep:
                if line == footer:
                    if not parsed:
                        raise ValueError('Could not decode {0} PEM block'.format(type))
                    return ''.join(parsed).decode('base64')
                else:
                    parsed.append(line)
            elif line == header:
                keep = True
        raise ValueError('Could not find {0} PEM block'.format(type))

    def decrypt(self, s):
        key = None
        nonce = binascii.a2b_base64(s['nonce'])
        sender = binascii.a2b_base64(s['sender'])
        secret = s['keys'].get(self.publicKeyBase64)
        if secret is None:
            print repr(self.publicKeyBase64), 'not in', s['keys'].keys()
            raise ValueError('This node is not in the list of recipients')

        box = binascii.a2b_base64(secret)
        key = libnacl.crypto_box_open(box, nonce, sender, self.privateKey)
        box = binascii.a2b_base64(s['secret'])
        return libnacl.crypto_secretbox_open(box, nonce, key)


    def _get_json(self, url):
        result = sane.get(
            ''.join([self.baseurl, url]),
            verify=self.verify,
        )
        return result.json()

    def _put_json(self, url, data):
        sane.put(
            ''.join([self.baseurl, url]),
            verify=self.verify,
            data=json.dumps(data)
        )

    def command_cat(self, group, filename):
        data = self._get_json('/group/{0}/data/{1}/'.format(group, filename))
        print self.decrypt(data)

    def command_ls(self, group=None):
        if group is None:
            for name in self._get_json('/group/'):
                print name

        else:
            for key in self._get_json('/group/{0}/data/'.format(group)).get('keys', {}):
                print key

    def command_put(self, group, name, filename=None):
        recipients = self._get_json('/group/{0}/'.format(group))

        if filename is None:
            data = os.stdin.read()
        else:
            data = open(filename, 'rb').read()

        _bytes = lambda b: binascii.b2a_base64(b).rstrip().decode('utf-8')

        nonce = os.urandom(24)
        key = os.urandom(32)
        secret = dict(
            sender=_bytes(self.publicKey),
            nonce=_bytes(nonce),
            secret=_bytes(libnacl.crypto_secretbox(data, nonce, key)),
            keys={},
        )

        for recipient in recipients.values():
            pub = binascii.a2b_base64(recipient)
            box = libnacl.crypto_box(key, nonce, pub, self.privateKey)
            secret['keys'][_bytes(pub)] = _bytes(box)

        self._put_json('/group/{0}/data/{1}/'.format(group, name), secret)


def run():
    args = parser.parse_args()

    # Set TLS options
    sane.mount('https://', SaneTLS(args.cafile))

    client = Client(args.keyfile, args.url, args.cafile)
    command = getattr(client, 'command_{0}'.format(args.command[0]))
    if command is None:
        return parser.usage()

    return command(*args.args)

if __name__ == '__main__':
    sys.exit(run())
