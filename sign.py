#!/usr/bin/env python3

import sys
import rsa
import shlex

from common import MSG_LEN

# generated with:
# pubkey, privkey = rsa.newkeys(512)
privkey = rsa.PrivateKey(10888551840171190772581446131615487397004739141476239826081159125184318457653121098130618388522625264228398784712748098397877149360163979789180129228494641, 65537, 4293316265649384939107330965516819656468856739778865577395413780824388865451557654864092552918367097296333302849745672482872733305980492523630539229122673, 7318430719845143890903985600718104830885245635407475200628395767019755941226222421, 1487826045909687825132917084942251035510427090070182223894335195724147821)

def usage():
    print("Usage: {} <index> <command string> <output file>".format(sys.argv[0]))
    exit(1)

def make_signed_message(index, message):
    if len(message) > 15:
        print('message too long! ({} > 15)'.format(len(message)))
        usage()
    if index > 255:
        print('index too high (does not fit into a byte)')
        usage()
    msg = bytes([index]) + bytes(message, 'ascii').rjust(MSG_LEN - 1, b'\0')
    signature = rsa.sign(msg, privkey, 'SHA-256')
    return msg + signature

if __name__ == '__main__':
    if len(sys.argv) < 4:
        usage()

    msg = make_signed_message(int(sys.argv[1]), sys.argv[2])
    with open(sys.argv[3], 'wb') as f:
        f.write(msg)
    print(msg)
