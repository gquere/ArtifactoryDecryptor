#!/usr/bin/env python3
# Artifactory encrypts secrets using AES/CBC/PKCS5Padding and stores them in base58 encoding
# https://jfrog.com/knowledge-base/what-are-the-artifactory-key-master-key-and-what-are-they-used-for/
import re
import base58
import argparse
from Crypto.Cipher import AES


# OUTPUT #######################################################################
def output(data):
    if args.output_file:
        with open(args.output_file, 'a+') as f:
            f.write(str(data))
    else:
        print(data)


# DECRYPT ######################################################################
def artifactory_decrypt(artifactory_key_file_contents, secret_contents):
    (pwd_type, pwd_id, algo, aes_blob_base58) = secret_contents.split('.')
    (key_type, key_id, algo, artifactory_key_base58) = artifactory_key_file_contents.split('.')

    # sanity checks
    if pwd_type != 'AM':
        print('{} is not a decryptable secret'.format(secret_contents))
        return None
    assert key_type == 'JS','{} is not a key'.format(artifactory_key_file_contents)
    assert pwd_id == key_id,'Password and key IDs don\'t match'

    # base58 decode and drop last 2 CRC bytes
    artifactory_key = base58.b58decode(artifactory_key_base58)[:-2]

    # base58 decode, then assume IV length is always 16, rest is actual encrypted secret
    aes_blob = base58.b58decode(aes_blob_base58)
    iv = aes_blob[1:17] # drop first byte, size of IV
    encrypted_secret = aes_blob[17:-2] # drop last 2 bytes of CRC

    cipher = AES.new(artifactory_key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(encrypted_secret)

    # remove PKCS5 padding
    plaintext = padded_plaintext[:-ord(padded_plaintext[len(padded_plaintext)-1:])]

    return plaintext


def do_decrypt(line):
    encrypted_secret = re.findall('(AM\..*\.AES128\.[a-zA-Z1-9]+)', line)
    if encrypted_secret:
        secret = artifactory_decrypt(artifactory_key_file_contents, encrypted_secret[0])

        if args.output_file:
            output(line.replace(encrypted_secret[0], secret.decode("utf-8")))
        else:
            output(secret.decode("utf-8"))
    else:
        if args.output_file:
            output(line)


# MAIN #########################################################################
parser = argparse.ArgumentParser()
parser.add_argument('artifactory_config_file', nargs='?')
parser.add_argument('-k', '--artifactory-key-file', type=str, required=True)
parser.add_argument('-o', '--output-file', type=str)

args = parser.parse_args()

with open(args.artifactory_key_file, 'r') as f:
    artifactory_key_file_contents = f.read()

if args.artifactory_config_file:
    with open(args.artifactory_config_file, 'r') as f:
        xml_contents = f.readlines()
    for line in xml_contents:
        do_decrypt(line)
else:
    while True:
        print('Secret to decrypt: ', end='')
        do_decrypt(input())
