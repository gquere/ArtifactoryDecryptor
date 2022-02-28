#!/usr/bin/env python3
# Artifactory encrypts secrets using AES/CBC/PKCS5Padding and stores them in base58 encoding
# https://jfrog.com/knowledge-base/what-are-the-artifactory-key-master-key-and-what-are-they-used-for/
import re
import base58
import argparse
from Cryptodome.Cipher import AES


# OUTPUT #######################################################################
def output(data):
    if args.output_file:
        with open(args.output_file, 'a+') as f:
            f.write(str(data))
    else:
        print(data)


# DECRYPT artifactory.key ######################################################
def decrypt_artifactory_key_secret(secret):
    (pwd_type, pwd_id, algo, aes_blob_base58) = secret.split('.')
    (key_type, key_id, algo, artifactory_key_base58) = artifactory_key_file_contents.split('.')

    # sanity checks
    if pwd_type != 'AM':
        print('{} is not an artifactory.key secret, it has to start with AM'.format(secret))
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


# DECRYPT master.key ###########################################################
def decrypt_master_key_secret(secret):

    # sanity check
    secret_type = secret[0:2]
    if secret_type != 'JE':
        print('{} is not a master.key secret, it has to start with JE'.format(secret))

    # base58 decode, then assume IV length is always 16, rest is actual encrypted secret
    aes_blob = base58.b58decode(secret[2:])
    assert aes_blob[0] == 16,'IV is not length 16?!'
    iv = aes_blob[1:17] # drop first byte, size of IV
    encrypted_secret = aes_blob[17:-2] # drop last 2 bytes of CRC

    master_key = bytearray.fromhex(master_key_file_contents)
    cipher = AES.new(master_key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(encrypted_secret)

    # remove PKCS5 padding
    plaintext = padded_plaintext[:-ord(padded_plaintext[len(padded_plaintext)-1:])]

    return plaintext


# SECRET TYPE IDENTIFICATION ###################################################
# There are two types of secrets in artifactory depending on the key used to
# encrypt them, either artifactory.key or master.key
def decrypt_secret(secret):
    if secret[0:2] == 'JE':
        return decrypt_master_key_secret(secret)
    elif secret[0:2] == 'AM':
        return decrypt_artifactory_key_secret(secret)


def do_decrypt(line):
    encrypted_secret = re.findall('(AM\..*\.AES128\.[a-zA-Z1-9]+)', line)
    if not encrypted_secret:
        encrypted_secret = re.findall('JE[1-9A-HJ-NP-Za-km-z]+', line)

    if encrypted_secret:
        print('found {}', encrypted_secret)
        try:
            plaintext = decrypt_secret(encrypted_secret[0])
            output(line.replace(encrypted_secret[0], plaintext.decode('utf-8')))
        except:
            output(line)
    else:
        output(line)


# MAIN #########################################################################
parser = argparse.ArgumentParser()
parser.add_argument('artifactory_config_file', nargs='?')
parser.add_argument('-k', '--artifactory-key-file', type=str)
parser.add_argument('-m', '--master-key-file', type=str)
parser.add_argument('-o', '--output-file', type=str)

args = parser.parse_args()

if args.artifactory_key_file:
    with open(args.artifactory_key_file, 'r') as f:
        artifactory_key_file_contents = f.read()
elif args.master_key_file:
    with open(args.master_key_file, 'r') as f:
        master_key_file_contents = f.read()
else:
    print('Error, need a keyfile to decrypt, supply either artifactory.key (AM secrets) or master.key (JE secrets) or both')
    exit(1)

if args.artifactory_config_file:
    with open(args.artifactory_config_file, 'r') as f:
        xml_contents = f.readlines()
    for line in xml_contents:
        do_decrypt(line)
else:
    while True:
        print('Secret to decrypt: ', end='')
        print(decrypt_secret(input()))
