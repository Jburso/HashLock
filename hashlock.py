#!/usr/bin/env python3

# HashLock v2.0

import sys
import argparse
import getpass
from string import ascii_lowercase, ascii_uppercase, digits
from hashlib import pbkdf2_hmac

class HashLockError(Exception):
    pass

def __inputcheck(masterpass, service, length, chars, counter):
    # Check masterpass
    if masterpass == "":
        raise HashLockError("Master Password cannot be empty")

    # Check service
    if service =="":
        raise HashLockError("Service cannot be empty")

    # Encode
    try:
        masterpass_bytes = masterpass.encode("utf-8")
        service_bytes = service.encode("utf-8")
    except UnicodeEncodeError:
        raise HashLockError('Master password and Service must be UTF-8 encoded.')

    # Check length
    if length < 8:
        raise HashLockError("Length must be 8 or more")

    # Check counter
    if counter not in range(0, 256):
        raise HashLockError('Count must be between 0 and 255 inclusive.')

    return masterpass_bytes, service_bytes

def __get_character_set(char_set):
    # initialize character sets
    character_subset = {
    "l": ascii_lowercase,
    "u": ascii_uppercase,
    "d": digits,
    "s": "`~!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?"
    }

    count = 0
    character_set = ""
    for para in 'luds':
        if char_set.find(para) != -1:
            count += 1
            character_set += character_subset[para]

    if count < len(char_set):
        raise HashLockError('Character set must only contain l, u, d, and/or s')

    return character_set

def __hash(key, length):
    # initialize salt
    salt = bytes.fromhex("c3eb7751a4a23058ccbf785e10b40ee5")
    # derive
    return pbkdf2_hmac("sha256", key, salt, 100000, length)

def __renderpassword(entropy, character_set):
    password = ""
    for char in entropy:
        password += character_set[int(char)%(len(character_set))]
    return password

def hashlock(masterpass, service, length=20, chars='luds', counter=0):
    '''
    Return a password generated from a master password and a service. User can specify length of output password, character set to use, and password update counter.
    
    Character sets:
        l: abcdefghijklmnopqrstuvwxyz
        u: ABCDEFGHIJKLMNOPQRSTUVWXYZ
        d: 0123456789
        s: `~!@#$%^&*()-_=+[{]}\|;:'",<.>/?
    '''
    masterpass_bytes, service_bytes = __inputcheck(masterpass, service, length, chars, counter)

    counter_bytes=bytes([counter])

    character_set = __get_character_set(chars)

    # calculate entropy of password wth hash
    entropy = __hash(service_bytes + counter_bytes + masterpass_bytes, length)

    # render password with character set
    return __renderpassword(entropy, character_set)

def main():
    parser = argparse.ArgumentParser(description='HashLock: A deterministic password manager/generator')
    # Required arguments
    parser.add_argument('service', metavar='SERVICE', help='service to generate password for.')
    # Optional arguments
    parser.add_argument('-l', '--length', type=int, default=20, help='length of output password. Must be 8 or more. [Default: 20]')
    parser.add_argument('-s', '--set', metavar='CHARACTER SET', type=str, default='luds', help="character set of output password. [Default: luds]")
    parser.add_argument('-c', '--counter', type=int, default=0, help='count for updated output password. [Default: 0]')
    parser.add_argument('-v', '--version', action='version', version="HashLock v2.0")

    args = parser.parse_args()

    masterpass = getpass.getpass("Master Password: ")

    try:
        password = hashlock(masterpass, args.service, args.length, args.set, args.counter)
    except HashLockError as e:
        print(e)
        sys.exit()

    print(password)

    masterpass = ""
    password = ""
    args.service = ""

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('')