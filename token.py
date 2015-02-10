#!/usr/bin/env python2

'''
Author: Adam Okuliar

Licence: 
'''

import hmac
import base64
import struct
import hashlib
import time
import getpass
import sys
import re
import ConfigParser
import os
import logging
from argparse import ArgumentParser
from logging import error, warning

DEFAULT_LOGGING_MODE = 'info'
XSEL_PATH = '/usr/bin/xsel'


class Token():

    def __init__(self, secret):
        self._secret = secret

    def _get_hotp_token(self, no):
        key = base64.b32decode(self._secret, True)
        msg = struct.pack(">Q", no)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        o = ord(h[19]) & 15
        h = (struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000
        token_string = '%06d' % h
        return token_string

    def get_interval_no(self):
        return int(time.time()) // 30

    def get_remaining_time(self):
        return 30 - int(time.time()) % 30

    def get_totp_token_code(self):
        return self._get_hotp_token(no=self.get_interval_no())


class Config_file():

    def __init__(self, path):
        self._path = path

    def store_token_data(self, pin, secret):
        config = ConfigParser.ConfigParser()
        config.add_section('token')
        config.set('token', 'secret', secret)
        config.set('token', 'pin', pin)
        f = open(self._path, 'w')
        config.write(f)
        f.close()

    def load_token_data(self):
        config = ConfigParser.ConfigParser()
        config.read(self._path)
        secret = config.get('token', 'secret')
        pin = config.get('token', 'pin')
        return pin, secret


class Credentials_store():

    def __init__(self):
        self._secret = None
        self._pin = None

    def make_secret(self, length=40):
        if self._secret is not None:
            raise ValueError('Secret already loaded or generated')

        import random
        key = ''
        for i in range(length):
            key += "ABCDEFGHCIJKLMNOPQRSTUVWXYZ234567"[random.randint(1, 32)]

        self._secret = key

    def read_token_pin(self):
        if self._pin is not None:
            raise ValueError('PIN already loaded or generated')

        pin = getpass.getpass('Token PIN:')
        pin2 = getpass.getpass('Verify PIN:')
        if pin != pin2:
            sys.exit('Password and verification does not match\n')

        self._pin = pin

    def pin_strength_check(self, min_length=8, groups=2):
        problems = []
        character_groups_count = 0
        character_groups_regexes = [r'[a-z]', r'[A-Z]', r'[0-9]', r'[@#$%^&+=_!^;\'\\`:"(){}\[\]\-\<\>\?\*\|,/~]']
        if len(self._pin) < min_length:
            problems.append('Password is too short, minimum length is %d\n' % (min_length))

        for character_group in character_groups_regexes:
            if re.search(character_group, self._pin) is not None:
                character_groups_count += 1

        if character_groups_count < groups:
            problems.append('Your pin contains only %d character groups. Minimum is %d groups\n' % (character_groups_count, groups))

        return problems

    def store_to_config(self, c):
        if self._secret is None:
            raise ValueError('Secret not loaded or generated, nothing to store')

        c.store_token_data(self._pin, self._secret)

    def load_from_config(self, c):
        self._pin, self._secret = c.load_token_data()

    def get_credentials(self):
        return self._pin, self._secret


def insert_token_data_to_clipboard(clip_data):
    if not os.path.isfile(XSEL_PATH):
        warning('Cannot find xsel utility')
        return

    import subprocess
    prog = '%s -bi' % XSEL_PATH
    p = subprocess.Popen(prog.split(), stdin=subprocess.PIPE)
    p.communicate(input=clip_data)


if __name__ == '__main__':
    parser = ArgumentParser(description='OTP token generator')
    parser.add_argument('-f', '--file', default='~/.token', help='token filename')
    parser.add_argument('-g', '--generate', action='store_true', help='create new token file')
    parser.add_argument('-l', '--log', choices=['DEBUG', 'ERROR', 'INFO', 'WARNING'], default=DEFAULT_LOGGING_MODE, type=str.upper, help='specify debug level [Default: %(default)s')

    args = parser.parse_args()

    logging.basicConfig(level=args.log.upper())

    conf_file_path = os.path.abspath(os.path.expanduser(args.file))

    cnf = Config_file(conf_file_path)
    cs = Credentials_store()

    if args.generate:
        cs.make_secret()
        cs.read_token_pin()
        problems = cs.pin_strength_check()
        if len(problems) > 0:
            sys.stderr.writelines(problems)
            sys.exit(1)

        cs.store_to_config(cnf)
        sys.exit(0)
    else:
        if not os.path.isfile(conf_file_path):
            error('File %s does not exists. Use -g for generate' % args.file)
            sys.exit(1)

        cnf.load_token_data()
        cs.load_from_config(cnf)
        pin, secret = cs.get_credentials()
        t = Token(secret)
        token_code = t.get_totp_token_code()

        full_token_code = '%s%s' % (pin, token_code)
        insert_token_data_to_clipboard(full_token_code)
        print 'token: %s' % token_code
