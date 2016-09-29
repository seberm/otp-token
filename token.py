#!/usr/bin/env python
import hmac
import base64
import struct
import hashlib
import time
import getpass
import sys
import ConfigParser
import os
import re
import random
from optparse import OptionParser
import subprocess
import qrcode


parser = OptionParser()
parser.add_option("-f", "--file", dest="file", default='~/.token', help="Token filename", metavar="FILE")
parser.add_option("-g", "--generate", action="store_true", dest="generate", default=False, help="Create new token file")
parser.add_option("-s", "--show", action="store_true", dest="show", default=False, help="Show all secrets in configuration file")

# dependecies for project are xsel python-qrcode


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

    def __str__(self):
        out = ''
        out += 'TOTP one time password token secret\n'
        out += 'Secret (Base32)\t: %s\n' % self._secret
        out += 'Secret (hex)\t: %s\n' % self.b32tob16(self._secret)
        return out

    def make_secret(self, length=32):

        base32_charset = "ABCDEFGHCIJKLMNOPQRSTUVWXYZ234567"
        max_index = len(base32_charset) - 1

        if self._secret is not None:
            raise ValueError('Secret already loaded or generated')
        key = ""
        for _ in range(length):
            key += base32_charset[random.randint(1, max_index)]
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
            problems.append('Your pin contains only %d character groups. Minimum is %d groups\n'
                            % (character_groups_count, groups))

        return problems

    def save_to_config(self, c):
        if self._secret is None:
            raise ValueError('Secret not loaded or generated, nothing to store')
        c.store_token_data(self._pin, self._secret)

    def load_from_config(self, c):
        self._pin, self._secret = c.load_token_data()

    def get_credentials(self):
        return self._pin, self._secret

    def b32tob16(self, b32string):
        if b32string is None:
            return None
        ascii_str = base64.b32decode(b32string, True)
        hex_str = base64.b16encode(ascii_str)
        return hex_str

    def print_qr(self):
        qr_url = 'otpauth://totp/token?secret=%s' % self._secret
        qr = qrcode.QRCode()
        qr.add_data(qr_url)
        qr.print_tty()
        print ''


def insert_token_data_to_clipboard(clip_data):
    p = subprocess.Popen('xsel -bi'.split(), stdin=subprocess.PIPE)
    p.communicate(input=clip_data)


if __name__ == '__main__':

    (options, args) = parser.parse_args()
    conf_file_path = os.path.abspath(os.path.expanduser(options.file))

    cnf = Config_file(conf_file_path)
    cs = Credentials_store()

    if options.generate:
        cs.make_secret()
        cs.read_token_pin()
        problems = cs.pin_strength_check()
        if len(problems) > 0:
            sys.stderr.writelines(problems)
            sys.exit(1)

        cs.save_to_config(cnf)
        print cs
        cs.print_qr()

    elif options.show:

        cnf.load_token_data()
        cs.load_from_config(cnf)
        print cs
        cs.print_qr()

    else:
        if not os.path.isfile(conf_file_path):
            print 'File %s does not exists. Use -g for generate' % options.file
            sys.exit(1)

        cnf.load_token_data()
        cs.load_from_config(cnf)

        pin, secret = cs.get_credentials()
        t = Token(secret)
        token_code = t.get_totp_token_code()

        full_token_code = '%s%s' % (pin, token_code)
        insert_token_data_to_clipboard(full_token_code)
        print 'token %s' % token_code
