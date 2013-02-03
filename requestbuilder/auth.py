# Copyright (c) 2012-2013, Eucalyptus Systems, Inc.
#
# Permission to use, copy, modify, and/or distribute this software for
# any purpose with or without fee is hereby granted, provided that the
# above copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import argparse
import base64
import hashlib
import hmac
import os
import requests.auth
import six
import time
import urllib
import urlparse
from . import Arg, AUTH
from .exceptions import AuthError
from .util import aggregate_subclass_fields

ISO8601 = '%Y-%m-%dT%H:%M:%SZ'


class BaseAuth(requests.auth.AuthBase):
    ARGS = []

    def __init__(self, service, **kwargs):
        self.args    = kwargs
        self.config  = service.config
        self.log     = service.log.getChild(self.__class__.__name__)
        self.service = service

    def collect_arg_objs(self):
        return aggregate_subclass_fields(self.__class__, 'ARGS')

    def preprocess_arg_objs(self, arg_objs):
        pass

    def configure(self):
        pass

    def __call__(self, req):
        pass


class HmacKeyAuth(BaseAuth):
    ARGS = [Arg('-I', '--access-key-id', dest='key_id', metavar='KEY_ID',
                default=argparse.SUPPRESS, route_to=AUTH),
            Arg('-S', '--secret-key', dest='secret_key', metavar='KEY',
                default=argparse.SUPPRESS, route_to=AUTH)]

    def configure(self):
        # See if an AWS credential file was given in the environment
        self.configure_from_aws_credential_file()
        # Try the requestbuilder config file next
        self.configure_from_configfile()

        if not self.args.get('key_id'):
            raise AuthError('missing access key ID')
        if not self.args.get('secret_key'):
            raise AuthError('missing secret key')

    def configure_from_aws_credential_file(self):
        if 'AWS_CREDENTIAL_FILE' in os.environ:
            path = os.getenv('AWS_CREDENTIAL_FILE')
            path = os.path.expandvars(path)
            path = os.path.expanduser(path)
            with open(path) as credfile:
                for line in credfile:
                    line = line.split('#', 1)[0]
                    if '=' in line:
                        (key, val) = line.split('=', 1)
                        if key.strip() == 'AWSAccessKeyId':
                            self.args.setdefault('key_id', val.strip())
                        elif key.strip() == 'AWSSecretKey':
                            self.args.setdefault('secret_key', val.strip())

    def configure_from_configfile(self):
        config_key_id = self.config.get_user_option('key-id')
        if config_key_id:
            self.args.setdefault('key_id', config_key_id)
        config_secret_key = self.config.get_user_option('secret-key',
                                                        redact=True)
        if config_secret_key:
            self.args.setdefault('secret_key', config_secret_key)


class QuerySigV2Auth(HmacKeyAuth):
    '''
    AWS signature version 2
    http://docs.amazonwebservices.com/general/latest/gr/signature-version-2.html
    '''

    def __call__(self, req):
        # We assume that req.params is a dict
        req.params['AWSAccessKeyId']   = self.args['key_id']
        req.params['SignatureVersion'] = 2
        req.params['SignatureMethod']  = 'HmacSHA256'
        req.params['Timestamp']        = time.strftime(ISO8601, time.gmtime())
        if 'Signature' in req.params:
            # Needed for retries so old signatures aren't included in to_sign
            del req.params['Signature']
        parsed = urlparse.urlparse(req.url)
        to_sign = '{method}\n{host}\n{path}\n'.format(method=req.method,
                host=parsed.netloc.lower(), path=(parsed.path or '/'))
        quoted_params = []
        for key in sorted(req.params):
            val = six.text_type(req.params[key])
            quoted_params.append(urllib.quote(key, safe='') + '=' +
                                 urllib.quote(val, safe='-_~'))
        query_string = '&'.join(quoted_params)
        to_sign += query_string
        self.log.debug('string to sign: %s', repr(to_sign))
        signature = self.sign_string(to_sign)
        self.log.debug('b64-encoded signature: %s', signature)
        req.params['Signature'] = signature

        self.convert_params_to_data(req)

        return req

    def convert_params_to_data(self, req):
        if req.method.upper() == 'POST' and isinstance(req.params, dict):
            # POST with params -> use params as form data instead
            self.log.debug('converting params to POST data')
            req.data   = req.params
            req.params = None

    def sign_string(self, to_sign):
        req_hmac = hmac.new(self.args['secret_key'], digestmod=hashlib.sha256)
        req_hmac.update(to_sign)
        return base64.b64encode(req_hmac.digest())
