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

from __future__ import absolute_import

import argparse
import base64
import email.utils
import hashlib
import hmac
import os
import logging
import re
from requestbuilder import Arg, AUTH
from requestbuilder.exceptions import AuthError
from requestbuilder.util import add_default_routes, aggregate_subclass_fields
import six
import time
import urllib
import urlparse

ISO8601 = '%Y-%m-%dT%H:%M:%SZ'


class BaseAuth(object):
    '''
    Basis for all authentication

    This class does nothing on its own.  It is up to you to implement the
    necessary functions to effect an authentication scheme.
    '''
    ARGS = []
    DEFAULT_ROUTES = (AUTH,)

    def __init__(self, config, loglevel=None, **kwargs):
        self.args    = kwargs
        self.config  = config
        # Auth handlers are much more tightly coupled with their associated
        # services.  Since some of them need to have access to stuff like
        # endpoint URLs and region names the service will automatically give
        # the auth handler a weak reference to itself when it creates the auth
        # handler itself or when you pass it to the service's __init__ method.
        # Be aware of this when you set the service's auth attribute by hand --
        # you may need to point it at the service for it to function properly.
        self.service = None

        self.log = logging.getLogger(self.__class__.__name__)
        if loglevel is not None:
            self.log.level = loglevel

    def collect_arg_objs(self):
        arg_objs = aggregate_subclass_fields(self.__class__, 'ARGS')
        add_default_routes(arg_objs, self.DEFAULT_ROUTES)
        return arg_objs

    def preprocess_arg_objs(self, arg_objs):
        pass

    def configure(self):
        pass

    def __call__(self, req):
        pass


class HmacKeyAuth(BaseAuth):
    '''
    Basis for AWS HMAC-based authentication
    '''
    ARGS = [Arg('-I', '--access-key-id', dest='key_id', metavar='KEY_ID'),
            Arg('-S', '--secret-key', dest='secret_key', metavar='KEY')]

    def configure(self):
        # If the current user/region was explicitly set (e.g. with --region),
        # use that first
        self.configure_from_configfile(only_if_explicit=True)
        # Try the environment next
        if 'AWS_ACCESS_KEY' in os.environ and not self.args.get('key_id'):
            self.args['key_id'] = os.getenv('AWS_ACCESS_KEY')
        if 'AWS_SECRET_KEY' in os.environ and not self.args.get('secret_key'):
            self.args['secret_key'] = os.getenv('AWS_SECRET_KEY')
        # See if an AWS credential file was given in the environment
        self.configure_from_aws_credential_file()
        # Try the requestbuilder config file next
        self.configure_from_configfile()

        if not self.args.get('key_id'):
            raise AuthError('missing access key ID; please supply one with -I')
        if not self.args.get('secret_key'):
            raise AuthError('missing secret key; please supply one with -S')

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
                        if (key.strip() == 'AWSAccessKeyId' and
                            not self.args.get('key_id')):
                            # There's probably a better way to do this, but it
                            # seems to work for me.  Patches are welcome.  :)
                            self.args['key_id'] = val.strip()
                        elif (key.strip() == 'AWSSecretKey' and
                            not self.args.get('secret_key')):
                            # This space for rent
                            self.args['secret_key'] = val.strip()

    def configure_from_configfile(self, only_if_explicit=False):
        if (only_if_explicit and self.config.current_user is None and
            self.config.current_region is None):
            # The current user/region were not explicitly set, so do nothing.
            return
        if not self.args.get('key_id'):
            config_key_id = self.config.get_user_option('key-id')
            if config_key_id:
                self.args['key_id'] = config_key_id
        if not self.args.get('secret_key'):
            config_secret_key = self.config.get_user_option('secret-key',
                                                            redact=True)
            if config_secret_key:
                self.args['secret_key'] = config_secret_key


class S3RestAuth(HmacKeyAuth):
    '''
    S3 REST authentication
    http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
    '''

    # This list comes from the CanonicalizedResource section of the above page
    HASHED_PARAMS = set(('acl', 'lifecycle', 'location', 'logging',
            'notification', 'partNumber', 'policy', 'requestPayment',
            'torrent', 'uploadId', 'uploads', 'versionId', 'versioning',
            'versions', 'website'))

    def __call__(self, req):
        if req.headers is None:
            req.headers = {}
        req.headers['Date'] = email.utils.formatdate()
        req.headers['Host'] = urlparse.urlparse(req.url).netloc
        if 'Signature' in req.headers:
            del req.headers['Signature']
        c_headers = self.get_canonicalized_headers(req)
        self.log.debug('canonicalized_headers: %s', repr(c_headers))
        c_resource = self.get_canonicalized_resource(req)
        self.log.debug('canonicalized resource: %s', repr(c_resource))
        to_sign = '\n'.join((req.method.upper(),
                             req.headers.get('Content-MD5', ''),
                             req.headers.get('Content-Type', ''),
                             req.headers.get('Date'),
                             c_headers + c_resource))
        self.log.debug('string to sign: %s', repr(to_sign))
        signature = self.sign_string(to_sign.encode('utf-8'))
        self.log.debug('b64-encoded signature: %s', signature)
        req.headers['Authorization'] = 'AWS {0}:{1}'.format(self.args['key_id'],
                                                            signature)

    def get_canonicalized_resource(self, req):
        # /bucket/keyname
        parsed_req_path = urlparse.urlparse(req.url).path
        assert self.service.endpoint is not None
        parsed_svc_path = urlparse.urlparse(self.service.endpoint).path
        # IMPORTANT:  this only supports path-style requests
        assert parsed_req_path.startswith(parsed_svc_path)
        resource = parsed_req_path[len(parsed_svc_path):]
        if parsed_svc_path.endswith('/'):
            # The leading / got stripped off
            resource = '/' + resource

        # Now append sub-resources, a.k.a. query string parameters
        if req.params:
            subresources = []
            for key, val in sorted(req.params.iteritems()):
                if key in self.HASHED_PARAMS:
                    if val is None:
                        subresources.append(key)
                    else:
                        print '{0}={1}'.format(key, val), key + '=' + val
                        #subresources.append('{0}={1}'.format(key, val))
                        subresources.append(key + '=' + val)
                if subresources:
                    resource += '?' + '&'.join(subresources)
        return resource

    def get_canonicalized_headers(self, req):
        headers_dict = {}
        for key, val in req.headers.iteritems():
            if key.lower().startswith('x-amz-'):
                headers_dict.setdefault(key.lower(), [])
                headers_dict[key.lower()].append(' '.join(val.split()))
        headers_strs = []
        for key, vals in sorted(headers_dict.iteritems()):
            headers_strs.append('{0}:{1}'.format(key, ','.join(vals)))
        if headers_strs:
            return '\n'.join(headers_strs) + '\n'
        else:
            return ''

    def sign_string(self, to_sign):
        req_hmac = hmac.new(self.args['secret_key'], digestmod=hashlib.sha1)
        req_hmac.update(to_sign)
        return base64.b64encode(req_hmac.digest())


class QuerySigV2Auth(HmacKeyAuth):
    '''
    AWS signature version 2
    http://docs.amazonwebservices.com/general/latest/gr/signature-version-2.html
    '''

    def __call__(self, req):
        if req.params is None:
            req.params = {}
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
        # Redact passwords
        redacted_to_sign = re.sub('assword=[^&]*', 'assword=<redacted>',
                                  to_sign)
        self.log.debug('string to sign: %s', repr(redacted_to_sign))
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
