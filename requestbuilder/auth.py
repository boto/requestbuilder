# Copyright (c) 2012-2014, Eucalyptus Systems, Inc.
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

import base64
import calendar
import datetime
import email.utils
import hashlib
import hmac
import os
import logging
import re
import six
import time
import urllib
import urlparse

from requestbuilder import Arg
from requestbuilder.exceptions import AuthError


ISO8601 = '%Y-%m-%dT%H:%M:%SZ'


class BaseAuth(object):
    '''
    Basis for all authentication

    This class does nothing on its own.  It is up to you to implement the
    necessary functions to effect an authentication scheme.
    '''
    ARGS = []

    def __init__(self, config, loglevel=None, **kwargs):
        self.args = kwargs
        self.config = config
        self.log = logging.getLogger(self.__class__.__name__)
        if loglevel is not None:
            self.log.level = loglevel

    def configure(self):
        pass

    def apply_to_request(self, request, service):
        pass


class HmacKeyAuth(BaseAuth):
    '''
    Basis for AWS HMAC-based authentication
    '''
    ARGS = [Arg('-I', '--access-key-id', dest='key_id', metavar='KEY_ID'),
            Arg('-S', '--secret-key', dest='secret_key', metavar='KEY'),
            Arg('--security-token', dest='security_token', metavar='TOKEN')]

    @classmethod
    def from_other(cls, other, **kwargs):
        kwargs.setdefault('loglevel', other.log.level)
        kwargs.setdefault('key_id', other.args.get('key_id'))
        kwargs.setdefault('secret_key', other.args.get('secret_key'))
        kwargs.setdefault('security_token', other.args.get('security_token'))
        new = cls(other.config, **kwargs)
        new.configure()
        return new

    def configure(self):
        # If the current user/region was explicitly set (e.g. with --region),
        # use that first
        self.configure_from_configfile(only_if_explicit=True)
        # Try the environment next
        self.args['key_id'] = (self.args.get('key_id') or
                               os.getenv('AWS_ACCESS_KEY_ID') or
                               os.getenv('AWS_ACCESS_KEY'))
        self.args['secret_key'] = (self.args.get('secret_key') or
                                   os.getenv('AWS_SECRET_ACCESS_KEY') or
                                   os.getenv('AWS_SECRET_KEY'))
        self.args['security_token'] = (self.args.get('security_token') or
                                       os.getenv('AWS_SECURITY_TOKEN'))
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
                            self.args['secret_key'] = val.strip()

    def configure_from_configfile(self, only_if_explicit=False):
        if only_if_explicit and not self.args.get('region'):  # Somewhat hacky
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

    def apply_to_request(self, req, service):
        if req.headers is None:
            req.headers = {}
        req.headers['Date'] = email.utils.formatdate()
        req.headers['Host'] = urlparse.urlparse(req.url).netloc
        if self.args.get('security_token'):
            req.headers['x-amz-security-token'] = self.args['security_token']
        if 'Signature' in req.headers:
            del req.headers['Signature']
        c_headers = self.get_canonicalized_headers(req)
        self.log.debug('canonicalized headers: %s', repr(c_headers))
        c_resource = self.get_canonicalized_resource(req, service)
        self.log.debug('canonicalized resource: %s', repr(c_resource))
        to_sign = '\n'.join((req.method,
                             req.headers.get('Content-MD5', ''),
                             req.headers.get('Content-Type', ''),
                             req.headers.get('Date'),
                             c_headers + c_resource))
        self.log.debug('string to sign: %s', repr(to_sign))
        signature = self.sign_string(to_sign.encode('utf-8'))
        self.log.debug('b64-encoded signature: %s', signature)
        req.headers['Authorization'] = 'AWS {0}:{1}'.format(self.args['key_id'],
                                                            signature)

    def apply_to_request_params(self, req, service, expiration_datetime):
        # This does not implement security tokens.
        for param in ('AWSAccessKeyId', 'Expires', 'Signature'):
            req.params.pop(param, None)

        expiration = calendar.timegm(expiration_datetime.utctimetuple())
        delta_t = expiration_datetime - datetime.datetime.utcnow()
        delta_t_sec = ((delta_t.microseconds +
                        (delta_t.seconds + delta_t.days * 24 * 3600) * 10**6)
                       / 10**6)
        self.log.debug('expiration: %i (%f seconds from now)',
                       expiration, delta_t_sec)
        c_headers = self.get_canonicalized_headers(req)
        self.log.debug('canonicalized headers: %s', repr(c_headers))
        c_resource = self.get_canonicalized_resource(req, service)
        self.log.debug('canonicalized resource: %s', repr(c_resource))
        to_sign = '\n'.join((req.method,
                             req.headers.get('Content-MD5', ''),
                             req.headers.get('Content-Type', ''),
                             six.text_type(expiration),
                             c_headers + c_resource))
        self.log.debug('string to sign: %s', repr(to_sign))
        signature = self.sign_string(to_sign.encode('utf-8'))
        self.log.debug('b64-encoded signature: %s', signature)
        req.params['AWSAccessKeyId'] = self.args['key_id']
        req.params['Expires'] = six.text_type(expiration)
        req.params['Signature'] = signature
        if self.args.get('security_token'):
            # This is a guess.  I have no evidence that this actually works.
            req.params['SecurityToken'] = self.args['security_token']

    def get_canonicalized_resource(self, req, service):
        # /bucket/keyname
        parsed_req_path = urlparse.urlparse(req.url).path
        assert service.endpoint is not None
        parsed_svc_path = urlparse.urlparse(service.endpoint).path
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

    @staticmethod
    def get_canonicalized_headers(req):
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

    def apply_to_request(self, req, service):
        if req.params is None:
            req.params = {}
        req.params['AWSAccessKeyId'] = self.args['key_id']
        req.params['SignatureVersion'] = 2
        req.params['SignatureMethod'] = 'HmacSHA256'
        req.params['Timestamp'] = time.strftime(ISO8601, time.gmtime())
        if self.args.get('security_token'):
            req.params['SecurityToken'] = self.args['security_token']
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
