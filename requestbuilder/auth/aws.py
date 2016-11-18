# Copyright (c) 2012-2015, Eucalyptus Systems, Inc.
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
import re
import tempfile
import time
import warnings

import six
import six.moves.urllib_parse as urlparse

from requestbuilder import Arg
from requestbuilder.auth import BaseAuth
from requestbuilder.exceptions import AuthError


ISO8601 = '%Y-%m-%dT%H:%M:%SZ'
ISO8601_BASIC = '%Y%m%dT%H%M%SZ'


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
        kwargs.setdefault('credential_expiration',
                          other.args.get('credential_expiration'))
        new = cls(other.config, **kwargs)
        new.configure()
        return new

    def configure(self):
        self.__populate_auth_args()

        if not self.args.get('key_id'):
            raise AuthError('missing access key ID; please supply one with -I')
        if not self.args.get('secret_key'):
            raise AuthError('missing secret key; please supply one with -S')
        if self.args.get('credential_expiration'):
            expiration = None
            for fmt in ('%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%SZ'):
                try:
                    expiration = datetime.datetime.strptime(
                        self.args['credential_expiration'], fmt)
                    break
                except ValueError:
                    continue
            else:
                self.log.warn(
                    'failed to parse credential expiration time '
                    '\'{0}\'; proceeding without validation'
                    .format(self.args['credential_expiration']))
            if expiration and expiration < datetime.datetime.utcnow():
                raise AuthError('credentials have expired')

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
            return path

    def __populate_auth_args(self):
        """
        Try to get auth info from each source in turn until one provides
        both a key ID and a secret key.  After each time a source fails
        to provide enough info we wipe self.args out so we don't wind up
        mixing info from multiple sources.
        """

        # self.args gets highest precedence
        if self.args.get('key_id') and not self.args.get('secret_key'):
            # __reset_unless_ready will wipe out key_id and result in
            # the wrong error message
            raise AuthError('missing secret key; please supply one with -S')
        if self.args.get('secret_key') and not self.args.get('key_id'):
            # If only one is supplied at the command line we should
            # immediately blow up
            raise AuthError('missing access key ID; please supply one with -I')
        if self.__reset_unless_ready():
            self.log.debug('using auth info provided directly')
            return
        # Environment comes next
        self.args['key_id'] = (os.getenv('AWS_ACCESS_KEY_ID') or
                               os.getenv('AWS_ACCESS_KEY'))
        self.args['secret_key'] = (os.getenv('AWS_SECRET_ACCESS_KEY') or
                                   os.getenv('AWS_SECRET_KEY'))
        self.args['security_token'] = os.getenv('AWS_SECURITY_TOKEN')
        self.args['credential_expiration'] = \
            os.getenv('AWS_CREDENTIAL_EXPIRATION')
        if self.__reset_unless_ready():
            self.log.debug('using auth info from environment')
            return
        # See if an AWS credential file was given in the environment
        aws_credfile_path = self.configure_from_aws_credential_file()
        if aws_credfile_path and self.__reset_unless_ready():
            self.log.debug('using auth info from AWS credential file %s',
                           aws_credfile_path)
            return
        # Try the config file
        self.args['key_id'] = self.config.get_user_option('key-id')
        self.args['secret_key'] = self.config.get_user_option('secret-key',
                                                              redact=True)
        if self.__reset_unless_ready():
            self.log.debug('using auth info from configuration')
            return

    def __reset_unless_ready(self):
        """
        If both an access key ID and a secret key are set in self.args
        return True.  Otherwise, clear auth info from self.args and
        return False.
        """
        if self.args.get('key_id') and self.args.get('secret_key'):
            return True
        for arg in ('key_id', 'secret_key', 'security_token',
                    'credential_expiration'):
            self.args[arg] = None
        return False


class HmacV1Auth(HmacKeyAuth):
    '''
    S3 REST authentication
    http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
    '''

    # This list comes from the CanonicalizedResource section of the above page
    HASHED_PARAMS = set((
        'acl', 'lifecycle', 'location', 'logging', 'notification',
        'partNumber', 'policy', 'requestPayment', 'torrent', 'uploadId',
        'uploads', 'versionId', 'versioning', 'versions', 'website'))

    def apply_to_request(self, req, service):
        self._update_request_before_signing(req)
        c_headers = self.get_canonicalized_headers(req)
        c_resource = self.get_canonicalized_resource(req, service)
        to_sign = self._get_string_to_sign(req, c_headers, c_resource)
        self.log.debug('string to sign: %s', repr(to_sign))
        signature = self.sign_string(to_sign.encode('utf-8'))
        self.log.debug('b64-encoded signature: %s', signature)
        self._apply_signature(req, signature)
        return req

    def apply_to_request_params(self, req, service, expiration_datetime):
        # This does not implement security tokens.
        msg = ('S3RestAuth.apply_to_request_params is deprecated; use '
               'requestbuilder.auth.aws.QueryHmacV1Auth instead')
        self.log.warn(msg)
        warnings.warn(msg, DeprecationWarning)

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

    def _update_request_before_signing(self, req):
        if not req.headers:
            req.headers = {}
        req.headers['Date'] = email.utils.formatdate()
        req.headers['Host'] = urlparse.urlparse(req.url).netloc
        if self.args.get('security_token'):
            req.headers['x-amz-security-token'] = self.args['security_token']
        req.headers.pop('Signature', None)

    def _get_string_to_sign(self, req, c_headers, c_resource):
        return '\n'.join((req.method.upper(),
                          req.headers.get('Content-MD5', ''),
                          req.headers.get('Content-Type', ''),
                          req.headers.get('Date'),
                          c_headers + c_resource))

    def _apply_signature(self, req, signature):
        req.headers['Authorization'] = 'AWS {0}:{1}'.format(
            self.args['key_id'], signature)

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
        if not resource:
            # This resource does not address a bucket
            resource = '/'

        # Now append sub-resources, a.k.a. query string parameters
        if getattr(req, 'params', None):
            # A regular Request
            params = req.params
        else:
            # A PreparedRequest
            params = _get_params_from_url(req.url)
        if params:
            subresources = []
            for key, val in sorted(params.iteritems()):
                if key in self.HASHED_PARAMS:
                    if val is None:
                        subresources.append(key)
                    else:
                        subresources.append(key + '=' + val)
                if subresources:
                    resource += '?' + '&'.join(subresources)
        self.log.debug('canonicalized resource: %s', repr(resource))
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
            c_headers = '\n'.join(headers_strs) + '\n'
        else:
            c_headers = ''
        self.log.debug('canonicalized headers: %s', repr(c_headers))
        return c_headers

    def sign_string(self, to_sign):
        req_hmac = hmac.new(self.args['secret_key'], digestmod=hashlib.sha1)
        req_hmac.update(to_sign)
        return base64.b64encode(req_hmac.digest())


class QueryHmacV1Auth(HmacV1Auth):
    DEFAULT_TIMEOUT = 600  # 10 minutes

    def _update_request_before_signing(self, req):
        timeout = int(self.args.get('timeout')) or self.DEFAULT_TIMEOUT
        assert timeout > 0
        params = _get_params_from_url(req.url)
        params['AWSAccessKeyId'] = self.args['key_id']
        params['Expires'] = int(time.time() + timeout)
        params.pop('Signature', None)
        req.prepare_url(_remove_params_from_url(req.url), params)

    def _get_string_to_sign(self, req, c_headers, c_resource):
        params = _get_params_from_url(req.url)
        return '\n'.join((req.method.upper(),
                          req.headers.get('Content-MD5', ''),
                          req.headers.get('Content-Type', ''),
                          params['Expires'],
                          c_headers + c_resource))

    def _apply_signature(self, req, signature):
        req.prepare_url(req.url, {'Signature': signature})


class QueryHmacV2Auth(HmacKeyAuth):
    '''
    AWS signature version 2
    http://docs.aws.amazon.com/general/latest/gr/signature-version-2.html
    '''

    def apply_to_request(self, req, service):
        parsed = urlparse.urlparse(req.url)
        if req.method == 'POST':
            # This is probably going to break when given multipart data.
            params = urlparse.parse_qs(req.body or '', keep_blank_values=True)
        else:
            params = urlparse.parse_qs(parsed.query, keep_blank_values=True)
        params = dict((key, vals[0]) for key, vals in params.iteritems())
        params['AWSAccessKeyId'] = self.args['key_id']
        params['SignatureVersion'] = 2
        params['SignatureMethod'] = 'HmacSHA256'
        params['Timestamp'] = time.strftime(ISO8601, time.gmtime())
        if self.args.get('security_token'):
            params['SecurityToken'] = self.args['security_token']
        # Needed for retries so old signatures aren't included in to_sign
        params.pop('Signature', None)
        to_sign = '{method}\n{host}\n{path}\n'.format(
            method=req.method, host=parsed.netloc.lower(),
            path=(parsed.path or '/'))
        quoted_params = []
        for key in sorted(params):
            val = six.text_type(params[key])
            quoted_params.append(urlparse.quote(key, safe='') + '=' +
                                 urlparse.quote(val, safe='-_~'))
        query_string = '&'.join(quoted_params)
        to_sign += query_string
        # Redact passwords
        redacted_to_sign = re.sub('assword=[^&]*', 'assword=<redacted>',
                                  to_sign)
        self.log.debug('string to sign: %s', repr(redacted_to_sign))
        signature = self.sign_string(to_sign)
        self.log.debug('b64-encoded signature: %s', signature)
        params['Signature'] = signature
        if req.method == 'POST':
            req.prepare_body(params, {})
        else:
            req.prepare_url(_remove_params_from_url(req.url), params)

        return req

    def sign_string(self, to_sign):
        req_hmac = hmac.new(self.args['secret_key'], digestmod=hashlib.sha256)
        req_hmac.update(to_sign)
        return base64.b64encode(req_hmac.digest())


class HmacV4Auth(HmacKeyAuth):
    """
    AWS signature version 4
    http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
    """

    def apply_to_request(self, req, service):
        if not service.NAME:
            self.log.critical('service class %s must have a NAME attribute '
                              'to use sigv4', service.__class__.__name__)
            raise AuthError('BUG: service class {0} does not have a name'
                            .format(service.__class__.__name__))
        payload_hash = self._hash_payload(req)  # large files will be slow here
        now = time.time()
        date_header = time.strftime(ISO8601_BASIC, time.gmtime(now))
        scope = self._build_scope(service, now)
        credential = '/'.join((self.args['key_id'],) + scope)
        self._update_request_before_signing(req, credential, payload_hash,
                                            date_header)

        c_uri = self._get_canonical_uri(req)
        c_query = self._get_canonical_query(req)
        c_headers = self._get_canonical_headers(req)
        s_headers = self._get_signed_headers(req)
        c_request = '\n'.join((req.method.upper(), c_uri, c_query, c_headers,
                               '', s_headers, payload_hash))
        self.log.debug('canonical request: %s', repr(c_request))

        to_sign = '\n'.join(('AWS4-HMAC-SHA256', date_header, '/'.join(scope),
                             hashlib.sha256(c_request).hexdigest()))
        # Redact passwords
        redacted_to_sign = re.sub('assword=[^&]*', 'assword=<redacted>',
                                  to_sign)
        self.log.debug('string to sign: %s', repr(redacted_to_sign))

        derived_hmac = hmac.new('AWS4{0}'.format(self.args['secret_key']),
                                digestmod=hashlib.sha256)
        for chunk in scope:
            derived_hmac.update(chunk)
            derived_hmac = hmac.new(derived_hmac.digest(),
                                    digestmod=hashlib.sha256)
        derived_hmac.update(to_sign)
        signature = derived_hmac.hexdigest()
        self.log.debug('signature: %s', signature)
        self._apply_signature(req, credential, signature)
        return req

    def _update_request_before_signing(self, req, credential, payload_sha256,
                                       date_header):
        parsed = urlparse.urlparse(req.url)
        req.headers['Host'] = parsed.netloc
        req.headers.pop('Authorization', None)
        req.headers['X-Amz-Content-SHA256'] = payload_sha256
        req.headers['X-Amz-Date'] = date_header
        if self.args.get('security_token'):
            req.headers['X-Amz-Security-Token'] = self.args['security_token']

    def _apply_signature(self, req, credential, signature):
        auth_header = ', '.join((
            'AWS4-HMAC-SHA256 Credential={0}'.format(credential),
            'SignedHeaders={0}'.format(self._get_signed_headers(req)),
            'Signature={0}'.format(signature)))
        req.headers['Authorization'] = auth_header

    def _build_scope(self, service, timestamp):
        if service.region_name:
            region = service.region_name
        elif os.getenv('AWS_AUTH_REGION'):
            region = os.getenv('AWS_AUTH_REGION')
        else:
            self.log.error('a region name is required to use sigv4')
            raise AuthError(
                "region name is required; either use a config file "
                "to supply the service's URL or set AWS_AUTH_REGION "
                "in the environment")
        scope = (time.strftime('%Y%m%d', time.gmtime(timestamp)),
                 region, service.NAME, 'aws4_request')
        self.log.debug('scope: %s', '/'.join(scope))
        return scope

    def _get_canonical_uri(self, req):
        path = urlparse.urlsplit(req.url).path or '/'
        # TODO:  Normalize stuff like ".."
        c_uri = urlparse.quote(path, safe='/~')
        self.log.debug('canonical URI: %s', c_uri)
        return c_uri

    def _get_canonical_query(self, req):
        req_params = urlparse.parse_qsl(urlparse.urlparse(req.url).query,
                                        keep_blank_values=True)
        params = []
        for key, val in sorted(req_params or []):
            params.append('='.join((urlparse.quote(key, safe='~-_.'),
                                    urlparse.quote(val, safe='~-_.'))))
        c_params = '&'.join(params)
        self.log.debug('canonical query: %s', c_params)
        return c_params

    def _get_normalized_headers(self, req):
        # This doesn't currently support multi-value headers.
        headers = {}
        for key, val in req.headers.iteritems():
            if key.lower() not in ('connection', 'user-agent'):
                # Reverse proxies like to rewrite Connection headers.
                # Ignoring User-Agent lets us generate storable query URLs
                headers[key.lower().strip()] = val.strip()
        return headers

    def _get_canonical_headers(self, req):
        headers = []
        normalized_headers = self._get_normalized_headers(req)
        for key, val in sorted(normalized_headers.items()):
            headers.append(':'.join((key, val)))
        self.log.debug('canonical headers: %s', str(headers))
        return '\n'.join(headers)

    def _get_signed_headers(self, req):
        normalized_headers = self._get_normalized_headers(req)
        s_headers = ';'.join(sorted(normalized_headers))
        self.log.debug('signed headers: %s', s_headers)
        return s_headers

    def _hash_payload(self, req):
        if self.args.get('payload_hash'):
            return self.args['payload_hash']
        digest = hashlib.sha256()
        if not req.body:
            pass
        elif hasattr(req.body, 'seek'):
            body_position = req.data.tell()
            self.log.debug('payload hashing starting')
            while True:
                chunk = req.body.read(16384)
                if not chunk:
                    break
                digest.update(chunk)
            req.body.seek(body_position)
            self.log.debug('payload hashing done')
        elif hasattr(req.body, 'read'):
            self.log.debug('payload spooling/hashing starting')
            # 10M happens to be the size of a bundle part, the thing we upload
            # most frequently.
            spool = tempfile.SpooledTemporaryFile(max_size=(10 * 1024 * 1024))
            while True:
                chunk = req.body.read(16384)
                if not chunk:
                    break
                digest.update(chunk)
                spool.write(chunk)
            self.log.debug('payload spooling/hashing done')
            spool.seek(0)
            self.log.info('re-pointing request body at spooled payload')
            req.body = spool
            # Should we close the original req.body here?
        else:
            digest.update(req.body)
        self.log.debug('payload hash: %s', digest.hexdigest())
        return digest.hexdigest()


class QueryHmacV4Auth(HmacV4Auth):
    def _update_request_before_signing(self, req, credential, payload_sha256,
                                       date_header):
        # We don't do anything with payload_sha256.  Is that bad?
        if (req.method.upper() == 'POST' and
                'form-urlencoded' in req.headers.get('Content-Type', '')):
            self.log.warn('Query string authentication and POST form data '
                          'are generally mutually exclusive; GET is '
                          'recommended instead')
        parsed = urlparse.urlparse(req.url)
        req.headers['Host'] = parsed.netloc
        req.headers.pop('Authorization', None)
        params = {
            'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
            'X-Amz-Credential': credential,
            'X-Amz-Date': date_header,
            'X-Amz-SignedHeaders': self._get_signed_headers(req)}
        if self.args.get('timeout'):
            params['X-Amz-Expires'] = self.args['timeout']
        if self.args.get('security_token'):
            params['X-Amz-Security-Token'] = self.args['security_token']
        req.prepare_url(req.url, params)

    def _apply_signature(self, req, credential, signature):
        req.prepare_url(req.url, {'X-Amz-Signature': signature})


def _get_params_from_url(url):
    """
    Given a URL, return a dict of parameters and their values.  If a
    parameter appears more than once all but the first value will be lost.
    """
    parsed = urlparse.urlparse(url)
    params = urlparse.parse_qs(parsed.query, keep_blank_values=True)
    return dict((key, vals[0]) for key, vals in params.iteritems())


def _remove_params_from_url(url):
    """
    Return a copy of a URL with its parameters, fragments, and query
    string removed.
    """
    parsed = urlparse.urlparse(url)
    return urlparse.urlunparse((parsed[0], parsed[1], parsed[2], '', '', ''))
