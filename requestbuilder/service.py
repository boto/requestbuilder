# Copyright (c) 2012, Eucalyptus Systems, Inc.
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

import boto.connection
import boto.exception
import os.path
import urlparse

class BaseService(boto.connection.AWSAuthConnection):
    Description = ''
    APIVersion = ''

    Authentication = 'sign-v2'
    Path = '/'
    Port = 443
    Provider = 'aws'
    EnvURL = 'AWS_URL'
    ResponseError = boto.exception.BotoServerError

    # Endpoint names (i.e. 'us-east-1') and their URLs
    Endpoints = {}

    def __init__(self, url=None, **kwargs):
        self._init_args = kwargs

        self.find_credentials()
        self._read_url_info(url or os.getenv(self.EnvURL))
        if self.Endpoints:
            if 'region_name' in self._init_args:
                endpoint = self.Endpoints.get(self._init_args['region_name'])
                self._read_url_info(endpoint)
            else:
                self._read_url_info(self.Endpoints.values()[0])
        self._init_args.setdefault('path',     self.Path)
        self._init_args.setdefault('port',     self.Port)
        self._init_args.setdefault('provider', self.Provider)
        if 'host' not in self._init_args:
            raise MissingCredentialsError()
        try:
            boto.connection.AWSAuthConnection.__init__(self, **self._init_args)
        except boto.exception.NoAuthHandlerFound:
            raise MissingCredentialsError()

    def find_credentials(self):
        '''
        If the 'AWS_CREDENTIAL_FILE' environment variable exists, parse that
        file for access keys and use them if keys were not already supplied to
        __init__.
        '''
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
                            self._init_args.setdefault('aws_access_key_id',
                                                       val.strip())
                        elif key.strip() == 'AWSSecretKey':
                            self._init_args.setdefault('aws_secret_access_key',
                                                       val.strip())

    def make_request(self, action, verb='GET', path='/', params=None,
                     headers=None, data='', api_version=None):
        request = self.build_base_http_request(verb, path, None, params,
                                               headers or {}, data)
        if action:
            request.params['Action'] = action
        if api_version:
            request.params['Version'] = api_version
        elif self.APIVersion:
            request.params['Version'] = self.APIVersion
        return self._mexe(request)

    def _read_url_info(self, url):
        """
        Parse a URL and use it to fill in is_secure, host, port, and path if
        any are missing.
        """
        if url:
            parse_result = urlparse.urlparse(url)
            if parse_result[0] == 'https':
                self._init_args.setdefault('is_secure', True)
            else:
                self._init_args.setdefault('is_secure', False)
            if ':' in parse_result[1]:
                (host, port) = parse_result[1].rsplit(':', 1)
                self._init_args.setdefault('host', host)
                self._init_args.setdefault('port', int(port))
            else:
                self._init_args.setdefault('host', parse_result[1])
            if parse_result[2]:
                self._init_args.setdefault('path', parse_result[2])

    def _required_auth_capability(self):
        return [self.Authentication]

class MissingCredentialsError(boto.exception.BotoClientError):
    def __init__(self):
        boto.exception.BotoClientError.__init__(self,
                                                'Failed to find credentials')
