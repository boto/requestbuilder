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

import copy
import os.path
import random
import requests.exceptions
import time
import urlparse

from .auth import QuerySignatureV2Auth
from .exceptions import ClientError, ServiceInitError

class BaseService(object):
    Name        = ''
    DESCRIPTION = ''
    API_VERSION = ''
    MaxRetries  = 4

    AuthClass = QuerySignatureV2Auth
    EnvURL    = 'AWS_URL'  # endpoint URL

    def __init__(self, config, log, url=None, regionspec=None, auth_args=None,
                 session_args=None):
        self.log = log
        # The region name currently only matters for sigv4.
        ## FIXME:  It also won't work with every config source yet.
        ## TODO:  DOCUMENT:  if url contains :: it will be split into
        ##                   regionspec::endpoint
        ## FIXME:  Is the above info true any more?
        self.config        = config
        self.endpoint_url  = None
        self.regionspec    = regionspec  ## TODO:  rename this
        self._auth_args    = auth_args    or {}
        self._session_args = session_args or {}

        # SSL verification is opt-in
        self._session_args.setdefault('verify', False)

        # Set self.endpoint_url and self.regionspec from __init__ args
        self._set_url_vars(url)

        # Grab info from the command line or service-specific config
        self.read_config()

        if not self.endpoint_url:
            regions = ', '.join(sorted(self.config.regions.keys()))
            errmsg = 'no endpoint to connect to was given'
            if regions:
                errmsg += '.  Known regions are '
                errmsg += ', '.join(sorted(self.config.regions.keys()))
            raise ServiceInitError(errmsg)

        auth = self.AuthClass(self, **self._auth_args)
        self.session = requests.session(auth=auth, **self._session_args)

    def read_config(self):
        '''
        Read configuration from the environment, files, and so on and use them
        to populate self.endpoint_url, self.regionspec, and self._auth_args.

        This method's configuration sources are, in order:
          - An environment variable with the same name as self.EnvURL
          - An AWS credential file, from the path given in the
            AWS_CREDENTIAL_FILE environment variable
          - Requestbuilder configuration files, from paths given in
            self.CONFIG_FILES

        Of these, earlier sources take precedence over later sources.

        Subclasses may override this method to add or rearrange configuration
        sources.
        '''
        # Try the environment first
        if self.EnvURL in os.environ:
            self._set_url_vars(os.getenv(self.EnvURL, None))
        # Read config files from their default locations
        self.read_aws_credential_file()
        self.read_requestbuilder_config()

    def read_requestbuilder_config(self):
        self._set_url_vars(self.config.get_region_option(self.regionspec,
                                                         self.Name + '-url'))
        secret_key = self.config.get_user_option(self.regionspec, 'secret-key')
        if secret_key and not self._auth_args.get('secret_key'):
            self._auth_args['secret_key'] = secret_key
        key_id = self.config.get_user_option(self.regionspec, 'key-id')
        if key_id and not self._auth_args.get('key_id'):
            self._auth_args['key_id'] = key_id

        if self.config.get_region_option_bool(self.regionspec, 'verify-ssl'):
            self._session_args['verify'] = True

    def read_aws_credential_file(self):
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
                        if (key.strip() == 'AWSAccessKeyId' and
                            not self._auth_args.get('key_id')):
                            self._auth_args['key_id'] = val.strip()
                        elif (key.strip() == 'AWSSecretKey' and
                              not self._auth_args.get('secret_key')):
                            self._auth_args['secret_key'] = val.strip()

    def make_request(self, action, method='GET', path=None, params=None,
                     headers=None, data=None, api_version=None):
        params = params or {}
        if action:
            params['Action'] = action
        if api_version:
            params['Version'] = api_version
        elif self.API_VERSION:
            params['Version'] = self.API_VERSION

        ## TODO:  test url-encoding
        if path:
            # We can't simply use urljoin because a path might start with '/'
            # like it could for S3 keys that start with that character.
            if self.endpoint_url.endswith('/'):
                url = self.endpoint_url + path
            else:
                url = self.endpoint_url + '/' + path
        else:
            url = self.endpoint_url

        hooks = {'pre_send':     _log_request_data(self.log),
                 'response':     _log_response_data(self.log),
                 'post_request': RetryOnStatuses((500, 503), self.MaxRetries,
                                                  logger=self.log)}

        try:
            return self.session.request(method=method, url=url, params=params,
                                        data=data, headers=headers,
                                        hooks=hooks)
        except requests.exceptions.ConnectionError as exc:
            raise ClientError('connection error')
        except requests.exceptions.RequestException as exc:
            raise ClientError(exc)

    def _set_url_vars(self, url):
        if url:
            if '::' in url:
                regionspec, endpoint_url = url.split('::', 1)
            else:
                regionspec   = None
                endpoint_url = url
            self.regionspec   = regionspec   or self.regionspec
            self.endpoint_url = endpoint_url or self.endpoint_url

class RetryOnStatuses(object):
    def __init__(self, statuses, max_retries, logger=None):
        self.statuses    = statuses
        self.max_retries = max_retries
        self.current_try = 0
        self.logger      = logger

    def __call__(self, request):
        if (request.response.status_code in self.statuses and
            self.current_try < self.max_retries):
            # Exponential backoff
            self.current_try += 1
            delay = (1 + random.random()) ** self.current_try
            if self.logger:
                self.logger.info('Retrying after %.3f seconds', delay)
            time.sleep((1 + random.random()) ** self.current_try)
            orig_response = request.response
            request.send(anyway=True)
            request.response.history = (orig_response.history +
                    [orig_response] + request.response.history)

def _log_request_data(logger):
    def __log_request_data(request):
        logger.debug('request method: %s', request.method)
        logger.debug('request url:    %s', request.url)
        if isinstance(request.headers, dict):
            for key, val in sorted(request.headers.iteritems()):
                logger.debug('request header: %s: %s', key, val)
        if isinstance(request.params, dict):
            for key, val in sorted(request.params.iteritems()):
                logger.debug('request param:  %s: %s', key, val)
        if isinstance(request.data, dict):
            for key, val in sorted(request.data.iteritems()):
                logger.debug('request data:   %s: %s', key, val)
    return __log_request_data

def _log_response_data(logger):
    def __log_response_data(response):
        if response.status_code >= 400:
            logger.error('response status: %i', response.status_code)
        elif response.status_code >= 300:
            logger.info('response status: %i', response.status_code)
        else:
            logger.debug('response status: %i', response.status_code)
        if isinstance(response.headers, dict):
            for key, val in sorted(response.headers.items()):
                logger.debug('response header: %s: %s', key, val)
    return __log_response_data
