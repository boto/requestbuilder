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
    Name        = 'base'
    Description = ''
    APIVersion  = ''
    MaxRetries  = 4

    AuthClass = QuerySignatureV2Auth
    EnvURL    = 'AWS_URL'  # endpoint URL

    # Region names (i.e. 'us-east-1') and their endpoints for this service
    ## TODO:  replace this with a config-based system
    Regions = {}

    def __init__(self, log, endpoint=None, region_name=None, auth_args=None,
                 session_args=None):
        self.log = log
        # The region name currently only matters for sigv4.
        ## FIXME:  It also won't work with every config source yet.
        self.endpoint      = endpoint
        self.region_name   = region_name
        self._auth_args    = auth_args    or {}
        self._session_args = session_args or {}

        # SSL verification is opt-in
        self._session_args.setdefault('verify', False)

        # Grab info from the command line or service-specific config
        self.find_credentials()

        # Try the environment next
        if self.EnvURL in os.environ:
            self.__set_missing(os.getenv(self.EnvURL, '__env__'))

        ## TODO:  switch to a config-based system for obtaining region info
        if region_name:
            if region_name in self.Regions:
                self.__set_missing(self.Regions[region_name], region_name)
            else:
                raise ServiceInitError('no such region: ' + region_name)
        elif self.Regions:
            ## TODO:  have a way of choosing a default region
            self.__set_missing(self.Regions[self.region],
                               self.Regions.keys()[0])
        if not self.endpoint:
            raise ServiceInitError('no endpoint to connect to was given')

        auth = self.AuthClass(self, **self._auth_args)
        self.session = requests.session(auth=auth, **self._session_args)

    ## TODO:  rename this function
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
                        if (key.strip() == 'AWSAccessKeyId' and
                            not self._auth_args.get('key_id')):
                            self._auth_args['key_id'] = val.strip()
                        elif (key.strip() == 'AWSSecretKey' and
                              not self._auth_args.get('key')):
                            self._auth_args['key'] = val.strip()

    def make_request(self, action, method='GET', path=None, params=None,
                     headers=None, data=None, api_version=None):
        params = params or {}
        if action:
            params['Action'] = action
        if api_version:
            params['Version'] = api_version
        elif self.APIVersion:
            params['Version'] = self.APIVersion

        ## TODO:  test url-encoding
        if path:
            # We can't simply use urljoin because a path might start with '/'
            # like it could for S3 keys that start with that character.
            if self.endpoint.endswith('/'):
                url = self.endpoint + path
            else:
                url = self.endpoint + '/' + path
        else:
            url = self.endpoint

        hooks = {'pre_send':     _log_request_data(self.log),
                 'response':     _log_response_data(self.log),
                 'post_request': RetryOnStatuses((500, 503), self.MaxRetries,
                                                  logger=self.log)}

        try:
            return self.session.request(method=method, url=url, params=params,
                                        data=data, headers=headers, hooks=hooks)
        except requests.exceptions.RequestException as exc:
            raise ClientError(exc.message, exc)

    def __set_missing(self, endpoint=None, region_name=None):
        self.endpoint    = self.endpoint    or endpoint
        self.region_name = self.region_name or region_name

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
        logger.debug('response status: %i', response.status_code)
        if isinstance(response.headers, dict):
            for key, val in sorted(response.headers.items()):
                logger.debug('response header: %s: %s', key, val)
    return __log_response_data
