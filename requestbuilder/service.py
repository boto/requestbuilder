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

import copy
import os.path
import random
import requests.exceptions
import time
import urlparse

from .auth import QuerySigV2Auth
from .exceptions import ClientError, ServiceInitError
from .util import aggregate_subclass_fields

class BaseService(object):
    NAME        = ''
    DESCRIPTION = ''
    API_VERSION = ''
    MAX_RETRIES = 4  ## TODO:  check the config file

    AUTH_CLASS = None
    ENV_URL    = None

    ARGS = []

    def __init__(self, config, log, **kwargs):
        self.args     = kwargs
        self.config   = config
        self.endpoint = None
        self.log      = log
        self.session_args = {'verify': False}  # SSL verification is opt-in
        self._session = None

        if self.AUTH_CLASS is not None:
            self.auth = self.AUTH_CLASS(self)
        else:
            self.auth = None

    @property
    def region_name(self):
        return self.config.get_region()

    def collect_arg_objs(self):
        service_args = aggregate_subclass_fields(self.__class__, 'ARGS')
        if self.auth is not None:
            auth_args = self.auth.collect_arg_objs()
        else:
            auth_args = []
        return service_args + auth_args

    def preprocess_arg_objs(self, arg_objs):
        if self.auth is not None:
            self.auth.preprocess_arg_objs(arg_objs)

    def configure(self):
        # self.args gets highest precedence for self.endpoint and user/region
        self.process_url(self.args.get('url'))
        if self.args.get('userregion'):
            self.process_userregion(self.args['userregion'])
        # Environment comes next
        self.process_url(os.getenv(self.ENV_URL))
        # Finally, try the config file
        self.process_url(self.config.get_region_option(self.NAME + '-url'))

        # Ensure everything is okay and finish up
        self.validate_config()
        if self.auth is not None:
            self.auth.configure()

    @property
    def session(self):
        if self._session is not None:
            return self._session
        if requests.__version__ >= '1.0':
            self._session = requests.session()
            self._session.auth = self.auth
            for key, val in self.session_args.iteritems():
                setattr(self._session, key, val)
        else:
            self._session = requests.session(auth=self.auth,
                                             **self.session_args)
        return self._session

    def validate_config(self):
        if self.endpoint is None:
            regions = ', '.join(sorted(self.config.regions.keys()))
            errmsg = 'no endpoint to connect to was given'
            if regions:
                errmsg += '.  Known regions are ' + regions
            raise ServiceInitError(errmsg)

    def process_url(self, url):
        if url:
            if '::' in url:
                userregion, endpoint = url.split('::', 1)
            else:
                endpoint   = url
                userregion = None
            if self.endpoint is None:
                self.endpoint = url
            if userregion:
                self.process_userregion(userregion)

    def process_userregion(self, userregion):
        if '@' in userregion:
            user, region = userregion.split('@', 1)
        else:
            user   = None
            region = userregion
        if region and self.config.current_region is None:
            self.config.current_region = region
        if user and self.config.current_user is None:
            self.config.current_user = user

    ## TODO:  nuke Action; the request should make it a param instead
    ## TODO:  the same should probably happen with API versions, but the
    ##        request would have to deal with service.API_VERSION, too
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
            if self.endpoint.endswith('/'):
                url = self.endpoint + path
            else:
                url = self.endpoint + '/' + path
        else:
            url = self.endpoint

        ## TODO:  replace pre_send and post_request hooks for use with requests 1
        hooks = {'pre_send':     _log_request_data(self.log),
                 'response':     _log_response_data(self.log),
                 'post_request': RetryOnStatuses((500, 503), self.MAX_RETRIES,
                                                  logger=self.log)}

        try:
            return self.session.request(method=method, url=url, params=params,
                                        data=data, headers=headers,
                                        hooks=hooks)
        except requests.exceptions.ConnectionError as exc:
            raise ClientError('connection error')
        except requests.exceptions.RequestException as exc:
            raise ClientError(exc)


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
