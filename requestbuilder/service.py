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

import copy
import datetime
import functools
import logging
import os.path
import random
import requests.exceptions
import time
import urlparse
import weakref

from .exceptions import ClientError, ServerError, ServiceInitError
from .util import aggregate_subclass_fields


class BaseService(object):
    NAME        = ''
    DESCRIPTION = ''
    API_VERSION = ''
    MAX_RETRIES = 4  ## TODO:  check the config file

    AUTH_CLASS = None
    REGION_ENVVAR = None
    URL_ENVVAR = None

    ARGS = []

    def __init__(self, config, loglevel=None, **kwargs):
        self.args      = kwargs
        self.config    = config
        self.endpoint  = None
        self.log       = logging.getLogger(self.__class__.__name__)
        if loglevel is not None:
            self.log.level = loglevel
        self.session_args = {'verify': False}  # SSL verification is opt-in
        self._session = None

        if self.AUTH_CLASS is not None:
            self.auth = self.AUTH_CLASS(self)
            self.auth.service = weakref.proxy(self)
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
        if self.REGION_ENVVAR in os.environ:
            self.process_userregion(os.getenv(self.REGION_ENVVAR))
        self.process_url(os.getenv(self.URL_ENVVAR))
        # Finally, try the config file
        self.process_url(self.config.get_region_option(self.NAME + '-url'))

        # Ensure everything is okay and finish up
        self.validate_config()
        if self.auth is not None:
            self.auth.configure()

    @property
    def session(self):
        if self._session is None:
            if requests.__version__ >= '1.0':
                self._session = requests.session()
                for key, val in self.session_args.iteritems():
                    setattr(self._session, key, val)
            else:
                self._session = requests.session(**self.session_args)
        return self._session

    def validate_config(self):
        if self.endpoint is None:
            url_opt = '{0}-url'.format(self.NAME)
            available_regions = []
            for rname, rconfig in self.config.regions.iteritems():
                if url_opt in rconfig and '*' not in rname:
                    available_regions.append(rname)
            if len(available_regions) > 0:
                msg = ('No {0} endpoint to connect to was given. Configured '
                       'regions with {0} endpoints are: {1}').format(
                    self.NAME, ', '.join(sorted(available_regions)))
            else:
                msg = ('No {0} endpoint to connect to was given. {0} '
                       'endpoints may be specified in a config file with '
                       '"{1}".').format(self.NAME, url_opt)
            raise ServiceInitError(msg)

    def process_url(self, url):
        if url:
            if '::' in url:
                userregion, endpoint = url.split('::', 1)
            else:
                endpoint = url
                userregion = None
            if self.endpoint is None:
                self.endpoint = endpoint
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

    def send_request(self, method='GET', path=None, params=None, headers=None,
                     data=None):
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

        hooks = {'pre_send': functools.partial(_log_request_data,  self.log),
                 'response': functools.partial(_log_response_data, self.log)}
        # Note that pre_send only works on requests 0

        try:
            max_tries = self.MAX_RETRIES + 1
            assert max_tries >= 1
            for attempt_no, delay in enumerate(_generate_delays(max_tries), 1):
                # Use exponential backoff if this is a retry
                if delay > 0:
                    self.log.debug('will retry after %.3f seconds', delay)
                    time.sleep(delay)

                self.log.info('sending request (attempt %i of %i)', attempt_no,
                              max_tries)
                # Requests 1 gives auth handlers PreparedRequests instead of the
                # original Requests like version 0 does.  Since most of our auth
                # handlers inspect and/or modify things that aren't headers, we
                # manually apply auth to it in this method to make things less
                # painful.
                if requests.__version__ >= '1.0':
                    request = requests.Request(method=method, url=url,
                                               params=params, data=data,
                                               headers=headers)
                    self.auth(request)
                    # A prepared request gives us extra info we want to log
                    p_request = request.prepare()
                    p_request.hooks = {'response': hooks['response']}
                    self.log.debug('request method: %s', request.method)
                    self.log.debug('request url:    %s', p_request.url)
                    if isinstance(p_request.headers, dict):
                        for key, val in sorted(p_request.headers.iteritems()):
                            if key.lower().endswith('password'):
                                val = '<redacted>'
                            self.log.debug('request header: %s: %s', key, val)
                    if isinstance(request.params, dict):
                        for key, val in sorted(request.params.iteritems()):
                            if key.lower().endswith('password'):
                                val = '<redacted>'
                            self.log.debug('request param:  %s: %s', key, val)
                    if isinstance(request.data, dict):
                        for key, val in sorted(request.data.iteritems()):
                            if key.lower().endswith('password'):
                                val = '<redacted>'
                            self.log.debug('request data:   %s: %s', key, val)
                    p_request.start_time = datetime.datetime.now()
                    response = self.session.send(p_request)
                else:
                    request = requests.Request(method=method, url=url,
                                               params=params, data=data,
                                               headers=headers,
                                               allow_redirects=True)
                    self.auth(request)
                    request.session = self.session
                    # A hook lets us log all the info that requests adds right
                    # before sending
                    request.hooks = hooks
                    request.start_time = datetime.datetime.now()
                    request.send()
                    response = request.response
                if response.status_code not in (500, 503):
                    break
                # If it *was* in that list, retry
            if response.status_code >= 300:
                # We include redirects because at this point, requests should
                # have handled it, but hasn't done so for some reason.
                self.handle_http_error(response)
            return response
        except requests.exceptions.ConnectionError as exc:
            raise ClientError('connection error')
        except requests.exceptions.HTTPError as exc:
            return self.handle_http_error(response)
        except requests.exceptions.RequestException as exc:
            raise ClientError(exc)

    def handle_http_error(self, response):
        raise ServerError(response)


# Note that the hook this is meant to run as was removed from requests 1.
def _log_request_data(logger, request, **kwargs):
    logger.debug('request method: %s', request.method)
    logger.debug('request url:    %s', request.full_url)
    if isinstance(request.headers, dict):
        for key, val in sorted(request.headers.iteritems()):
            if key.lower().endswith('password'):
                val = '<redacted>'
            logger.debug('request header: %s: %s', key, val)
    if isinstance(request.params, dict):
        for key, val in sorted(request.params.iteritems()):
            if key.lower().endswith('password'):
                val = '<redacted>'
            logger.debug('request param:  %s: %s', key, val)
    if isinstance(request.data, dict):
        for key, val in sorted(request.data.iteritems()):
            if key.lower().endswith('password'):
                val = '<redacted>'
            logger.debug('request data:   %s: %s', key, val)


def _log_response_data(logger, response, **kwargs):
    duration = datetime.datetime.now() - response.request.start_time
    logger.debug('response time: %i.%03i seconds', duration.seconds,
                 duration.microseconds // 1000)
    if response.status_code >= 400:
        logger.error('response status: %i', response.status_code)
    else:
        logger.info('response status: %i', response.status_code)
    if isinstance(response.headers, dict):
        for key, val in sorted(response.headers.items()):
            logger.debug('response header: %s: %s', key, val)


def _generate_delays(max_tries):
    if max_tries >= 1:
        yield 0
        for retry_no in range(1, max_tries):
            next_delay = (random.random() + 1) * 2 ** (retry_no - 1)
            yield min((next_delay, 15))
