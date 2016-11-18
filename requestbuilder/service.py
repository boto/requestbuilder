# Copyright (c) 2012-2016 Hewlett Packard Enterprise Development LP
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

import cgi
import collections
import datetime
import functools
import io
import logging
import os.path
import random
import time

import requests.exceptions
import six
import six.moves.urllib_parse as urlparse

from requestbuilder.exceptions import (ClientError, ServerError,
                                       ServiceInitError, TimeoutError)
from requestbuilder.mixins import RegionConfigurableMixin


class BaseService(RegionConfigurableMixin):
    NAME = None
    DESCRIPTION = ''
    API_VERSION = ''
    MAX_RETRIES = 2
    TIMEOUT = 30  # socket timeout in seconds

    REGION_ENVVAR = None
    URL_ENVVAR = None

    ARGS = []

    def __init__(self, config, loglevel=None, max_retries=None, timeout=None,
                 **kwargs):
        self.args = kwargs
        self.config = config
        self.endpoint = None
        self.log = logging.getLogger(self.__class__.__name__)
        if loglevel is not None:
            self.log.level = loglevel
        self.max_retries = max_retries
        self.region_name = None  # Note this can differ from config.region
        self.session_args = {}
        self.timeout = timeout
        self._session = None

    @classmethod
    def from_other(cls, other, **kwargs):
        kwargs.setdefault('loglevel', other.log.level)
        kwargs.setdefault('max_retries', other.max_retries)
        kwargs.setdefault('session_args', dict(other.session_args))
        kwargs.setdefault('timeout', other.timeout)
        if 'region' in other.args:
            kwargs.setdefault('region', other.args['region'])
        new = cls(other.config, **kwargs)
        new.configure()
        return new

    def configure(self):
        # TODO:  rename this to setup
        #
        # Configure user and region before grabbing endpoint info since
        # the latter may depend upon the former
        self.update_config_view()
        self.__configure_endpoint()

        # Configure timeout and retry handlers
        if self.max_retries is None:
            config_max_retries = self.config.get_global_option('max-retries')
            if config_max_retries is not None:
                self.max_retries = int(config_max_retries)
            else:
                self.max_retries = self.MAX_RETRIES
        if self.timeout is None:
            config_timeout = self.config.get_global_option('timeout')
            if config_timeout is not None:
                self.timeout = float(config_timeout)
            else:
                self.timeout = self.TIMEOUT

        self.session_args.setdefault('stream', True)

        # SSL cert verification is opt-in
        self.session_args.setdefault('verify', self.config.convert_to_bool(
            self.config.get_region_option('verify-ssl'), default=False))

        # Ensure everything is okay and finish up
        self.validate_config()

    @property
    def session(self):
        if self._session is None:
            self._session = requests.session()
            for key, val in six.iteritems(self.session_args):
                setattr(self._session, key, val)
            for adapter in self._session.adapters.values():
                # send_request handles retries to allow for re-signing
                adapter.max_retries = 0
        return self._session

    def validate_config(self):
        if self.endpoint is None:
            if self.NAME is not None:
                url_opt = '{0}-url'.format(self.NAME)
                available_regions = self.config.get_all_region_options(url_opt)
                if len(available_regions) > 0:
                    msg = ('No {0} endpoint to connect to was given. '
                           'Configured regions with {0} endpoints are: '
                           '{1}').format(self.NAME,
                                         ', '.join(sorted(available_regions)))
                else:
                    msg = ('No {0} endpoint to connect to was given. {0} '
                           'endpoints may be specified in a config file with '
                           '"{1}".').format(self.NAME, url_opt)
            else:
                msg = 'No endpoint to connect to was given'
            raise ServiceInitError(msg)

    def get_request_url(self, method='GET', path=None, params=None,
                        headers=None, data=None, files=None, auth=None):
        url = self.__get_url_for_path(path)

        headers = dict(headers or {})
        if 'host' not in [header.lower() for header in headers]:
            headers['Host'] = urlparse.urlparse(self.endpoint).netloc

        p_request = self.__log_and_prepare_request(method, url, params, data,
                                                   files, headers, auth)
        return p_request.url

    def send_request(self, method='GET', path=None, params=None, headers=None,
                     data=None, files=None, auth=None):
        url = self.__get_url_for_path(path)
        headers = dict(headers)
        if 'host' not in [header.lower() for header in headers]:
            headers['Host'] = urlparse.urlparse(self.endpoint).netloc

        try:
            max_tries = self.max_retries + 1
            assert max_tries >= 1
            redirects_left = 5
            if isinstance(data, file) and hasattr(data, 'seek'):
                # If we're redirected we need to be able to reset
                data_file_offset = data.tell()
            else:
                data_file_offset = None
            while True:
                for attempt_no, delay in enumerate(
                        _generate_delays(max_tries), 1):
                    # Use exponential backoff if this is a retry
                    if delay > 0:
                        self.log.debug('will retry after %.3f seconds', delay)
                        time.sleep(delay)

                    self.log.info('sending request (attempt %i of %i)',
                                  attempt_no, max_tries)
                    p_request = self.__log_and_prepare_request(
                        method, url, params, data, files, headers, auth)
                    proxies = requests.utils.get_environ_proxies(url)
                    for key, val in sorted(proxies.items()):
                        self.log.debug('request  proxy:  %s=%s', key, val)
                    p_request.start_time = datetime.datetime.now()
                    try:
                        response = self.session.send(
                            p_request, timeout=self.timeout, proxies=proxies,
                            allow_redirects=False)
                    except requests.exceptions.Timeout:
                        if attempt_no < max_tries:
                            self.log.debug('timeout', exc_info=True)
                            if data_file_offset is not None:
                                self.log.debug('re-seeking body to '
                                               'beginning of file')
                                # pylint: disable=E1101
                                data.seek(data_file_offset)
                                # pylint: enable=E1101
                                continue
                            elif not hasattr(data, 'tell'):
                                continue
                            # Fallthrough -- if it has a file pointer but not
                            # seek we can't retry because we can't rewind.
                        raise
                    if response.status_code not in (500, 503):
                        break
                    # If it *was* in that list, retry
                if (response.status_code in (301, 302, 307, 308) and
                        redirects_left > 0 and 'Location' in response.headers):
                    # Standard redirect -- we need to handle this ourselves
                    # because we have to re-sign requests when their URLs
                    # change.
                    redirects_left -= 1
                    parsed_rdr = urlparse.urlparse(
                        response.headers['Location'])
                    parsed_url = urlparse.urlparse(url)
                    new_url_bits = []
                    for rdr_bit, url_bit in zip(parsed_rdr, parsed_url):
                        new_url_bits.append(rdr_bit or url_bit)
                    if 'Host' in headers:
                        headers['Host'] = new_url_bits[1]  # netloc
                    url = urlparse.urlunparse(new_url_bits)
                    self.log.debug('redirecting to %s (%i redirect(s) '
                                   'remaining)', url, redirects_left)
                    if data_file_offset is not None:
                        self.log.debug('re-seeking body to beginning of file')
                        # pylint: disable=E1101
                        data.seek(data_file_offset)
                        # pylint: enable=E1101
                    continue
                elif response.status_code >= 300:
                    # We include 30x because we've handled the standard method
                    # of redirecting, but the server might still be trying to
                    # redirect another way for some reason.
                    self.handle_http_error(response)
                return response
        except requests.exceptions.Timeout as exc:
            self.log.debug('timeout', exc_info=True)
            raise TimeoutError('request timed out', exc)
        except requests.exceptions.ConnectionError as exc:
            self.log.debug('connection error', exc_info=True)
            return self.__handle_connection_error(exc)
        except requests.exceptions.HTTPError as exc:
            return self.handle_http_error(response)
        except requests.exceptions.RequestException as exc:
            self.log.debug('request error', exc_info=True)
            raise ClientError(exc)

    def __handle_connection_error(self, err):
        if isinstance(err, six.string_types):
            msg = err
        elif isinstance(err, Exception) and len(err.args) > 0:
            if hasattr(err.args[0], 'reason'):
                msg = err.args[0].reason
            elif isinstance(err.args[0], Exception):
                return self.__handle_connection_error(err.args[0])
            else:
                msg = err.args[0]
        else:
            raise ClientError('connection error')
        raise ClientError('connection error ({0})'.format(msg))

    def handle_http_error(self, response):
        self.log.debug('HTTP error', exc_info=True)
        raise ServerError(response)

    def __get_url_for_path(self, path):
        if path:
            # We can't simply use urljoin because a path might start with '/'
            # like it could for S3 keys that start with that character.
            if self.endpoint.endswith('/'):
                return self.endpoint + path
            else:
                return self.endpoint + '/' + path
        else:
            return self.endpoint

    def __log_and_prepare_request(self, method, url, params, data, files,
                                  headers, auth):
        hooks = {'response': functools.partial(_log_response_data, self.log)}
        if auth:
            bound_auth = auth.bind_to_service(self)
        else:
            bound_auth = None
        request = requests.Request(method=method, url=url, params=params,
                                   data=data, files=files, headers=headers,
                                   auth=bound_auth)
        p_request = self.session.prepare_request(request)
        p_request.hooks = {'response': hooks['response']}
        self.log.debug('request  method: %s', request.method)
        self.log.debug('request  url:    %s', p_request.url)
        if isinstance(p_request.headers, (dict, collections.Mapping)):
            for key, val in sorted(six.iteritems(p_request.headers)):
                if key.lower().endswith('password'):
                    val = '<redacted>'
                self.log.debug('request  header: %s: %s', key, val)
        if isinstance(request.params, (dict, collections.Mapping)):
            for key, val in sorted(urlparse.parse_qsl(
                    urlparse.urlparse(p_request.url).query,
                    keep_blank_values=True)):
                if key.lower().endswith('password'):
                    val = '<redacted>'
                self.log.debug('request  param:  %s: %s', key, val)
        if isinstance(request.data, (dict, collections.Mapping)):
            content_type, content_type_params = cgi.parse_header(
                p_request.headers.get('content-type') or '')
            if content_type == 'multipart/form-data':
                data = cgi.parse_multipart(io.BytesIO(p_request.body),
                                           content_type_params)
            elif content_type == 'application/x-www-form-urlencoded':
                data = dict(urlparse.parse_qsl(p_request.body,
                                               keep_blank_values=True))
            else:
                data = request.data
            for key, val in sorted(data.items()):
                # pylint: disable=superfluous-parens
                if key in (request.files or {}):
                    # We probably don't want to include the contents of
                    # entire files in debug output.
                    continue
                # pylint: enable=superfluous-parens
                if key.lower().endswith('password'):
                    val = '<redacted>'
                self.log.debug('request  data:   %s: %s', key, val)
        if isinstance(request.files, (dict, collections.Mapping)):
            for key, val in sorted(six.iteritems(request.files)):
                if hasattr(val, '__len__'):
                    val = '<{0} bytes>'.format(len(val))
                self.log.debug('request  file:   %s: %s', key, val)
        return p_request

    def __configure_endpoint(self):
        # self.args gets highest precedence
        if self.args.get('url'):
            url, region_name = _parse_endpoint_url(self.args['url'])
        # Environment comes next
        elif os.getenv(self.URL_ENVVAR):
            url, region_name = _parse_endpoint_url(os.getenv(self.URL_ENVVAR))
        # Try the config file
        elif self.NAME:
            url, section = self.config.get_region_option2(self.NAME + '-url')
            if section:
                # Check to see if the region name is explicitly specified
                region_name = self.config.get_region_option('name', section)
                if region_name is None:
                    # If it isn't then just grab the end of the section name
                    region_name = section.rsplit(':', 1)[-1]
            else:
                region_name = None
        self.endpoint = url
        self.region_name = region_name


def _log_response_data(logger, response, **_):
    if hasattr(response.request, 'start_time'):
        duration = datetime.datetime.now() - response.request.start_time
        logger.debug('response time:   %i.%03i seconds', duration.seconds,
                     duration.microseconds // 1000)
    if response.status_code >= 400:
        logger.error('response status: %i', response.status_code)
    else:
        logger.info('response status: %i', response.status_code)
    if isinstance(response.headers, (dict, collections.Mapping)):
        for key, val in sorted(response.headers.items()):
            logger.debug('response header: %s: %s', key, val)


def _generate_delays(max_tries):
    if max_tries >= 1:
        yield 0
        for retry_no in range(1, max_tries):
            next_delay = (random.random() + 1) * 2 ** (retry_no - 1)
            yield min((next_delay, 15))


def _parse_endpoint_url(urlish):
    """
    If given a URL, return the URL and None.  If given a URL with a string and
    "::" prepended to it, return the URL and the prepended string.  This is
    meant to give one a means to supply a region name via arguments and
    variables that normally only accept URLs.
    """
    if '::' in urlish:
        region, url = urlish.split('::', 1)
    else:
        region = None
        url = urlish
    return url, region
