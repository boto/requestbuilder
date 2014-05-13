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

import argparse
from functools import partial
import logging
import os.path
import sys
import textwrap
import warnings

from requestbuilder import EMPTY, PARAMS
from requestbuilder.command import BaseCommand
from requestbuilder.exceptions import ServerError
from requestbuilder.service import BaseService
from requestbuilder.util import aggregate_subclass_fields
from requestbuilder.xmlparse import parse_listdelimited_aws_xml


class BaseRequest(BaseCommand):
    '''
    The basis for a command line tool that represents a request.  The data for
    this request are stored in a few instance members:
     - method:   the HTTP method to use (e.g. 'GET').  Defaults to self.METHOD.
     - path:     the path to append to the service's path (e.g. 'sub/dir')
     - headers:  a dict of HTTP headers
     - params:   a dict of query parameters
     - body:     a string or file object containing a request body, or a dict
                 to pass to the server as form data

    This specialization of BaseCommand that implements main() as a three-step
    process:
     - preprocess():   do any processing needed before sending the request,
                       such as parsing complex command line arguments and
                       storing them in self.params, self.headers, and so forth.
     - send():         send this request to the server using the data stored
                       in its attributes, parse it using self.parse_result(),
                       and return it
     - postprocess():  given a parsed response, do any processing needed before
                       main() returns the response.

    Most requests need only implement preprocess().  Requests whose workflows
    involve sending other requests often do so in postprocess(), where the
    result of the request is known.

    Important members of this class, in addition to those inherited from
    BaseCommand, include:
     - SERVICE_CLASS:  a class corresponding to the web service in use
     - NAME:           a string representing the name of this request.  This
                       defaults to the class's name.
     - METHOD:         the HTTP method to use by default
    '''

    SERVICE_CLASS = BaseService
    AUTH_CLASS    = None
    NAME          = None
    METHOD        = 'GET'

    DEFAULT_ROUTES = (PARAMS,)
    LIST_TAGS = []


    def __init__(self, service=None, auth=None, **kwargs):
        self.auth = auth
        self.service = service
        # Parts of the HTTP request to be sent to the server.
        self.method    = self.METHOD
        self.path      = None
        self.headers   = {}
        self.params    = {}
        self.body      = ''
        self.files     = {}

        # HTTP response obtained from the server
        self.response = None

        self.__configured = False

        BaseCommand.__init__(self, **kwargs)

    def _post_init(self):
        if self.service is None and self.SERVICE_CLASS is not None:
            self.service = self.SERVICE_CLASS(self.config,
                                              loglevel=self.log.level)
        if self.auth is None:
            if self.AUTH_CLASS is not None:
                self.auth = self.AUTH_CLASS(self.config,
                                            loglevel=self.log.level)
            elif self.SERVICE_CLASS.AUTH_CLASS is not None:
                # Backward compatibility
                msg = ('BaseService.AUTH_CLASS is deprecated; use '
                       'BaseRequest.AUTH_CLASS instead')
                self.log.warn(msg)
                warnings.warn(msg, DeprecationWarning)
                self.auth = self.SERVICE_CLASS.AUTH_CLASS(
                    self.config, loglevel=self.log.level)
        BaseCommand._post_init(self)

    @classmethod
    def from_other(cls, other, **kwargs):
        kwargs.setdefault('service', other.service)
        kwargs.setdefault('auth', other.auth)
        kwargs.setdefault('loglevel', other.log.level)
        new = cls(config=other.config, **kwargs)
        # That already calls configure
        return new

    def collect_arg_objs(self):
        arg_objs = BaseCommand.collect_arg_objs(self)
        if self.service is not None:
            arg_objs.extend(
                aggregate_subclass_fields(self.service.__class__, 'ARGS'))
        if self.auth is not None:
            arg_objs.extend(
                aggregate_subclass_fields(self.auth.__class__, 'ARGS'))
        return arg_objs

    def distribute_args(self):
        BaseCommand.distribute_args(self)
        if self.service is not None:
            self.service.args.update(self.args)
        if self.auth is not None:
            self.auth.args.update(self.args)

    def configure(self):
        BaseCommand.configure(self)
        if self.service is not None:
            self.service.configure()
        if self.auth is not None:
            self.auth.configure()
        self.__configured = True

    @property
    def name(self):
        return self.NAME or self.__class__.__name__

    @property
    def status(self):
        if self.response is not None:
            return self.response.status
        else:
            return None

    def send(self):
        if not self.__configured:
            self.log.warn('send() called before configure(); bugs may result')
        headers = dict(self.headers or {})
        headers.setdefault('User-Agent', self.suite.get_user_agent())
        params  = self.prepare_params()
        try:
            self.response = self.service.send_request(
                method=self.method, path=self.path, headers=headers,
                params=params, data=self.body, files=self.files,
                auth=self.auth)
            return self.parse_response(self.response)
        except ServerError as err:
            self.response = err.response
            try:
                # Empty the socket buffer so it can be reused.
                # Hopefully error responses won't be too large for this to be
                # problematic.
                if self.response is not None:
                    self.response.content
            except RuntimeError:
                # The content was already consumed
                pass
            return self.handle_server_error(err)

    def handle_server_error(self, err):
        self.log.debug('-- response content --\n',
                       extra={'append': True})
        self.log.debug(self.response.text, extra={'append': True})
        self.log.debug('-- end of response content --')
        self.log.info('result: failure')
        raise

    def prepare_params(self):
        return self.params or {}

    def parse_response(self, response):
        return response

    def log_and_parse_response(self, response, parse_func, **kwargs):
        # We do some extra handling here to log stuff as it comes in rather
        # than reading it all into memory at once.
        self.log.debug('-- response content --\n', extra={'append': True})
        # Using Response.iter_content gives us automatic decoding, but we then
        # have to make the generator look like a file so etree can use it.
        with _IteratorFileObjAdapter(self.response.iter_content(16384)) \
                as content_fileobj:
            logged_fileobj = _ReadLoggingFileWrapper(content_fileobj, self.log,
                                                     logging.DEBUG)
            parsed_response = parse_func(logged_fileobj, **kwargs)
        self.log.debug('-- end of response content --')
        return parsed_response

    def main(self):
        '''
        The main processing method for this type of request.  In this method,
        inheriting classes generally populate self.headers, self.params, and
        self.body with information gathered from self.args or elsewhere,
        call self.send, and return the response.
        '''
        self.preprocess()
        response = self.send()
        self.postprocess(response)
        return response

    def preprocess(self):
        pass

    def postprocess(self, response):
        pass

    def handle_cli_exception(self, err):
        if isinstance(err, ServerError):
            msg = '{0}: {1}'.format(os.path.basename(sys.argv[0]),
                                    err.format_for_cli())
            print >> sys.stderr, msg
            if self.debug:
                raise
            sys.exit(1)
        else:
            BaseCommand.handle_cli_exception(self, err)


class AWSQueryRequest(BaseRequest):
    API_VERSION = None
    FILTERS = []

    def populate_parser(self, parser, arg_objs):
        BaseRequest.populate_parser(self, parser, arg_objs)
        if self.FILTERS:
            parser.add_argument('--filter', metavar='NAME=VALUE',
                    action='append', dest='filters',
                    help='restrict results to those that meet criteria',
                    type=partial(_parse_filter, filter_objs=self.FILTERS))
            parser.epilog = self.__build_filter_help()
            self._arg_routes['filters'] = (None,)

    def process_cli_args(self):
        BaseRequest.process_cli_args(self)
        if 'filters' in self.args:
            self.args['Filter'] = _process_filters(self.args.pop('filters'))
            self._arg_routes['Filter'] = (self.params,)

    @property
    def action(self):
        return self.name

    def prepare_params(self):
        params = self.flatten_params(self.params)
        params['Action'] = self.action
        params['Version'] = self.API_VERSION or self.service.API_VERSION
        redacted_params = dict(params)
        for key in params:
            if key.lower().endswith('password'):
                # This makes it slightly more obvious that this is redacted by
                # the framework and not just a string.
                redacted_params[key] = type('REDACTED', (),
                        {'__repr__': lambda self: '<redacted>'})()
        self.log.info('parameters: %s', redacted_params)
        return params

    def parse_response(self, response):
        # Parser for list-delimited responses like EC2's
        response_dict = self.log_and_parse_response(response,
                parse_listdelimited_aws_xml, list_tags=self.LIST_TAGS)
        # Strip off the root element
        assert len(response_dict) == 1
        return response_dict[list(response_dict.keys())[0]]

    def flatten_params(self, args, prefix=None):
        '''
        Given a possibly-nested dict of args and an arg routing
        destination, transform each element in the dict that matches the
        corresponding arg routing table into a simple dict containing
        key-value pairs suitable for use as query parameters.  This
        implementation flattens dicts and lists into the format given
        by AWS query APIs, which use dotted lists of dict keys and list
        indices to indicate nested structures.

        Keys with non-boolean, non-zero values that evaluate as false
        are ignored.  To include an empty string as a parameter, pass
        EMPTY (the object, not the string) as its value.

        Examples:
          in:  {'InstanceId': 'i-12345678', 'PublicIp': '1.2.3.4'}
          out: {'InstanceId': 'i-12345678', 'PublicIp': '1.2.3.4'}

          in:  {'RegionName': ['us-east-1', 'us-west-1']}
          out: {'RegionName.1': 'us-east-1',
                'RegionName.2': 'us-west-1'}

          in:  {'Filter': [{'Name':  'image-id',
                            'Value': ['ami-12345678']},
                           {'Name':  'instance-type',
                            'Value': ['m1.small', 't1.micro']}],
                'InstanceId': ['i-24680135']}
          out: {'Filter.1.Name':    'image-id',
                'Filter.1.Value.1': 'ami-12345678',
                'Filter.2.Name':    'instance-type',
                'Filter.2.Value.1': 'm1.small',
                'Filter.2.Value.2': 't1.micro',
                'InstanceId.1':     'i-24680135'}
        '''
        flattened = {}
        if args is None:
            pass
        elif isinstance(args, dict):
            for (key, val) in args.iteritems():
                # Prefix.Key1, Prefix.Key2, ...
                if prefix:
                    prefixed_key = '{0}.{1}'.format(prefix, key)
                else:
                    prefixed_key = str(key)

                if isinstance(val, dict) or isinstance(val, list):
                    flattened.update(self.flatten_params(val, prefixed_key))
                elif isinstance(val, file):
                    flattened[prefixed_key] = val.read()
                elif val or val is 0:
                    flattened[prefixed_key] = str(val)
                elif isinstance(val, bool):
                    flattened[prefixed_key] = str(val).lower()
                elif val is EMPTY:
                    flattened[prefixed_key] = ''
        elif isinstance(args, list):
            for (i_item, item) in enumerate(args, 1):
                # Prefix.1, Prefix.2, ...
                if prefix:
                    prefixed_key = '{0}.{1}'.format(prefix, i_item)
                else:
                    prefixed_key = str(i_item)

                if isinstance(item, dict) or isinstance(item, list):
                    flattened.update(self.flatten_params(item, prefixed_key))
                elif isinstance(item, file):
                    flattened[prefixed_key] = item.read()
                elif item or item == 0:
                    flattened[prefixed_key] = str(item)
                elif isinstance(item, bool):
                    flattened[prefixed_key] = str(item).lower()
                elif item is EMPTY:
                    flattened[prefixed_key] = ''
        else:
            raise TypeError('non-flattenable type: ' + args.__class__.__name__)
        return flattened

    def __build_filter_help(self, force=False):
        '''
        Return a pre-formatted help string for all of the filters defined in
        self.FILTERS.  The result is meant to be used as command line help
        output.
        '''
        # Does not have access to self.config
        if '-h' not in sys.argv and '--help' not in sys.argv and not force:
            # Performance optimization
            return ''

        helplines = ['allowed filter names:']
        for filter_obj in self.FILTERS:
            if filter_obj.help:
                first, _, rest = filter_obj.help.partition('\n')
                if rest.startswith(' ') and not first.startswith(' '):
                    # First line is not uniformly indented
                    content = first + ' ' + textwrap.dedent(rest)
                else:
                    content = filter_obj.help
                if len(filter_obj.name) <= 20:
                    # Short name; start on same line and pad two spaces
                    firstline = '  {0:<20}  '.format(filter_obj.name)
                    wrapper = textwrap.TextWrapper(fix_sentence_endings=True,
                        initial_indent=firstline, subsequent_indent=(' ' * 24))
                else:
                    # Long name; start on next line
                    helplines.append('  ' + filter_obj.name)
                    wrapper = textwrap.TextWrapper(fix_sentence_endings=True,
                        initial_indent=(' ' * 24),
                        subsequent_indent=(' ' * 24))
                helplines.extend(wrapper.wrap(content))
            else:
                # No help; everything goes on one line
                helplines.append('  ' + filter_obj.name)
        return '\n'.join(helplines)


def _parse_filter(filter_str, filter_objs=None):
    '''
    Given a "key=value" string given as a command line parameter, return a pair
    with the matching filter's dest member and the given value after converting
    it to the type expected by the filter.  If this is impossible, an
    ArgumentTypeError will result instead.
    '''
    # Find the appropriate filter object
    filter_objs = [obj for obj in (filter_objs or [])
                   if obj.matches_argval(filter_str)]
    if not filter_objs:
        msg = '"{0}" matches no available filters'.format(filter_str)
        raise argparse.ArgumentTypeError(msg)
    return filter_objs[0].convert(filter_str)


def _process_filters(cli_filters):
    '''
    Change filters from the [(key, value), ...] format given at the command
    line to [{'Name': key, 'Value': [value, ...]}, ...] format, which
    flattens to the form the server expects.
    '''
    filter_args = {}
    # Compile [(key, value), ...] pairs into {key: [value, ...], ...}
    for (key, val) in cli_filters or {}:
        filter_args.setdefault(key, [])
        filter_args[key].append(val)
    # Build the flattenable [{'Name': key, 'Value': [value, ...]}, ...]
    filters = [{'Name': name, 'Value': values} for (name, values)
               in filter_args.iteritems()]
    return filters


class _IteratorFileObjAdapter(object):
    def __init__(self, source):
        self._source  = source
        self._buflist = []
        self._closed  = False
        self._len     = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @property
    def closed(self):
        return self._closed

    def close(self):
        if not self._closed:
            self._buflist = None
            self._closed = True

    def read(self, size=-1):
        if size is None or size < 0:
            for chunk in self._source:
                self._buflist.append(chunk)
            result = ''.join(self._buflist)
            self._buflist = []
            self._len     = 0
        else:
            while self._len < size:
                try:
                    chunk = next(self._source)
                    self._buflist.append(chunk)
                    self._len += len(chunk)
                except StopIteration:
                    break
            result    = ''.join(self._buflist)
            extra_len = len(result) - size
            self._buflist = []
            self._len     = 0
            if extra_len > 0:
                self._buflist = [result[-extra_len:]]
                self._len     = extra_len
                result = result[:-extra_len]
        return result


class _ReadLoggingFileWrapper(object):
    def __init__(self, fileobj, logger, level):
        self.fileobj = fileobj
        self.logger  = logger
        self.level   = level

    def read(self, size=-1):
        chunk = self.fileobj.read(size)
        self.logger.log(self.level, chunk, extra={'append': True})
        return chunk
