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

from __future__ import absolute_import

import logging
import platform
import sys

from . import __version__, EMPTY, AUTH, PARAMS, SERVICE, SESSION
from .command import BaseCommand
from .exceptions import ClientError, ServerError
from .service import BaseService
from .xmlparse import parse_listdelimited_aws_xml

class BaseRequest(BaseCommand):
    '''
    The basis for a command line tool that represents a request.  To invoke
    this as a command line tool, call the do_cli() method on an instance of the
    class; arguments will be parsed from the command line.  To invoke this in
    another context, pass keyword args to __init__() with names that match
    those stored by the argument parser and then call main().

    Important methods in this class include:
     - do_cli:       command line entry point
     - main:         pre/post-request processing and request sending
     - send:         actually send a request to the server and return a
                     response (called by the main() method)
     - print_result: format data from the main method and print it to stdout

    To be useful a tool should inherit from this class and implement the main()
    and print_result() methods.  The do_cli() method functions as the entry
    point for the command line, populating self.args from the command line and
    then calling main() and print_result() in sequence.  Other tools may
    instead supply arguments via __init__() and then call main() alone.

    Important members of this class include:
     - ServiceClass: a class corresponding to the web service in use
     - APIVersion:   the API version to send along with the request.  This is
                     only necessary to override the service class's API version
                     for a specific request.
     - Action:       a string containing the Action query parameter.  This
                     defaults to the class's name.
     - Description:  a string describing the tool.  This becomes part of the
                     command line help string.
     - Args:         a list of Arg and/or MutuallyExclusiveArgGroup objects
                     are used to generate command line arguments.  Inheriting
                     classes needing to add command line arguments should
                     contain their own Args lists, which are *prepended* to
                     those of their parent classes.
     - Filters:      a list of Filter objects that are used to generate filter
                     options at the command line.  Inheriting classes needing
                     to add filters should contain their own Filters lists,
                     which are *prepended* to those of their parent classes.
    '''

    ServiceClass = BaseService
    APIVersion   = None
    Action       = None

    ListDelims = []

    DefaultRoute = PARAMS

    def __init__(self, **kwargs):
        BaseCommand.__init__(self, **kwargs)

        # Parts of the HTTP request to be sent to the server.
        # Note that self.serialize_params will update self.params for each
        # entry in self.args that routes to PARAMS.
        self.headers   = None
        self.params    = None
        self.post_data = None
        self.method    = 'GET'

        # HTTP response obtained from the server
        self.response    = None

        self._service    = None
        self._user_agent = None

    @property
    def name(self):
        '''
        The name of this action.  Used when choosing what to supply for the
        Action query parameter.
        '''
        return self.Action or self.__class__.__name__

    @property
    def user_agent(self):
        '''
        Return a user-agent string for this program.
        '''
        if not self._user_agent:
            template = 'requestbuilder/{ver} ({os} {osver}; {python} {pyver})'
            self._user_agent = template.format(ver=__version__,
                    os=platform.uname()[0], osver=platform.uname()[2],
                    python=platform.python_implementation(),
                    pyver=platform.python_version())
        return self._user_agent

    @property
    def service(self):
        if self._service is None:
            service_args = {'auth_args':    {},
                            'session_args': {}}
            for (key, val) in self.args.iteritems():
                if key in self._arg_routes.get(SERVICE, []):
                    service_args[key] = val
                elif key in self._arg_routes.get(AUTH, []):
                    service_args['auth_args'][key] = val
                elif key in self._arg_routes.get(SESSION, []):
                    service_args['session_args'][key] = val
            self._service = self.ServiceClass(self.log, **service_args)
        return self._service

    @property
    def status(self):
        if self.response is not None:
            return self.response.status
        else:
            return None

    def serialize_params(self, args, route, prefix=None):
        '''
        Given a possibly-nested dict of args and an arg routing destination,
        transform each element in the dict that matches the corresponding
        arg routing table into a simple dict containing key-value pairs
        suitable for use as query parameters.  This implementation flattens
        dicts and lists into the format given by the EC2 query API, which uses
        dotted lists of dict keys and list indices to indicate nested
        structures.

        Keys with nonzero values that evaluate as false are ignored.  If a
        collection of keys is supplied with ignore then keys that do not
        appear in that collection are also ignored.

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
            return {}
        elif isinstance(args, dict):
            for (key, val) in args.iteritems():
                # Prefix.Key1, Prefix.Key2, ...
                if key in self._arg_routes.get(route, []) or route is _ALWAYS:
                    if prefix:
                        prefixed_key = prefix + '.' + str(key)
                    else:
                        prefixed_key = str(key)

                    if isinstance(val, dict) or isinstance(val, list):
                        flattened.update(self.serialize_params(val, _ALWAYS,
                                                               prefixed_key))
                    elif isinstance(val, file):
                        flattened[prefixed_key] = val.read()
                    elif val or val is 0:
                        flattened[prefixed_key] = str(val)
                    elif val is EMPTY:
                        flattened[prefixed_key] = ''
        elif isinstance(args, list):
            for (i_item, item) in enumerate(args, 1):
                # Prefix.1, Prefix.2, ...
                if prefix:
                    prefixed_key = prefix + '.' + str(i_item)
                else:
                    prefixed_key = str(i_item)

                if isinstance(item, dict) or isinstance(item, list):
                    flattened.update(self.serialize_params(item, _ALWAYS,
                                                           prefixed_key))
                elif isinstance(item, file):
                    flattened[prefixed_key] = item.read()
                elif item or item == 0:
                    flattened[prefixed_key] = str(item)
                elif val is EMPTY:
                    flattened[prefixed_key] = ''
        else:
            raise TypeError('non-flattenable type: ' + args.__class__.__name__)
        return flattened

    def send(self):
        '''
        Send a request to the server and return its response.  More precisely:

         1. Build a dict of params suitable for submission as HTTP request
            parameters, based first upon the content of self.params, and
            second upon everything in self.args that routes to PARAMS.
         2. Send an HTTP request via self.service with the HTTP method given
            in self.method using query parameters from the aforementioned
            serialized dict, headers based on self.headers, and POST data based
            on self.post_data.
         3. If the response's status code indicates success, parse the
            response with self.parse_response and return the result.
         4. If the response's status code does not indicate success, log an
            error and raise a ServerError.
        '''
        params =      self.serialize_params(self.args,   PARAMS)
        params.update(self.serialize_params(self.params, _ALWAYS))
        headers = dict(self.headers or {})
        headers.setdefault('User-Agent', self.user_agent)
        self.log.debug('serialized params: %s', params)
        self.response = self.service.make_request(self.name,
                method=self.method, headers=headers, params=params,
                data=self.post_data, api_version=self.APIVersion)
        try:
            if 200 <= self.response.status_code < 300:
                parsed = self.parse_response(self.response)
                self.log.debug('result: success')
                return parsed
            else:
                self.log.debug('-- response content --\n%s',
                               self.response.text)
                self.log.debug('-- end of response content --')
                self.log.debug('result: failure')
                raise ServerError(self.response.status_code,
                                  self.response.content)
        finally:
            # Empty the socket buffer so it can be reused
            try:
                self.response.content
            except RuntimeError:
                # The content was already consumed
                pass

    def parse_response(self, response):
        # Parser for list-delimited responses like EC2's

        # We do some extra handling here to log stuff as it comes in rather
        # than reading it all into memory at once.
        self.log.debug('-- response content --\n', extra={'append': True})
        # Using Response.iter_content gives us automatic decoding, but we then
        # have to make the generator look like a file so etree can use it.
        with _IteratorFileObjAdapter(self.response.iter_content(16384)) \
                as content_fileobj:
            logged_fileobj = _ReadLoggingFileWrapper(content_fileobj, self.log,
                                                     logging.DEBUG)
            response_dict = parse_listdelimited_aws_xml(logged_fileobj,
                                                        self.ListDelims)
        self.log.debug('-- end of response content --')
        # Strip off the root element
        return response_dict[response_dict.keys()[0]]

    def main(self):
        '''
        The main processing method for this type of request.  In this method,
        inheriting classes generally populate self.headers, self.params, and
        self.post_data with information gathered from self.args or elsewhere,
        call self.send, and return the response.  BaseRequest's default
        behavior is to simply return the result of a request with everything
        that routes to PARAMS.
        '''
        return self.send()

    def _handle_cli_exception(self, err):
        if isinstance(err, ServerError):
            if err.code:
                print >> sys.stderr, 'error ({code}) {msg}'.format(
                        code=err.code, msg=err.message or '')
            else:
                print >> sys.stderr, 'error {msg}'.format(
                        msg=err.message or '')
            if self.debug:
                raise
            sys.exit(1)
        else:
            BaseCommand._handle_cli_exception(self, err)

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
            self.buflist = None
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

_ALWAYS = type('_ALWAYS', (), {'__repr__': lambda self: '_ALWAYS'})()
