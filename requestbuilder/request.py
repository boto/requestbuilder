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

import argparse
import bdb
import boto.jsonresponse
from functools import partial
import json
import pprint
import sys
import textwrap
import traceback
import types

try:
    import epdb
except ImportError:
    import pdb

from . import __version__, CONNECTION, PARAMS, Arg, MutuallyExclusiveArgList
from .service import BaseService, MissingCredentialsError

class InheritableRequestClass(type):
    '''
    Classes of this type allow one to specify 'Args', 'Filters', 'ListMarkers',
    and 'ItemMarkers' lists as attributes of classes and have them be appended
    to their superclasses' rather than clobbering them.

    Additionally, all method calls are decorated with a function that renames
    logs to that of the the object's name() return value.
    '''
    def __new__(mcs, name, bases, attrs):
        for attrname in ('Args', 'Filters', 'ListMarkers', 'ItemMarkers'):
            if attrname in attrs:
                for base in bases:
                    for attr in getattr(base, attrname, []):
                        if attr not in attrs[attrname]:
                            attrs[attrname].append(attr)
        return type.__new__(mcs, name, bases, attrs)

class BaseRequest(object):
    '''
    The basis for a command line tool that represents a request.  To invoke
    this as a command line tool, call the do_cli() method on an instance of the
    class; arguments will be parsed from the command line.  To invoke this in
    another context, pass keyword args to __init__ with names that match those
    stored by the argument parser and then call main().

    Important methods in this class include:
     - do_cli:       command line entry point
     - main:         pre/post-request processing and request sending
     - send:         actually send a request to the server and return a
                     response (called by the main() method)
     - print_result: format data from the main method and print it to stdout

    To be useful a tool should inherit from this class and implement the main()
    and print_result() methods.  The do_cli() method functions as the entry
    point for the command line, populating self.args from the command line and
    then calling mein() and print_result() in sequence.  Other tools may
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

    __metaclass__ = InheritableRequestClass
    Version = 'requestbuilder ' + __version__

    ServiceClass = BaseService
    APIVersion   = None
    Action       = None
    Description  = ''

    ListMarkers = []
    ItemMarkers = []

    Args = [Arg('-D', '--debug', action='store_true', route_to=None,
                help='show debugging output'),
            Arg('--debugger', action='store_true', route_to=None,
                help='enable interactive debugger on error')]
    Filters = []

    def name(self):
        '''
        The name of this action.  Used when choosing what to supply for the
        Action query parameter.
        '''
        return self.Action or self.__class__.__name__

    def __init__(self, **kwargs):
        # Arguments corresponding to those in self.Args.  This may be used in
        # lieu of (and will take priority over) arguments given at the CLI.
        self.args = kwargs

        # Parts of the HTTP request to be sent to the server.
        # Note that self.flatten_params will update self.params for each entry
        # in self.args that routes to PARAMS.
        self.headers   = None
        self.params    = None
        self.post_data = None
        self.verb      = 'GET'

        # HTTP response obtained from the server
        self.http_response = None

        self._arg_routes = {}
        self._cli_parser = None
        self._connection = None

        self._parse_arg_lists()

    @property
    def connection(self):
        if self._connection is None:
            conn_args = {}
            for (key, val) in self.args.iteritems():
                if key in self._arg_routes.get(CONNECTION):
                    conn_args[key] = val
            self._connection = self.ServiceClass(**conn_args)
        return self._connection

    @property
    def status(self):
        if self.http_response is not None:
            return self.http_response.status
        else:
            return None

    @property
    def reason(self):
        if self.http_response is not None:
            return self.http_response.reason
        else:
            return None

    def print_result(self, data):
        '''
        Format data for printing at the command line and print it to standard
        out.  The default formatter attempts to print JSON or something else
        reasonable.  Override this method if you want specific formatting.
        '''
        if data:
            if isinstance(data, dict):
                for (key, val) in data.iteritems():
                    if key not in ['ResponseMetadata', 'requestId']:
                        # Will there ever be more than one of these?
                        print json.dumps(val, indent=4)
            elif isinstance(data, list):
                print '\n'.join([str(item) for item in data])
            elif isinstance(data, basestring):
                print data
            else:
                pprint.pprint(data)

    def flatten_params(self, args, route, prefix=None):
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
                        flattened.update(self.flatten_params(val, route,
                                                             prefixed_key))
                    elif isinstance(val, file):
                        flattened[prefixed_key] = val.read()
                    elif val or val is 0:
                        flattened[prefixed_key] = str(val)
        elif isinstance(args, list):
            for (i_item, item) in enumerate(args, 1):
                # Prefix.1, Prefix.2, ...
                if prefix:
                    prefixed_key = prefix + '.' + str(i_item)
                else:
                    prefixed_key = str(i_item)

                if isinstance(item, dict) or isinstance(item, list):
                    flattened.update(self.flatten_params(item, route,
                                                         prefixed_key))
                elif isinstance(item, file):
                    flattened[prefixed_key] = item.read()
                elif item or item == 0:
                    flattened[prefixed_key] = str(item)
        else:
            raise TypeError('non-flattenable type: ' + args.__class__.__name__)
        return flattened

    def _parse_arg_lists(self):
        '''
        Use self.Args and self.Filters to build a command line argument parser
        that is stored to self._cli_parser and to populate the argument routing
        table.
        '''
        self._cli_parser = argparse.ArgumentParser(
                description='\n'.join(textwrap.wrap(self.Description)),
                formatter_class=argparse.RawDescriptionHelpFormatter)
        for arg_obj in self.Args:
            self.__add_arg_to_cli_parser(arg_obj, self._cli_parser)
        if self.Filters:
            self._cli_parser.add_argument('--filter', metavar='key=value',
                    action='append', dest='_filters', help='filter output',
                    type=partial(_parse_filter, filter_objs=self.Filters))
            self._arg_routes[None].append('_filters')
            self._cli_parser.epilog = self.__build_filter_help()
        self._cli_parser.add_argument('--version', action='version',
                                      version=self.Version)

    def process_cli_args(self):
        '''
        Process CLI args to fill in missing parts of self.args and enable
        debugging if necessary.
        '''
        cli_args = self._cli_parser.parse_args().__dict__
        for (key, val) in cli_args.iteritems():
            self.args.setdefault(key, val)

        if self.args.get('debug'):
            boto.set_stream_logger(self.name())
        if self.args.get('debugger'):
            sys.excepthook = _requestbuilder_except_hook(
                    self.args.get('debugger', False),
                    self.args.get('debug', False))

        if '_filters' in self.args:
            self.params['Filter'] = _process_filters(cli_args.pop('_filters'))

    def send(self):
        '''
        Send a request to the server and return its response.  More precisely:

         1. Build a flattened dict of params suitable for submission as HTTP
            request parameters, based first upon the content of self.params,
            and second upon everything in self.args that routes to PARAMS.
         2. Send an HTTP request via self.connection with the HTTP verb given
            in self.verb using query parameters from the aforementioned
            flattened dict, headers based on self.headers, and POST data based
            on self.post_data.
         3. If the response's status code indicates success, parse the
            response's body with self.parse_http_response and return the
            result.
         4. If the response's status code does not indicate success, log an
            error and raise a ResponseError.
        '''
        params =      self.flatten_params(self.args,   PARAMS)
        params.update(self.flatten_params(self.params, _ALWAYS))
        if self.headers:
            boto.log.debug('Request headers: {0}'.format(self.headers))
        if params:
            boto.log.debug('Request params: {0}'.format(params))
        self.http_response = self.connection.make_request(self.name(),
                verb=self.verb, headers=self.headers, params=params,
                data=self.post_data, api_version=self.APIVersion)
        response_body = self.http_response.read()
        boto.log.debug(response_body)
        if 200 <= self.http_response.status < 300:
            return self.parse_http_response(response_body)
        else:
            boto.log.error('{0} {1}'.format(self.http_response.status,
                                            self.http_response.reason))
            boto.log.error(response_body)
            raise self.connection.ResponseError(self.http_response.status,
                                                self.http_response.reason,
                                                response_body)

    def parse_http_response(self, response_body):
        response = boto.jsonresponse.Element(list_marker=self.ListMarkers,
                                             item_marker=self.ItemMarkers)
        handler = boto.jsonresponse.XmlHandler(response, self)
        handler.parse(response_body)
        return response[response.keys()[0]]  # Strip off the root element

    def main(self):
        '''
        The main processing method for this type of request.  In this method,
        inheriting classes generally populate self.headers, self.params, and
        self.post_data with information gathered from self.args or elsewhere,
        call self.send, and return the response.
        '''
        pass

    def do_cli(self):
        '''
        The entry point for the command line.  This method parses command line
        arguments using the class's Args and Filters lists to populate
        self.args, obtains a response from the main method, then passes the
        result to print_result.
        '''
        try:
            self.process_cli_args()  # self.args is populated
            response = self.main()
            self.print_result(response)
        except self.ServiceClass.ResponseError as err:
            sys.exit('error ({code}) {msg}'.format(code=err.error_code,
                                                   msg=err.error_message))
        except MissingCredentialsError as err:
            sys.exit('error: unable to find credentials')
        except Exception as err:
            if self.args.get('debug'):
                raise
            if '--debug' in sys.argv or '-D' in sys.argv:
                # In case an error occurs during argument parsing
                raise
            sys.exit('error: {0}'.format(err))

    def __add_arg_to_cli_parser(self, arglike_obj, parser):
        if isinstance(arglike_obj, Arg):
            arg = parser.add_argument(*arglike_obj.pargs, **arglike_obj.kwargs)
            self._arg_routes.setdefault(arglike_obj.route, [])
            self._arg_routes[arglike_obj.route].append(arg.dest)
        elif isinstance(arglike_obj, MutuallyExclusiveArgList):
            exgroup = parser.add_mutually_exclusive_group(
                    required=arglike_obj.required)
            for group_arg in arglike_obj:
                self.__add_arg_to_cli_parser(group_arg, exgroup)
        else:
            raise TypeError('Unknown argument type ' +
                            arglike_obj.__class__.__name__)

    def __build_filter_help(self):
        """
        Return a pre-formatted help string for all of the filters defined in
        self.Filters.  The result is meant to be used as command line help
        output.
        """
        ## FIXME:  This code has a bug with triple-quoted strings that contain
        ##         embedded indentation.  textwrap.dedent doesn't seem to help.
        ##         Reproducer: 'whether the   volume will be deleted'
        max_len = 24
        col_len = max([len(filter_obj.name) for filter_obj in self.Filters
                       if len(filter_obj.name) < max_len]) - 1
        helplines = ['available filters:']
        for filter_obj in self.Filters:
            if filter_obj.help:
                if len(filter_obj.name) <= col_len:
                    # filter-name    Description of the filter that
                    #                continues on the next line
                    right_space = ' ' * (max_len - len(filter_obj.name) - 2)
                    wrapper = textwrap.TextWrapper(fix_sentence_endings=True,
                        initial_indent=('  ' + filter_obj.name + right_space),
                        subsequent_indent=(' ' * max_len))
                else:
                    # really-long-filter-name
                    #                Description that begins on the next line
                    helplines.append('  ' + filter_obj.name)
                    wrapper = textwrap.TextWrapper(fix_sentence_endings=True,
                            initial_indent=(   ' ' * max_len),
                            subsequent_indent=(' ' * max_len))
                helplines.extend(wrapper.wrap(filter_obj.help))
            else:
                helplines.append('  ' + filter_obj.name)
        return '\n'.join(helplines)

def _parse_filter(filter_str, filter_objs=None):
    """
    Given a "key=value" string given as a command line parameter, return a pair
    with the matching filter's dest member and the given value after converting
    it to the type expected by the filter.  If this is impossible, an
    ArgumentTypeError will result instead.
    """
    if '=' not in filter_str:
        msg = 'filter %s must have format "key=value"' % filter_str
        raise argparse.ArgumentTypeError(msg)
    (key, val_as_str) = filter_str.split('=', 1)
    # Find the appropriate filter object
    try:
        filter_obj = [obj for obj in (filter_objs or []) if obj.name == key][0]
        val = filter_obj.convert(val_as_str)
    except IndexError:
        raise argparse.ArgumentTypeError('unknown filter: %s' % key)
    return (filter_obj.dest, val)

def _process_filters(cli_filters):
    """
    Change filters from the [(key, value), ...] format given at the command
    line to [{'Name': key, 'Value': [value, ...]}, ...] format, which
    flattens to the form the server expects.
    """
    filter_args = {}
    # Compile [(key, value), ...] pairs into {key: [value, ...], ...}
    for (key, val) in cli_filters or {}:
        filter_args.setdefault(key, [])
        filter_args[key].append(val)
    # Build the flattenable [{'Name': key, 'Value': [value, ...]}, ...]
    filters = [{'Name': name, 'Value': values} for (name, values)
               in filter_args.iteritems()]
    return filters

def _requestbuilder_except_hook(debugger_enabled, debug_enabled):
    """
    Wrapper for the debugger-launching except hook
    """
    def excepthook(typ, value, tracebk):
        """
        If the debugger option is enabled, launch epdb (or pdb if epdb is
        unavailable) when an uncaught exception occurs.
        """
        if typ is bdb.BdbQuit:
            sys.exit(1)
        sys.excepthook = sys.__excepthook__

        if debugger_enabled and sys.stdout.isatty() and sys.stdin.isatty():
            if 'epdb' in sys.modules:
                epdb.post_mortem(tracebk, typ, value)
            else:
                pdb.post_mortem(tracebk)
        elif debug_enabled:
            traceback.print_tb(tracebk)
            sys.exit(1)
        else:
            print value
            sys.exit(1)
    return excepthook

_ALWAYS = '==ALWAYS=='
