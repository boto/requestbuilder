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

import argparse
import bdb
from functools import partial
import json
import logging
import pprint
import sys
import textwrap
import traceback

try:
    import epdb
except ImportError:
    import pdb

from . import __version__, Arg, MutuallyExclusiveArgList
from .logging import configure_root_logger

class InheritableCommandClass(type):
    '''
    Classes of this type allow one to specify 'Args' and 'Filters' lists as
    attributes of classes and have them be appended to their superclasses'
    rather than clobbering them.
    '''
    def __new__(mcs, name, bases, attrs):
        for attrname in ('Args', 'Filters'):
            if attrname in attrs:
                for base in bases:
                    for attr in getattr(base, attrname, []):
                        if attr not in attrs[attrname]:
                            attrs[attrname].append(attr)
        return type.__new__(mcs, name, bases, attrs)

class BaseCommand(object):
    '''
    The basis for a command line tool.  To invoke this as a command line tool,
    call the do_cli() method on an instance of the class; arguments will be
    parsed from the command line.  To invoke this in another context, pass
    keyword args to __init__() with names that match those stored by the
    argument parser and then call main().

    Important methods in this class include:
     - do_cli:       command line entry point
     - main:         processing
     - print_result: format data from the main method and print it to stdout

    To be useful a tool should inherit from this class and implement the main()
    and print_result() methods.  The do_cli() method functions as the entry
    point for the command line, populating self.args from the command line and
    then calling main() and print_result() in sequence.  Other tools may
    instead supply arguments via __init__() and then call main() alone.

    Important members of this class include:
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

    __metaclass__ = InheritableCommandClass
    Version = 'requestbuilder ' + __version__

    Description = ''

    Args = [Arg('-D', '--debug', action='store_true', route_to=None,
                help='show debugging output'),
            Arg('--debugger', action='store_true', route_to=None,
                help='enable interactive debugger on error')]
    Filters = []
    DefaultRoute = None

    def __init__(self, **kwargs):
        # Arguments corresponding to those in self.Args.  This may be used in
        # lieu of (and will take priority over) arguments given at the CLI.
        self.args = kwargs

        self._arg_routes = {}
        self._cli_parser = None

        self._parse_arg_lists()

        self._configure_logging()

    def _configure_logging(self):
        self.log = logging.getLogger(self.name)
        if self.debug:
            self.log.setLevel(logging.DEBUG)

    @property
    def name(self):
        return self.__class__.__name__

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

    def _parse_arg_lists(self):
        '''
        Use self.Args and self.Filters to build a command line argument parser
        that is stored to self._cli_parser and to populate the argument routing
        table.
        '''
        description = '\n\n'.join([textwrap.fill(textwrap.dedent(para))
                                   for para in self.Description.split('\n\n')])
        self._cli_parser = argparse.ArgumentParser(description=description,
                formatter_class=argparse.RawDescriptionHelpFormatter)
        for arg_obj in self.Args:
            self.__add_arg_to_cli_parser(arg_obj, self._cli_parser)
        if self.Filters:
            self._cli_parser.add_argument('--filter', metavar='NAME=VALUE',
                    action='append', dest='_filters',
                    help='restrict results to resources that meet criteria',
                    type=partial(_parse_filter, filter_objs=self.Filters))
            self._arg_routes.setdefault(None, [])
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

        if self.args.get('debugger'):
            sys.excepthook = _requestbuilder_except_hook(
                    self.args.get('debugger', False),
                    self.args.get('debug', False))

        if '_filters' in self.args:
            self.args['Filter'] = _process_filters(cli_args.pop('_filters'))
            self._arg_routes.setdefault(self.DefaultRoute, [])
            self._arg_routes[self.DefaultRoute].append('Filter')

    def main(self):
        '''
        The main processing method.  main() is expected to do something with
        self.args and return a result.
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
            configure_root_logger()
            self.process_cli_args()  # self.args is populated
            response = self.main()
            self.print_result(response)
        except Exception as err:
            self._handle_cli_exception(err)

    @property
    def debug(self):
        if self.args.get('debug') or self.args.get('debugger'):
            return True
        if any(arg in sys.argv for arg in ('--debug', '-D', '--debugger')):
            # In case an error occurs during argument parsing
            return True
        return False

    def _handle_cli_exception(self, err):
        print >> sys.stderr, 'error: {0}'.format(err)
        if self.debug:
            raise
        sys.exit(1)

    def __add_arg_to_cli_parser(self, arglike_obj, parser):
        if isinstance(arglike_obj, Arg):
            if arglike_obj.kwargs.get('dest') is not argparse.SUPPRESS:
                arg = parser.add_argument(*arglike_obj.pargs,
                                          **arglike_obj.kwargs)
                route = getattr(arglike_obj, 'route', self.DefaultRoute)
                self._arg_routes.setdefault(route, [])
                self._arg_routes[route].append(arg.dest)
        elif isinstance(arglike_obj, MutuallyExclusiveArgList):
            exgroup = parser.add_mutually_exclusive_group(
                    required=arglike_obj.required)
            for group_arg in arglike_obj:
                self.__add_arg_to_cli_parser(group_arg, exgroup)
        else:
            raise TypeError('Unknown argument type ' +
                            arglike_obj.__class__.__name__)

    def __build_filter_help(self):
        '''
        Return a pre-formatted help string for all of the filters defined in
        self.Filters.  The result is meant to be used as command line help
        output.
        '''
        if '-h' not in sys.argv and '--help' not in sys.argv:
            # Performance optimization
            return ''

        ## FIXME:  This code has a bug with triple-quoted strings that contain
        ##         embedded indentation.  textwrap.dedent doesn't seem to help.
        ##         Reproducer: 'whether the   volume will be deleted'
        max_len = 24
        col_len = max([len(filter_obj.name) for filter_obj in self.Filters
                       if len(filter_obj.name) < max_len]) - 1
        helplines = ['available filter names:']
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

def _requestbuilder_except_hook(debugger_enabled, debug_enabled):
    '''
    Wrapper for the debugger-launching except hook
    '''
    def excepthook(type_, value, tracebk):
        '''
        If the debugger option is enabled, launch epdb (or pdb if epdb is
        unavailable) when an uncaught exception occurs.
        '''
        if type_ is bdb.BdbQuit:
            sys.exit(1)
        sys.excepthook = sys.__excepthook__

        if debugger_enabled and sys.stdout.isatty() and sys.stdin.isatty():
            if 'epdb' in sys.modules:
                epdb.post_mortem(tracebk, type_, value)
            else:
                pdb.post_mortem(tracebk)
        elif debug_enabled:
            traceback.print_tb(tracebk)
            sys.exit(1)
        else:
            print value
            sys.exit(1)
    return excepthook
