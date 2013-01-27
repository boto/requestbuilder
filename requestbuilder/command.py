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
from .config import Config
from .logging import configure_root_logger

class BaseCommand(object):
    ## TODO:  Fix this docstring
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
     - DESCRIPTION:  a string describing the tool.  This becomes part of the
                     command line help string.
     - Args:         a list of Arg and/or MutuallyExclusiveArgGroup objects
                     are used to generate command line arguments.  Inheriting
                     classes needing to add command line arguments should
                     contain their own Args lists, which are *prepended* to
                     those of their parent classes.
    '''

    VERSION = 'requestbuilder ' + __version__

    DESCRIPTION = ''

    ARGS = [Arg('-D', '--debug', action='store_true', route_to=None,
                help='show debugging output'),
            Arg('--debugger', action='store_true', route_to=None,
                help='enable interactive debugger on error')]
    DefaultRoute = None
    ConfigFiles = ['/etc/requestbuilder.ini']

    def __init__(self, _do_cli=False, **kwargs):
        # Note to programmer:  when run() is initializing the first object it
        # can't catch exceptions that may result from accesses to self.config.
        # To deal with this, run() disables config file parsing during this
        # process to expose premature access to self.config during testing.
        self.args          = {}    # populated later
        self.log           = None  # created by _configure_logging
        self._allowed_args = None  # created by _build_parser
        self._arg_routes   = {}
        self._cli_parser   = None  # created by _build_parser
        self._config       = None

        self._configure_logging()

        # We need to enforce arg constraints in one location to make this
        # framework equally useful for chained commands and those driven
        # directly from the command line.  Thus, we do most of the parsing/
        # validation work in __init__ as opposed to putting it off until
        # we hit CLI-specific code.
        self._build_parser()

        # Come up with a list of args that the arg parser will allow
        for key, val in kwargs.iteritems():
            if key in self._allowed_args:
                self.args[key] = val
            else:
                raise TypeError('__init__() got an unexpected keyword '
                                'argument \'{0}\'; allowed arguments are {1}'
                                .format(key, ', '.join(self._allowed_args)))

        ## TODO:  AUTH PARAM PASSING (probably involves the service class)
        if _do_cli:
            self._process_cli_args()
        else:
            # TODO:  enforce arg constraints when not pulling from the CLI
            pass

    def _configure_logging(self):
        # Does not have access to self.config
        self.log = logging.getLogger(self.name)
        if self.debug:
            self.log.setLevel(logging.DEBUG)

    def _build_parser(self):
        # Does not have access to self.config
        description = '\n\n'.join([textwrap.fill(textwrap.dedent(para))
                                   for para in self.DESCRIPTION.split('\n\n')])
        parser = argparse.ArgumentParser(description=description,
                formatter_class=argparse.RawDescriptionHelpFormatter)
        self._allowed_args = self._populate_parser(parser)
        parser.add_argument('--version', action='version',
                            version=self.VERSION)  # doesn't need routing
        self._cli_parser = parser

    def _populate_parser(self, parser):
        # Returns the args the parser was populated with  <-- FIXME (the docs)
        # Does not have access to self.config
        args = []
        for arg_obj in self.aggregate_subclass_fields('ARGS'):
            args.extend(self.__add_arg_to_cli_parser(arg_obj, parser))
        return args

    def _process_cli_args(self):
        '''
        Process CLI args to fill in missing parts of self.args and enable
        debugging if necessary.
        '''
        # Does not have access to self.config
        cli_args = self._cli_parser.parse_args()
        for (key, val) in vars(cli_args).iteritems():
            self.args.setdefault(key, val)

    def __add_arg_to_cli_parser(self, arglike_obj, parser):
        # Returns the args the parser was populated with
        # Does not have access to self.config
        if isinstance(arglike_obj, Arg):
            if arglike_obj.kwargs.get('dest') is argparse.SUPPRESS:
                # Treat it like it doesn't exist at all
                return []
            else:
                arg = parser.add_argument(*arglike_obj.pargs,
                                          **arglike_obj.kwargs)
                route = getattr(arglike_obj, 'route', self.DefaultRoute)
                self._arg_routes.setdefault(route, [])
                self._arg_routes[route].append(arg.dest)
                return [arg]
        elif isinstance(arglike_obj, MutuallyExclusiveArgList):
            exgroup = parser.add_mutually_exclusive_group(
                    required=arglike_obj.required)
            args = []
            for group_arg in arglike_obj:
                args.extend(self.__add_arg_to_cli_parser(group_arg, exgroup))
            return args
        else:
            raise TypeError('Unknown argument type ' +
                            arglike_obj.__class__.__name__)

    @classmethod
    def run(cls):
        BaseCommand.__INHIBIT_CONFIG_PARSING = True
        ## TODO:  document:  command line entry point
        cmd = cls(_do_cli=True)
        BaseCommand.__INHIBIT_CONFIG_PARSING = False
        try:
            cmd.configure_global_logging()
            result = cmd.main()
            cmd.print_result(result)
        except Exception as err:
            cmd.handle_cli_exception(err)

    ## TODO:  backward compat; remove this
    do_cli = run

    def configure_global_logging(self):
        if self.config.get_global_option('debug') in ('color', 'colour'):
            configure_root_logger(use_color=True)
        else:
            configure_root_logger()
        if self.args.get('debugger'):
            sys.excepthook = _debugger_except_hook(
                    self.args.get('debugger', False),
                    self.args.get('debug', False))

    @property
    def config(self):
        if not self._config:
            if getattr(BaseCommand, '__INHIBIT_CONFIG_PARSING', False):
                raise AssertionError(
                        'config files may not be parsed during __init__')
            self._config = Config(self.ConfigFiles, log=self.log)
            # Now that we have a config file we should check to see if it wants
            # us to turn on debugging
            if self.__config_enables_debugging():
                self.log.setLevel(logging.DEBUG)
        return self._config

    @property
    def name(self):
        return self.__class__.__name__

    def print_result(self, data):
        '''
        Format data for printing at the command line and print it to standard
        out.  The default formatter attempts to print JSON or something else
        reasonable.  Override this method if you want specific formatting.
        '''
        ## TODO:  make this a noop
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

    def main(self):
        '''
        The main processing method.  main() is expected to do something with
        self.args and return a result.
        '''
        pass

    @property
    def debug(self):
        if self._config and self.__config_enables_debugging():
            return True
        if self.args.get('debug') or self.args.get('debugger'):
            return True
        if any(arg in sys.argv for arg in ('--debug', '-D', '--debugger')):
            # In case an error occurs during argument parsing
            return True
        return False

    def handle_cli_exception(self, err):
        print >> sys.stderr, 'error: {0}'.format(err)
        if self.debug:
            raise
        sys.exit(1)

    @classmethod
    def aggregate_subclass_fields(cls, field_name):
        values = []
        for m_class in cls.mro():
            if field_name in vars(m_class):
                values.extend(getattr(m_class, field_name))
        return values

    def __config_enables_debugging(self):
        if self._config.get_global_option('debug') in ('color', 'colour'):
            # It isn't boolean, but still counts as true.
            return True
        return self._config.get_global_option_bool('debug', False)


def _debugger_except_hook(debugger_enabled, debug_enabled):
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
