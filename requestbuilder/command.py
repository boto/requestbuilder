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

import argparse
import bdb
import logging
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
from .util import aggregate_subclass_fields

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
     - DESCRIPTION:  a string describing the tool.  This becomes part of the
                     command line help string.
     - Args:         a list of Arg and/or MutuallyExclusiveArgGroup objects
                     are used to generate command line arguments.  Inheriting
                     classes needing to add command line arguments should
                     contain their own Args lists, which are *prepended* to
                     those of their parent classes.
    '''

    DESCRIPTION = ''
    ARGS = [Arg('-D', '--debug', action='store_true', route_to=None,
                help='show debugging output'),
            Arg('--debugger', action='store_true', route_to=None,
                help='enable interactive debugger on error')]

    VERSION = 'requestbuilder ' + __version__

    def __init__(self, _do_cli=False, **kwargs):
        self.args          = kwargs
        self.config        = None  # created by _process_configfile
        self.log           = None  # created by _configure_logging
        self._arg_routes   = {}
        self._cli_parser   = None  # created by _build_parser

        self._configure_logging()
        self._process_configfiles()
        if _do_cli:
            self._configure_global_logging()

        # We need to enforce arg constraints in one location to make this
        # framework equally useful for chained commands and those driven
        # directly from the command line.  Thus, we do most of the parsing/
        # validation work before __init__ returns as opposed to putting it
        # off until we hit CLI-specific code.
        #
        # Derived classes MUST call this method to ensure things stay sane.
        self.__do_cli = _do_cli
        self._post_init()

    def _post_init(self):
        self._build_parser()
        if self.__do_cli:
            # Distribute CLI args to the various places that need them
            self.process_cli_args()
        self.distribute_args()
        self.configure()

    @property
    def default_route(self):
        # This is a property so we can return something that references self.
        return None

    @property
    def config_files(self):
        # This list may need to be computed on the fly.
        return []

    def _configure_logging(self):
        self.log = logging.getLogger(self.name)
        if self.debug:
            self.log.setLevel(logging.DEBUG)

    def _process_configfiles(self):
        self.config = Config(self.config_files, log=self.log)
        # Now that we have a config file we should check to see if it wants
        # us to turn on debugging
        if self.__config_enables_debugging():
            self.log.setLevel(logging.DEBUG)

    def _configure_global_logging(self):
        if self.config.get_global_option('debug') in ('color', 'colour'):
            configure_root_logger(use_color=True)
        else:
            configure_root_logger()
        if self.args.get('debugger'):
            sys.excepthook = _debugger_except_hook(
                    self.args.get('debugger', False),
                    self.args.get('debug', False))

    def _build_parser(self):
        description = '\n\n'.join([textwrap.fill(textwrap.dedent(para))
                                   for para in self.DESCRIPTION.split('\n\n')])
        parser = argparse.ArgumentParser(description=description,
                formatter_class=argparse.RawDescriptionHelpFormatter)
        arg_objs = self.collect_arg_objs()
        self.preprocess_arg_objs(arg_objs)
        self.populate_parser(parser, arg_objs)
        parser.add_argument('--version', action='version',
                            version=self.VERSION)  # doesn't need routing
        self._cli_parser = parser

    def collect_arg_objs(self):
        return aggregate_subclass_fields(self.__class__, 'ARGS')

    def preprocess_arg_objs(self, arg_objs):
        pass

    def populate_parser(self, parser, arg_objs):
        for arg_obj in arg_objs:
            self.__add_arg_to_cli_parser(arg_obj, parser)

    def __add_arg_to_cli_parser(self, arglike_obj, parser):
        # Returns the args the parser was populated with
        if isinstance(arglike_obj, Arg):
            if arglike_obj.kwargs.get('dest') is argparse.SUPPRESS:
                # Treat it like it doesn't exist at all
                return []
            else:
                arg = parser.add_argument(*arglike_obj.pargs,
                                          **arglike_obj.kwargs)
                route = getattr(arglike_obj, 'route', self.default_route)
                self._arg_routes[arg.dest] = route
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

    def process_cli_args(self):
        cli_args = self._cli_parser.parse_args()
        # Everything goes in self.args.  distribute_args() also puts them
        # elsewhere later on in the process.
        self.args.update(vars(cli_args))

    def distribute_args(self):
        for key, val in self.args.iteritems():
            # If a location to route this to was supplied, put it there, too.
            route = self._arg_routes[key]
            if route is not None:
                if callable(route):
                    # If it's callable, call it to get the actual destination
                    # dict.  This is needed to allow Arg objects to refer to
                    # instance attributes from the context of the class.
                    route = route(self)
                # At this point we had better have a dict.
                route[key] = val

    def configure(self):
        # TODO:  Come up with something that can enforce arg constraints based
        # on the info we can get from self._cli_parser
        pass

    @classmethod
    def run(cls):
        try:
            cmd = cls(_do_cli=True)
        except Exception as err:
            print >> sys.stderr, 'error: {0}'.format(err)
            # Since we don't even have a config file to consult our options for
            # determining when debugging is on are limited to what we got at
            # the command line.
            if any(arg in sys.argv for arg in ('--debug', '-D', '--debugger')):
                raise
            sys.exit(1)
        try:
            result = cmd.main()
            cmd.print_result(result)
        except Exception as err:
            cmd.handle_cli_exception(err)

    @property
    def name(self):
        return self.__class__.__name__

    def print_result(self, data):
        pass

    def main(self):
        '''
        The main processing method.  main() is expected to do something with
        self.args and return a result.
        '''
        pass

    @property
    def debug(self):
        if self.__config_enables_debugging():
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

    def __config_enables_debugging(self):
        if self.config is None:
            return False
        if self.config.get_global_option('debug') in ('color', 'colour'):
            # It isn't boolean, but still counts as true.
            return True
        return self.config.get_global_option_bool('debug', False)


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
