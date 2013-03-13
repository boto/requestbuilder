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
import os.path
import sys
import textwrap
import traceback

try:
    import epdb
except ImportError:
    import pdb

from . import Arg, MutuallyExclusiveArgList
from .config import Config
from .exceptions import ArgumentError
from .logging import configure_root_logger
from .suite import RequestBuilder
from .util import aggregate_subclass_fields

class BaseCommand(object):
    '''
    The basis for a command line tool.  To invoke this as a command line tool,
    call the run() method on the class.  Arguments will be parsed from the
    command line.  To invoke this in another context, such as from inside
    another command, pass keyword arguments to __init__() with names that match
    those stored by the argument parser and then call main() to retrieve a
    result.

    The general workflow of a command involves two methods:  main(), which
    inspects the arguments stored in self.args, does something, and returns a
    result; and print_result(), which takes the output of main() and prints it
    to stdout.  By default, both of these methods do nothing.  It is up to you
    to implement them to do what the tool is designed to do.

    Important members of this class include:
     - DESCRIPTION:  a string that describes the tool.  This becomes part of
                     the command line help string.
     - USAGE:        a usage message for the command line help string.  If this
                     is None, one will be generated automatically.
     - ARGS:         a list of Arg and/or MutuallyExclusiveArgGroup objects
                     are used to generate command line arguments.  Inheriting
                     classes needing to add command line arguments should
                     contain their own ARGS lists, which are combined with
                     those of their parent classes.
    '''

    DESCRIPTION = ''
    USAGE = None
    ARGS = []
    SUITE = RequestBuilder

    def __init__(self, _do_cli=False, **kwargs):
        self.args          = kwargs
        self.config        = None  # created by _process_configfile
        self.log           = None  # created by _configure_logging
        self.suite         = self.SUITE()
        self._arg_routes   = {}
        self._cli_parser   = None  # created by _build_parser
        self.__debug       = False

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
        try:
            self.configure()
        except ArgumentError as err:
            if self.__do_cli and not self.__debug:
                # This is the only context in which we have a parser object,
                # so if we don't handle this here and now the caller will have
                # to handle it without one, which means no usage info for the
                # user.
                #
                # This is contingent on self.__debug and not self.debug because
                # run(), having no idea whether the config enables debugging or
                # not, is going to terminate the program anyway regardless of
                # that.
                self._cli_parser.error(str(err))
            else:
                raise

    @property
    def default_route(self):
        # This is a property so we can return something that references self.
        return None

    def _configure_logging(self):
        self.log = logging.getLogger(self.name)
        if self.debug:
            self.log.setLevel(logging.DEBUG)

    def _process_configfiles(self):
        config_files = self.suite.list_config_files()
        self.config = Config(config_files, loglevel=self.log.level)
        # Now that we have a config file we should check to see if it wants
        # us to turn on debugging
        if self.__config_enables_debugging():
            self.log.setLevel(logging.DEBUG)

    def _configure_global_logging(self):
        if self.config.get_global_option('debug') in ('color', 'colour'):
            configure_root_logger(use_color=True)
        else:
            configure_root_logger()

    def _build_parser(self):
        description = '\n\n'.join([textwrap.fill(textwrap.dedent(para))
                                   for para in self.DESCRIPTION.split('\n\n')])
        parser = argparse.ArgumentParser(description=description,
                formatter_class=argparse.RawDescriptionHelpFormatter,
                usage=self.USAGE, add_help=False)
        arg_objs = self.collect_arg_objs()
        self.preprocess_arg_objs(arg_objs)
        self.populate_parser(parser, arg_objs)
        # Low-level basic args that affect the core of the framework
        # These don't actually show up once CLI args finish processing.
        parser.add_argument('--debug', action='store_true', dest='_debug',
                            default=argparse.SUPPRESS,
                            help='show debugging output')
        parser.add_argument('--debugger', action='store_true', dest='_debugger',
                            default=argparse.SUPPRESS,
                            help='launch interactive debugger on error')
        parser.add_argument('--version', action='store_true', dest='_version',
                            default=argparse.SUPPRESS,
                            help="show the program's version and exit")
        if any('-h' in arg_obj.pargs for arg_obj in arg_objs
               if isinstance(arg_obj, Arg)):
            parser.add_argument('--help', action='help',
                                default=argparse.SUPPRESS,
                                help='show this help message and exit')
        else:
            parser.add_argument('-h', '--help', action='help',
                                default=argparse.SUPPRESS,
                                help='show this help message and exit')
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
        elif isinstance(arglike_obj, list) or isinstance(arglike_obj, tuple):
            args = []
            for group_arg in arglike_obj:
                args.extend(self.__add_arg_to_cli_parser(group_arg, parser))
            return args
        else:
            raise TypeError('Unknown argument type ' +
                            arglike_obj.__class__.__name__)

    def process_cli_args(self):
        cli_args = vars(self._cli_parser.parse_args())
        if cli_args.pop('_debug', False):
            self.__debug = True
        if cli_args.pop('_debugger', False):
            self.__debug = True
            sys.excepthook = _debugger_except_hook
        if cli_args.get('_version', False):
            self.suite.print_version_and_exit()
        # Everything goes in self.args.  distribute_args() also puts them
        # elsewhere later on in the process.
        self.args.update(cli_args)
        for key in list(cli_args.keys()):
            if (('password' in key.lower() or 'secret' in key.lower()) and
                cli_args[key] is not None):
                # This makes it slightly more obvious that this is redacted by
                # the framework and not just a string by removing quotes.
                cli_args[key] = type('REDACTED', (),
                    {'__repr__': lambda self: '<redacted>'})()
        self.log.debug('parsed arguments: ' + str(cli_args))

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
            msg_prefix = '{0}: error:'.format(os.path.basename(sys.argv[0]))
            if isinstance(err, EnvironmentError):
                # These don't have regular 'message' attributes, and they occur
                # frequently enough they we handle them specially.
                if hasattr(err, 'filename'):
                    print >> sys.stderr, msg_prefix, err.strerror + ':', \
                        err.filename
                else:
                    print >> sys.stderr, msg_prefix, err.strerror
            else:
                print >> sys.stderr, msg_prefix, err.message or str(err)
            # Since we don't even have a config file to consult our options for
            # determining when debugging is on are limited to what we got at
            # the command line.
            if any(arg in sys.argv for arg in ('--debug', '--debugger')):
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

    def main(self):
        '''
        The main processing method.  main() is expected to do something with
        self.args and return a result.
        '''
        pass

    def print_result(self, data):
        '''
        Take a result produced by main() and print it to stdout.
        '''
        pass

    @property
    def debug(self):
        if self.__config_enables_debugging():
            return True
        if self.__debug:
            return True
        if any(arg in sys.argv for arg in ('--debug', '--debugger')):
            # In case an error occurs during argument parsing
            return True
        return False

    def handle_cli_exception(self, err):
        msg_prefix = '{0}: error:'.format(os.path.basename(sys.argv[0]))
        if isinstance(err, ArgumentError) and self.__do_cli and not self.debug:
            # Note that, unlike _post_init, we get to use self.debug instead
            # of self.__debug
            self._cli_parser.error(str(err))
        if isinstance(err, EnvironmentError):
            # These don't have regular 'message' attributes, and they occur
            # frequently enough they we handle them specially.
            if hasattr(err, 'filename'):
                print >> sys.stderr, msg_prefix, err.strerror + ':', \
                    err.filename
            else:
                print >> sys.stderr, msg_prefix, err.strerror
        else:
            print >> sys.stderr, msg_prefix, err.message or str(err)
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


def _debugger_except_hook(type_, value, tracebk):
    '''
    Launch epdb (or pdb if epdb is unavailable) when an uncaught exception
    occurs.
    '''
    if type_ is bdb.BdbQuit:
        sys.exit(1)
    sys.excepthook = sys.__excepthook__

    if sys.stdout.isatty() and sys.stdin.isatty():
        if 'epdb' in sys.modules:
            epdb.post_mortem(tracebk, type_, value)
        else:
            pdb.post_mortem(tracebk)
    else:
        traceback.print_tb(tracebk)
        sys.exit(1)
