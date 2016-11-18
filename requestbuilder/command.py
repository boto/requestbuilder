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

from __future__ import absolute_import, print_function

import argparse
import bdb
import logging
import os.path
import re
import signal
import sys
import textwrap
import traceback
import warnings
try:
    import epdb
except ImportError:
    import pdb

import six

from requestbuilder import Arg, MutuallyExclusiveArgList
from requestbuilder.config import ConfigData, ConfigView
from requestbuilder.exceptions import ArgumentError
from requestbuilder.logging import configure_root_logger
from requestbuilder.suite import RequestBuilder
from requestbuilder.util import add_default_routes, aggregate_subclass_fields


class BaseCommand(object):
    """
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
     - DESCRIPTION:  a string that describes the tool, which is re-wrapped and
                     used as part of the command line help string.  If it is
                     not supplied, the class's doc string, if any, will be
                     used instead.
     - USAGE:        a usage message for the command line help string.  If this
                     is None, one will be generated automatically.
     - ARGS:         a list of Arg and/or MutuallyExclusiveArgGroup objects
                     are used to generate command line arguments.  Inheriting
                     classes needing to add command line arguments should
                     contain their own ARGS lists, which are combined with
                     those of their parent classes.
    """

    DESCRIPTION = ''
    USAGE = None
    ARGS = []
    DEFAULT_ROUTES = ()
    SUITE = RequestBuilder
    __CONFIGURED_GLOBAL_STATE = False

    def __init__(self, config=None, loglevel=None, _do_cli=False, **kwargs):
        self.args = kwargs
        self.config = config  # created by _process_configfiles if None
        self.log = None  # created by _configure_logging
        self.suite = self.SUITE()
        self._arg_routes = {}  # arg name -> tuple of callables or dicts
        self._cli_parser = None  # created by _build_parser
        self.__debug = False
        self.__do_cli = _do_cli

        self._configure_logging(loglevel)
        self._process_configfiles()
        if self.__do_cli and not BaseCommand.__CONFIGURED_GLOBAL_STATE:
            self._configure_global_logging()
            BaseCommand.__CONFIGURED_GLOBAL_STATE = True

        # We need to enforce arg constraints in one location to make this
        # framework equally useful for chained commands and those driven
        # directly from the command line.  Thus, we do most of the parsing/
        # validation work before __init__ returns as opposed to putting it
        # off until we hit CLI-specific code.
        #
        # Derived classes MUST call this method to ensure things stay sane.
        self._build_parser()
        if self.__do_cli:
            # Distribute CLI args to the various places that need them
            self.process_cli_args()
        # This will raise an exception if kwargs contains anything unexpected.
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

    @classmethod
    def from_other(cls, other, **kwargs):
        kwargs.setdefault('loglevel', other.log.level)
        new = cls(config=other.config, **kwargs)
        # That already calls configure
        return new

    def _configure_logging(self, loglevel):
        self.log = logging.getLogger(self.name)
        if loglevel is not None:
            self.log.setLevel(loglevel)
        elif self.debug:
            self.log.setLevel(logging.DEBUG)

    def _process_configfiles(self):
        if self.config is None:
            config_files = self.suite.list_config_files()
            config_data = ConfigData(config_files)
            self.config = ConfigView(config_data)
        # Now that we have a config file we should check to see if it wants
        # us to turn on debugging
        if self.debug:
            self.log.setLevel(logging.DEBUG)
            self.config.log.setLevel(logging.DEBUG)

    def _configure_global_logging(self):
        if self.config.get_global_option('debug') in ('color', 'colour'):
            configure_root_logger(use_color=True)
        else:
            configure_root_logger()

    def _build_parser(self):
        description = _rewrap_description(
            self.DESCRIPTION or self.__doc__ or '')
        parser = argparse.ArgumentParser(
            description=description, usage=self.USAGE, add_help=False,
            formatter_class=argparse.RawDescriptionHelpFormatter)
        arg_objs = self.collect_arg_objs()
        self._populate_parser(parser, arg_objs)
        # Low-level basic args that affect the core of the framework
        # These don't actually show up once CLI args finish processing.
        parser.add_argument('--debug', action='store_true', dest='_debug',
                            default=argparse.SUPPRESS,
                            help='show debugging output')
        parser.add_argument('--debugger', action='store_true',
                            dest='_debugger', default=argparse.SUPPRESS,
                            help='launch interactive debugger on error')
        parser.add_argument('--version', action='version',
                            version=self.suite.format_version(),
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
        arg_objs = aggregate_subclass_fields(self.__class__, 'ARGS')
        add_default_routes(arg_objs, self.DEFAULT_ROUTES)
        return arg_objs

    def _populate_parser(self, parser, arg_objs):
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
                if arglike_obj.routes is None:
                    self._arg_routes[arg.dest] = (None,)
                else:
                    self._arg_routes[arg.dest] = arglike_obj.routes
                return [arg]
        elif isinstance(arglike_obj, MutuallyExclusiveArgList):
            exgroup = parser.add_mutually_exclusive_group(
                required=arglike_obj.is_required)
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
            signal.signal(signal.SIGUSR1, _debugger_usr1_handler)
        # Everything goes in self.args.  distribute_args() also puts them
        # elsewhere later on in the process.
        self.args.update(cli_args)
        redacted = type('REDACTED', (),
                        {'__repr__': lambda self: '<redacted>'})()
        for key in list(cli_args.keys()):
            if (('password' in key.lower() or 'secret' in key.lower()) and
                    cli_args[key] is not None):
                # This makes it slightly more obvious that this is redacted by
                # the framework and not just a string by removing quotes.
                cli_args[key] = redacted
        self.log.debug('parsed arguments from CLI: %s', str(cli_args))

    def distribute_args(self):
        for key, val in six.iteritems(self.args):
            # If a location to route this to was supplied, put it there, too.
            if key not in self._arg_routes:
                raise TypeError('got unrecognized arg: "{0}"'.format(key))
            routes = self._arg_routes[key]
            for route in routes:
                if route is not None:
                    if callable(route):
                        # If it's callable, call it to get the actual
                        # destination dict.  This is needed to allow Arg
                        # objects to refer to instance attributes from the
                        # context of the class.
                        route = route(self)
                    # At this point we had better have a dict.
                    route[key] = val

    def configure(self):
        # TODO:  rename this to setup
        pass

    @classmethod
    def run(cls):
        try:
            cmd = cls(_do_cli=True)
        except Exception as err:
            msg_prefix = '{0}: error:'.format(os.path.basename(sys.argv[0]))
            if isinstance(err, EnvironmentError):
                # These don't have regular 'args' attributes, and they occur
                # frequently enough they we handle them specially.
                err_bits = [msg_prefix]
                if getattr(err, 'strerror', None):
                    err_bits.append(err.strerror)
                if getattr(err, 'filename', None):
                    err_bits[-1] += ':'
                    err_bits.append(err.filename)
                print(' '.join(err_bits), file=sys.stderr)
            else:
                if len(err.args) > 0 and err.args[0]:
                    print(msg_prefix, err.args[0], file=sys.stderr)
                else:
                    print(msg_prefix, str(err), file=sys.stderr)
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
            # Note that, unlike __init__, we get to use self.debug instead
            # of self.__debug
            self._cli_parser.error(str(err))
        if isinstance(err, EnvironmentError):
            # These don't have regular 'args' attributes, and they occur
            # frequently enough they we handle them specially.
            err_bits = [msg_prefix]
            if getattr(err, 'strerror', None):
                err_bits.append(err.strerror)
            if getattr(err, 'filename', None):
                err_bits[-1] += ':'
                err_bits.append(err.filename)
            print(' '.join(err_bits), file=sys.stderr)
        else:
            if len(err.args) > 0 and err.args[0]:
                print(msg_prefix, err.args[0], file=sys.stderr)
            else:
                print(msg_prefix, str(err), file=sys.stderr)
        if self.debug:
            raise
        sys.exit(1)

    def __config_enables_debugging(self):
        if self.config is None:
            return False
        if self.config.get_global_option('debug') in ('color', 'colour'):
            return True
        if self.config.convert_to_bool(self.config.get_global_option('debug')):
            return True
        return False


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


def _debugger_usr1_handler(_, frame):
    """
    Show a traceback and local variables when sent SIGUSR1.  Note that
    this could cause exceptions due to interrupted system calls.
    """
    frame_dict = {'_frame': frame}
    frame_dict.update(frame.f_globals)
    frame_dict.update(frame.f_locals)
    print(''.join(traceback.format_stack(frame)), file=sys.stderr)


def _rewrap_description(text, width=70):
    """
    Split lines into paragraphs based on blank lines and changes in
    indentation level, rewrap the text in each of those paragraphs, and
    yield each of those paragraphs.  In paragraphs that start with
    common shell prompt characters (#, $, and %) or bullets (* and -)
    followed by whitespace, those characters do not count against the
    paragraph's indentation level.
    """
    # Match shell prompts and bullets
    bullets = {r'^(\s*)\#(\s+)': r'\1 \2',
               r'^(\s*)\$(\s+)': r'\1 \2',
               r'^(\s*)\%(\s+)': r'\1 \2',
               r'^(\s*)\*(\s+)': r'\1 \2',
               r'^(\s*)\-(\s+)': r'\1 \2'}

    def measure_margin(line):
        if not line.strip():
            return -1
        for pattern, sub in bullets.iteritems():
            line = re.sub(pattern, sub, line)
        return len(line) - len(line.lstrip())

    def find_bullet_pattern(line):
        for pattern in bullets:
            if line and re.match(pattern, line):
                return pattern

    def reformat_paragraph(lines, width=70):
        if not lines:
            return ''
        margin = measure_margin(lines[0])
        pattern = find_bullet_pattern(lines[0])
        if pattern:
            firstline_margin = len(lines[0]) - len(lines[0].lstrip())
            bullet_text = lines[0][firstline_margin:margin]
            lines[0] = re.sub(pattern, bullets[pattern], lines[0], 1)
        rewrapped = textwrap.wrap('\n'.join(line.strip() for line in lines),
                                  width=(width - margin))
        if pattern:
            combined = ([' ' * firstline_margin + bullet_text + rewrapped[0]] +
                        [' ' * margin + line for line in rewrapped[1:]])
        else:
            combined = [' ' * margin + line for line in rewrapped]

        combined = '\n'.join(' ' * margin + line for line in rewrapped)
        if pattern:
            combined = ' ' * firstline_margin + bullet_text + combined[margin:]
        return combined

    text %= dict(prog=os.path.basename(sys.argv[0]))
    in_lines = textwrap.dedent(text.rstrip().lstrip('\n')).splitlines()
    paragraphs = []
    current_lines = []
    current_margin = 0
    for line in in_lines:
        if not line.strip():
            paragraphs.append(reformat_paragraph(current_lines,
                                                 width=width))
            del current_lines[:]
            current_lines.append('')
            current_margin = -1
        else:
            pattern = find_bullet_pattern(line)
            margin = measure_margin(line)
            if pattern:
                # Bullets always begin new paragraphs
                paragraphs.append(reformat_paragraph(current_lines,
                                                     width=width))
                del current_lines[:]
            elif margin != current_margin:
                # Different margin -> start new paragraph
                paragraphs.append(reformat_paragraph(current_lines,
                                                     width=width))
                del current_lines[:]
            current_margin = margin
            current_lines.append(line)
    if current_lines:
        paragraphs.append(reformat_paragraph(current_lines, width=width))

    # Combine adjacent empty paragraphs
    for i in xrange(len(paragraphs) - 1, 0, -1):
        if paragraphs[i] == paragraphs[i - 1] == '':
            del paragraphs[i]
    return '\n'.join(paragraphs)
