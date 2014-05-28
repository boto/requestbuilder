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

import argparse
import operator
import os.path
import subprocess


__version__ = '0.2.1'

if '__file__' in globals():
    # Check if this is a git repo; maybe we can get more precise version info
    try:
        repo_path = os.path.join(os.path.dirname(__file__), '..')
        git = subprocess.Popen(['git', 'describe'], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               env={'GIT_DIR': os.path.join(repo_path, '.git')})
        git.wait()
        git.stderr.read()
        if git.returncode == 0:
            __version__ = git.stdout.read().strip().lstrip('v')
            if type(__version__).__name__ == 'bytes':
                __version__ = __version__.decode()
    except:
        # Not really a bad thing; we'll just use what we had
        pass


########## SINGLETONS ##########
# Indicates a parameter that should be sent to the server without a value.
# Contrast this with empty strings, with are omitted from requests entirely.
EMPTY = type('EMPTY', (), {'__repr__': lambda self: "''",
                           '__str__':  lambda self: ''})()

# Getters used for arg routing
PARAMS  = operator.attrgetter('params')
SESSION = operator.attrgetter('service.session_args')


########## ARG CLASSES ##########
class Arg(object):
    '''
    A command line argument.  Positional and keyword arguments to __init__
    are the same as those to argparse.ArgumentParser.add_argument.

    The value specified by the 'dest' argument (or the one inferred if
    none is specified) is used as the name of the parameter to server
    queries unless send=False is also supplied.
    '''

    def __init__(self, *pargs, **kwargs):
        if 'route_to' in kwargs:
            if isinstance(kwargs['route_to'], (list, set, tuple)):
                self.routes = tuple(kwargs.pop('route_to'))
            else:
                self.routes = (kwargs.pop('route_to'),)
        else:
            self.routes = None
        self.pargs = pargs
        self.kwargs = kwargs

    def __eq__(self, other):
        if isinstance(other, Arg):
            return sorted(self.pargs) == sorted(other.pargs)
        return False


class MutuallyExclusiveArgList(list):
    '''
    Pass Args as positional arguments to __init__ to create a set of
    command line arguments that are mutually exclusive.  If you also
    call the required() method then the user must specify exactly one
    of them.  The recommended way to do that is via chaining it from
    __init__.

    Examples:

        MutuallyExclusiveArgList(Arg('--spam'), Arg('--eggs'))

        MutuallyExclusiveArgList(Arg('--spam'),
                                 Arg('--eggs')).required()
    '''

    def __init__(self, *args):
        if len(args) > 0 and isinstance(args[0], bool):
            self.is_required = args[0]
            list.__init__(self, args[1:])
        else:
            self.is_required = False
            list.__init__(self, args)

    def required(self):
        self.is_required = True
        return self


class Filter(object):
    '''
    An AWS API filter.  For APIs that support filtering by name/value
    pairs, adding a Filter to a request's list of filters will allow a
    user to send an output filter to the server with '--filter name=value'
    at the command line.

    The value specified by the 'dest' argument (or the 'name' argument,
    if none is given) is used as the name of a filter in queries.
    '''
    def __init__(self, name, type=str, choices=None, help=None):
        self.name    = name
        self.type    = type
        self.choices = choices
        self.help    = help

    def matches_argval(self, argval):
        return argval.startswith(self.name + '=')

    def convert(self, argval):
        '''
        Given an argument to --filter of the form "<name>=<value>", convert
        the value to the appropriate type by calling self.type on it, then
        return a (name, converted_value) tuple.  If the value's type conversion
        doesn't work then an ArgumentTypeError will result.  If the conversion
        succeeds but does not appear in self.choices when it exists, an
        ArgumentTypeError will result as well.
        '''
        if '=' not in argval:
            msg = "filter '{0}' must have format 'NAME=VALUE'".format(argval)
            raise argparse.ArgumentTypeError(msg)
        (name, value_str) = argval.split('=', 1)
        try:
            value = self.type(value_str)
        except ValueError:
            msg = "{0} filter value '{1}' must have type {2}".format(
                    name, value_str, self.type.__name__)
            raise argparse.ArgumentTypeError(msg)
        if self.choices and value not in self.choices:
            msg = "{0} filter value '{1}' must match one of {2}".format(
                    name, value,
                    ', '.join([str(choice) for choice in self.choices]))
            raise argparse.ArgumentTypeError(msg)
        if value == '':
            value = EMPTY
        return (name, value)


class GenericTagFilter(Filter):
    '''
    A filter that accepts "tag:<key>=<value>" values
    '''
    def matches_argval(self, argval):
        return argval.startswith('tag:') and '=' in argval
