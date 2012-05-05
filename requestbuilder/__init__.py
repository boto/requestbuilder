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

__version__ = '0.0'

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
            self.route  = kwargs.pop('route_to')
        self.pargs  = pargs
        self.kwargs = kwargs

    def __eq__(self, other):
        if isinstance(other, Arg):
            return sorted(self.pargs) == sorted(other.pargs)
        return False


class MutuallyExclusiveArgList(list):
    '''
    Pass Args as positional arguments to __init__ to create a set of
    command line arguments that are mutually exclusive.  If the first
    argument passed to __init__ is True then the user must specify
    exactly one of them.

    Example:  MutuallyExclusiveArgList(Arg('--one'), Arg('--two'))
    '''

    def __init__(self, *args):
        if len(args) > 0 and isinstance(args[0], bool):
            self.required = args[0]
            list.__init__(self, args[1:])
        else:
            self.required = False
            list.__init__(self, args)


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
            msg = 'filter {0} must have format "NAME=VALUE"'.format(argval)
            raise argparse.ArgumentTypeError(msg)
        (name, value_str) = argval.split('=', 1)
        try:
            value = self.type(value_str)
        except ValueError:
            msg = 'filter {0} must have type {1}'.format(
                    value_str, self.type.__name__)
            raise argparse.ArgumentTypeError(msg)
        if self.choices and value not in self.choices:
            msg = 'filter value {0} must match one of {1}'.format(
                    value, ', '.join([str(choice) for choice in self.choices]))
            raise argparse.ArgumentTypeError(msg)
        return (name, value)


class GenericTagFilter(Filter):
    '''
    A filter that accepts "tag:<key>=<value>" values
    '''
    def matches_argval(self, argval):
        return argval.startswith('tag:') and '=' in argval


########## SINGLETONS ##########
# Indicates a parameter that should be sent to the server without a value
EMPTY = type('EMPTY', (), {'__repr__': lambda self: "''"})()

# Constants (enums?) used for arg routing
CONNECTION = type('CONNECTION', (), {'__repr__': lambda self: 'CONNECTION'})()
PARAMS     = type('PARAMS',     (), {'__repr__': lambda self: 'PARAMS'})()

# Common args for query authentication
STD_AUTH_ARGS = [
        Arg('-I', '--access-key-id', dest='aws_access_key_id',
            metavar='KEY_ID', route_to=CONNECTION),
        Arg('-S', '--secret-key', dest='aws_secret_access_key', metavar='KEY',
            route_to=CONNECTION)]
