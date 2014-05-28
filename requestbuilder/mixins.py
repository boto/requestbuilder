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
import math
import os
import signal
import sys

try:
    import progressbar
except ImportError:
    pass

from requestbuilder import Arg, MutuallyExclusiveArgList


class RegionConfigurableMixin(object):
    """
    A mixin that allows the user to specify which user/region names to use
    for the configuration via a --region arg and, if a 'REGION_ENVVAR' class
    variable is set, an environment variable as well.  The included
    update_config_view method actually reads these data and updates
    self.config to point to them.
    """

    ARGS = [Arg('--region', metavar='USER@REGION', route_to=None,
                help=('region and/or user names to search when looking up '
                      'config file data'))]

    def update_config_view(self, region=None, user=None):
        # Different sources of user/region info can override only parts of
        # the set, so we only overwite things conditionally.

        # self.args gets highest precedence
        if self.args.get('region'):
            _user, _region = self.__parse_region(self.args['region'])
            user = user or _user
            region = region or _region
        # Environment comes next
        if (getattr(self, 'REGION_ENVVAR', None) and
                os.getenv(self.REGION_ENVVAR)):
            _user, _region = self.__parse_region(os.getenv(self.REGION_ENVVAR))
            user = user or _user
            region = region or _region
        # Default region from the config file
        if not region:
            region = self.config.get_global_option('default-region')
        # User info can come from a region, so set that in the config now.
        if region:
            self.config.region = region
        # Look up the region's user if needed...
        if not user:
            user = self.config.get_region_option('user')
        # ...and finally update the config with that as well.
        if user:
            self.config.user = user

    @staticmethod
    def __parse_region(regionish):
        """
        Given a string with pattern "[USER@][REGION]", return the user
        and region names that that string represents, if any, and None
        for the values it does not represent.

        Examples:
         - ""          -> (None, None)
         - "spam"      -> (None, "spam")
         - "eggs@"     -> ("eggs", None)
         - "eggs@spam" -> ("eggs", "spam")
        """

        if not regionish:
            return None, None
        if regionish.endswith('@'):
            return regionish.rstrip('@'), None
        elif '@' in regionish:
            return regionish.split('@', 1)
        else:
            return None, regionish


class TabifyingMixin(object):
    '''
    A command mixin that provides the tabify() function along with its
    associated --show-empty-fields command line arg.
    '''

    ARGS = [Arg('--show-empty-fields', action='store_true', route_to=None,
                help='show empty values as "(nil)"')]

    def tabify(self, fields, include=None):
        '''
        Join a list of strings with tabs.  Nonzero items that Python considers
        false are printed as-is if they appear in the include list, replaced
        with '(nil)' if the user specifies --show-empty-fields at the command
        line, and omitted otherwise.
        '''
        def allowable(item):
            return bool(item) or item is 0 or item in (include or [])

        if self.args['show_empty_fields']:
            fstr = '(nil)'
        else:
            fstr = ''
        return '\t'.join([str(f) if allowable(f) else fstr for f in fields])


if 'progressbar' in sys.modules:
    _PROGRESS_BAR_COMMAND_ARGS = [
        MutuallyExclusiveArgList(
            Arg('--progress', dest='show_progress', action='store_true',
                default=sys.stdout.isatty(), route_to=None,
                help='show progress (the default when run interactively)'),
            Arg('--no-progress', dest='show_progress', action='store_false',
                default=sys.stdout.isatty(), route_to=None, help='''do not
                show progress (the default when run non-interactively)'''))]
else:
    # Keep them around so scripts don't break, but make them non-functional
    #
    # This isn't in a MutuallyExclusiveArgList because of an argparse bug:
    # http://bugs.python.org/issue17890
    _PROGRESS_BAR_COMMAND_ARGS = [
        Arg('--progress', dest='show_progress', action='store_false',
            default=False, route_to=None, help=argparse.SUPPRESS),
        Arg('--no-progress', dest='show_progress', action='store_false',
            default=False, route_to=None, help=argparse.SUPPRESS)]


class FileTransferProgressBarMixin(object):
    '''
    A command mixin that provides download/upload progress bar support,
    along with options to enable or disable them.  If progress bars are
    disabled at the command line get_progressbar will return None.  If the
    progressbar module is unavailable get_progressbar will return None *and*
    no progress-related options will be added.
    '''

    ARGS = _PROGRESS_BAR_COMMAND_ARGS

    def get_progressbar(self, label=None, maxval=None):
        if 'progressbar' in sys.modules and self.args.get('show_progress',
                                                          False):
            widgets = []
            if label is not None:
                widgets += [label, ' ']
            if maxval is not None:
                widgets += [progressbar.Percentage(), ' ',
                            progressbar.Bar(marker='='), ' ',
                            _FileSize(), ' ',
                            progressbar.FileTransferSpeed(), ' ']
                if 'AdaptiveETA' in dir(progressbar):
                    widgets.append(progressbar.AdaptiveETA())
                else:
                    widgets.append(progressbar.ETA())
                pbar = progressbar.ProgressBar(widgets=widgets,
                                               maxval=(maxval or sys.maxint),
                                               poll=0.05)
                #
                # The ProgressBar class initializer installs a signal handler
                # for SIGWINCH to resize the progress bar. Sometimes this can
                # interrupt long running system calls which can cause an
                # IOError exception to be raised. The call to siginterrupt
                # below will retrieve the currently installed signal handler
                # for SIGWINCH and set the SA_RESTART flag. This will cause
                # system calls to be restarted after the handler has been
                # executed instead of raising an exception.
                #
                signal.siginterrupt(signal.SIGWINCH, False)
                return pbar
            else:
                widgets += [_IndeterminateBouncingBar(marker='='), ' ',
                            _FileSize(), ' ',
                            progressbar.FileTransferSpeed(), ' ',
                            progressbar.Timer(format='Time: %s')]
                pbar = _IndeterminateProgressBar(widgets=widgets,
                                                 maxval=(maxval or sys.maxint),
                                                 poll=0.05)
                # See comment above
                signal.siginterrupt(signal.SIGWINCH, False)
                return pbar
        else:
            return _EveryMethodObject()


# Used as a placeholder for ProgressBar when progressbar isn't there
class _EveryMethodObject(object):
    def do_nothing(self, *args, **kwargs):
        pass

    def __getattribute__(self, name):
        return object.__getattribute__(self, 'do_nothing')


if 'progressbar' in sys.modules:
    class _IndeterminateProgressBar(progressbar.ProgressBar):
        def finish(self):
            self.maxval = self.currval
            progressbar.ProgressBar.finish(self)


    class _IndeterminateBouncingBar(progressbar.BouncingBar):
        '''
        A BouncingBar that moves exactly one space each time it updates,
        rather than one space per unit.  This is mainly used for downloads with
        unknown lengths.
        '''
        def __init__(self, *args, **kwargs):
            progressbar.BouncingBar.__init__(self, *args, **kwargs)
            self.__update_count = 0

        def update(self, pbar, width):
            orig_currval = pbar.currval
            pbar.currval = self.__update_count
            retval = progressbar.BouncingBar.update(self, pbar, width)
            pbar.currval = orig_currval
            self.__update_count += 1
            return retval


    class _FileSize(progressbar.Widget):
        PREFIXES = ' kMGTPEZY'

        def update(self, pbar):
            if pbar.currval == 0:
                power = 0
                scaledval = 0
            else:
                power = int(math.log(pbar.currval, 1024))
                scaledval = pbar.currval / 1024.0 ** power
            return '{0:6.2f} {1}B'.format(scaledval, self.PREFIXES[power])
