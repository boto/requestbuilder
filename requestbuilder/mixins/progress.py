# Copyright (c) 2012-2015, Eucalyptus Systems, Inc.
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
import signal
import sys
import time

try:
    import progressbar
except ImportError:
    pass

from requestbuilder import Arg, MutuallyExclusiveArgList


if 'progressbar' in sys.modules:
    _PROGRESS_BAR_COMMAND_ARGS = [
        MutuallyExclusiveArgList(
            Arg('--progress', dest='show_progress', action='store_true',
                default=sys.stdout.isatty(), route_to=None,
                help='show progress (the default when run interactively)'),
            Arg('--no-progress', dest='show_progress', action='store_false',
                default=sys.stdout.isatty(), route_to=None, help='''do not
                show progress (the default when run non-interactively)'''),
            Arg('--porcelain', dest='show_porcelain', action='store_true',
                route_to=None, help=argparse.SUPPRESS))]
else:
    # Keep them around so scripts don't break, but make them non-functional
    #
    # This isn't in a MutuallyExclusiveArgList because of an argparse bug:
    # http://bugs.python.org/issue17890
    _PROGRESS_BAR_COMMAND_ARGS = [
        Arg('--progress', dest='show_progress', action='store_false',
            default=False, route_to=None, help=argparse.SUPPRESS),
        Arg('--no-progress', dest='show_progress', action='store_false',
            default=False, route_to=None, help=argparse.SUPPRESS),
        Arg('--porcelain', dest='show_porcelain', action='store_true',
            route_to=None, help=argparse.SUPPRESS)]


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
        if self.args.get('show_porcelain'):
            return _MachineReadableCounter(label=label, maxval=maxval)
        elif 'progressbar' in sys.modules and self.args.get('show_progress',
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


class _MachineReadableCounter(object):
    def __init__(self, maxval=None, label=None):
        self.maxval = maxval
        self.currval = 0
        self._last_displayed_val = None
        self._last_updated = 0
        self._finished = False
        if label:
            self.__template = '{0} '.format(label)
        else:
            self.__template = ''
        if self.maxval:
            self.__template = '{0}{{0}}/{1}\n'.format(self.__template,
                                                      int(self.maxval))
        else:
            self.__template = '{0}{{0}}\n'.format(self.__template)

    def start(self):
        self._display()

    def update(self, val):
        self.currval = val
        delta = time.time() - self._last_updated
        if (delta > 0.1 and self.currval != self._last_displayed_val and
                not self._finished):
            self._display()
            self._last_updated = time.time()

    def finish(self):
        if self.maxval:
            self.currval = self.maxval
        self._display()
        self._finished = True

    def _display(self):
        sys.stderr.write(self.__template.format(int(self.currval)))
        self._last_displayed_val = self.currval
