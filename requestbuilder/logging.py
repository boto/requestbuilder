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

import logging


class ProgressiveStreamHandler(logging.StreamHandler):
    '''
    A handler class that allows the "cursor" to stay on one line for selected
    messages
    '''

    appending = False

    def emit(self, record):
        try:
            if getattr(record, 'append', False):
                if self.appending:
                    self.stream.write(record.getMessage())
                else:
                    self.stream.write(self.format(record))
                self.appending = True
            else:
                terminator = getattr(self, 'terminator', '\n')
                if self.appending:
                    self.stream.write(terminator)
                self.stream.write(self.format(record))
                self.stream.write(terminator)
                self.appending = False
            self.flush()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.handleError(record)


class ColoringFormatter(logging.Formatter):
    LOG_COLORS = [(logging.ERROR, '\033[91m'),
                  (logging.WARN,  '\033[93m'),
                  (logging.INFO,  '\033[92m'),
                  (logging.DEBUG, '\033[94m')]

    def format(self, record):
        msg = logging.Formatter.format(self, record)
        for level, colorcode in sorted(self.LOG_COLORS, reverse=True):
            if record.levelno >= level:
                return colorcode + msg + '\033[0m'
        return msg


def configure_root_logger(use_color=False):
    logfmt = '%(asctime)s %(levelname)-7s %(name)s %(message)s'
    rootlogger = logging.getLogger('')
    handler    = ProgressiveStreamHandler()
    if use_color:
        formatter = ColoringFormatter(logfmt)
    else:
        formatter = logging.Formatter(logfmt)
    handler.setFormatter(formatter)
    rootlogger.addHandler(handler)
    rootlogger.setLevel(100)

    # Attempt to have logging capture warnings as well (requires 2.7)
    try:
        logging.captureWarnings(True)
    except AttributeError:
        pass
