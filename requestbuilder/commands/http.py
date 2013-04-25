# Copyright (c) 2013, Eucalyptus Systems, Inc.
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
import os.path
from requestbuilder import Arg, SERVICE
from requestbuilder.mixins import FileTransferProgressBarMixin
from requestbuilder.request import BaseRequest
import sys


class Get(BaseRequest, FileTransferProgressBarMixin):
    DESCRIPTION = 'A simple HTTP GET request'
    ARGS = [Arg('url', metavar='URL', route_to=SERVICE,
                help='URL to download (required)'),
            Arg('dest', metavar='PATH', route_to=None,
                help='where to download to (required)'),
            Arg('--label', route_to=None, help=argparse.SUPPRESS)]

    def parse_response(self, response):
        if ('Content-Length' in response.headers and
            response.headers.get('Content-Encoding') != 'gzip'):
            # The Content-Length for a gzipped response is that of the
            # compressed data, not the raw data that requests/urllib3 give us.
            # Since we can't tell how much has been read from the socket from
            # this level we don't show progress for gzipped # responses --
            # they'd overflow the max value otherwise.
            maxval = int(response.headers['Content-Length'])
        else:
            maxval = None
        label = self.args.get('label') or os.path.basename(self.args['url'])
        bar = self.get_progressbar(label=label, maxval=maxval)
        with open(self.get_dest_path(), 'w') as ofile:
            bar.start()
            for chunk in response.iter_content(chunk_size=8192):
                ofile.write(chunk)
                bar.update(ofile.tell())
            bar.finish()
            return self.get_dest_path(), ofile.tell()

    def get_dest_path(self):
        if os.path.isdir(self.args['dest']):
            return os.path.join(self.args['dest'],
                                os.path.basename(self.args['url']))
        else:
            return self.args['dest']
