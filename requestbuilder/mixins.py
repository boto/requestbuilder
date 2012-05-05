# Software License Agreement (2-clause BSD License)
#
# Copyright (c) 2012, Eucalyptus Systems, Inc.
#
# Redistribution and use of this software in source and binary forms, with or
# without modification, are permitted provided that the following conditions
# are met:
#
#   Redistributions of source code must retain the above
#   copyright notice, this list of conditions and the
#   following disclaimer.
#
#   Redistributions in binary form must reproduce the above
#   copyright notice, this list of conditions and the
#   following disclaimer in the documentation and/or other
#   materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from . import Arg
from .command import BaseCommand

class TabifyingCommand(BaseCommand):
    '''
    A request mixin that provides the tabify() function along with its
    associated --show-empty-fields command line arg.
    '''

    Args = [Arg('--show-empty-fields', action='store_true', route_to=None,
                help='show empty columns as "(nil)"')]

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
