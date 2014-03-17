# Copyright (c) 2013-2014, Eucalyptus Systems, Inc.
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

import platform
import sys

import requests

from requestbuilder import __version__


class RequestBuilder(object):
    '''
    A class with attributes and methods that define an entire suite of tools
    '''

    def __init__(self):
        self.__user_agent = None

    @staticmethod
    def format_version():
        return 'requestbuilder {0} (Intermezzo)'.format(__version__)

    @staticmethod
    def list_config_files():
        return []

    def get_user_agent(self):
        if self.__user_agent is None:
            user_agent = ['requestbuilder/{0}'.format(__version__)]

            tokens = []
            impl = platform.python_implementation()
            if impl == 'PyPy':
                impl_version = '{0}.{1}.{2}'.format(
                    sys.pypy_version_info.major,
                    sys.pypy_version_info.minor,
                    sys.pypy_version_info.micro)
                if sys.pypy_version_info.releaselevel != 'final':
                    impl_version += sys.pypy_version_info.releaselevel
            else:
                # I'm guessing for non-CPython implementations; feel free to
                # submit patches or the needed implementation-specific API
                # references.
                impl_version = platform.python_version()
            tokens.append('{0} {1}'.format(impl, impl_version))
            plat = []
            try:
                plat.append(platform.system())
                plat.append(platform.release())
            except IOError:
                pass
            if plat:
                tokens.append(' '.join(plat))
            tokens.append(platform.machine())
            user_agent.append('({0})'.format('; '.join(tokens)))
            user_agent.append('requests/{0}'.format(requests.__version__))

            self.__user_agent = ' '.join(user_agent)
        return self.__user_agent
