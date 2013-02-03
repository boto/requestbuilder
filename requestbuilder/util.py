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

import platform
import requests
import sys
from . import __version__

def aggregate_subclass_fields(cls, field_name):
    values = []
    # pylint doesn't know about classes' built-in mro() method
    # pylint: disable-msg=E1101
    for m_class in cls.mro():
        # pylint: enable-msg=E1101
        if field_name in vars(m_class):
            values.extend(getattr(m_class, field_name))
    return values

def get_default_user_agent():
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
        # I'm guessing for non-CPython implementations; feel free to submit
        # patches or the needed implementation-specific API references.
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

    try:
        # This should always work; I'm just being paranoid.
        user_agent.append('requests/{0}'.format(requests.__version__))
    except:
        pass

    return ' '.join(user_agent)
