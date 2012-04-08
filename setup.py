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

from distutils.core import setup

from requestbuilder import __version__

setup(name = 'requestbuilder',
      version = __version__,
      description = 'Command line-driven HTTP request builder',
      author = 'Garrett Holmstrom (gholms)',
      author_email = 'gholms@fedoraproject.org',
      packages = ['requestbuilder'],
      license = 'ISC',
      platforms = 'Posix; MacOS X',
      classifiers = ['Development Status :: 2 - Pre-Alpha',
                     'Intended Audience :: Developers',
                     'License :: OSI Approved :: ISC License (ISCL)',
                     'Programming Language :: Python',
                     'Programming Language :: Python :: 2',
                     'Programming Language :: Python :: 2.6',
                     'Programming Language :: Python :: 2.7',
                     'Topic :: Internet'],
      requires = ['boto (>= 2.2)'],
      provides = ['requestbuilder'])
