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

from distutils.command.build_py import build_py
from distutils.command.sdist import sdist
import os.path
import sys

from setuptools import find_packages, setup

from requestbuilder import __version__


requirements = ['requests>=1',
                'six']
if sys.version_info < (2, 7):
    requirements.append('argparse')


class build_py_with_git_version(build_py):
    '''Like build_py, but also hardcoding the version in __init__.__version__
       so it's consistent even outside of the source tree'''

    def build_module(self, module, module_file, package):
        build_py.build_module(self, module, module_file, package)
        if module == '__init__' and '.' not in package:
            version_line = "__version__ = '{0}'\n".format(__version__)
            old_init_name = self.get_module_outfile(self.build_lib, (package,),
                                                    module)
            new_init_name = old_init_name + '.new'
            with open(new_init_name, 'w') as new_init:
                with open(old_init_name) as old_init:
                    for line in old_init:
                        if line.startswith('__version__ ='):
                            new_init.write(version_line)
                        else:
                            new_init.write(line)
                new_init.flush()
            os.rename(new_init_name, old_init_name)


class sdist_with_git_version(sdist):
    '''Like sdist, but also hardcoding the version in __init__.__version__ so
       it's consistent even outside of the source tree'''

    def make_release_tree(self, base_dir, files):
        sdist.make_release_tree(self, base_dir, files)
        version_line = "__version__ = '{0}'\n".format(__version__)
        old_init_name = os.path.join(base_dir, 'requestbuilder/__init__.py')
        new_init_name = old_init_name + '.new'
        with open(new_init_name, 'w') as new_init:
            with open(old_init_name) as old_init:
                for line in old_init:
                    if line.startswith('__version__ ='):
                        new_init.write(version_line)
                    else:
                        new_init.write(line)
            new_init.flush()
        os.rename(new_init_name, old_init_name)


setup(name='requestbuilder',
      version=__version__,
      description='Command line-driven HTTP request builder',
      author='Garrett Holmstrom (gholms)',
      author_email='gholms@devzero.com',
      url='https://github.com/boto/requestbuilder',
      packages=find_packages(),
      install_requires=requirements,
      license='ISC',
      platforms='Posix; MacOS X',
      classifiers=['Development Status :: 3 - Alpha',
                   'Intended Audience :: Developers',
                   'License :: OSI Approved :: ISC License (ISCL)',
                   'Operating System :: OS Independent',
                   'Programming Language :: Python',
                   'Programming Language :: Python :: 2',
                   'Programming Language :: Python :: 2.6',
                   'Programming Language :: Python :: 2.7',
                   'Topic :: Internet'],
      cmdclass={'build_py': build_py_with_git_version,
                'sdist': sdist_with_git_version})
