from __future__ import print_function

from setuptools import setup
from setuptools.command.test import test as TestCommand

import os
import sys

ROOT = os.path.abspath(os.path.dirname(__file__))

tests_require = ['pytest', 'pytest-pep8']
if sys.version_info[0] == 2:
    tests_require.append('mock')

def read(*filenames):
    buf = []
    for filename in filenames:
        filepath = os.path.join(ROOT, filename)
        try:
            with open(filepath, 'r') as f:
                buf.append(f.read())
        except IOError:
            # ignore tox IOError (no such file or directory)
            pass
    return '\n\n'.join(buf)


long_description = read('README.md')

class PyTest(TestCommand):

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest
        errcode = pytest.main(self.test_args)
        sys.exit(errcode)


setup(
    name='tlvdict',
    version="3.0",
    url='https://github.com/311labs/tlvdict/',
    author='Ian Starnes',
    author_email='ian@311labs.com',
    tests_require=tests_require,
    cmdclass={'test': PyTest},
    description=(
        'A Python dict that handles TLV decode/encode'
    ),
    long_description=long_description,
    packages=['tlvdict'],
    platforms='any',
    test_suite='tests',
    python_requires='>=3.5, <4',
    classifiers=[
        'Programming Language :: Python',
        'Development Status :: 1.1.0 - Prod',
        'Natural Language :: English',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Utilities',
    ],
    install_requires=[
        'objict',
    ],
    extras_require={
        'dev': ['check-manifest', 'wheel'],
        'test': tests_require,
    }
)
