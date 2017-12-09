#!/usr/bin/env python
# vim: set fileencoding=utf-8
r"""Signet distutils setup.py
Copyright(c) 2014, Carroll-Net, Inc., All Rights Reserved"""
# ----------------------------------------------------------------------------
# Standard library imports
# ----------------------------------------------------------------------------
import os
from setuptools import setup

try:
    # http://bugs.python.org/issue15881#msg170215
    # pylint: disable=W0611
    import multiprocessing
except ImportError:
    pass

# ----------------------------------------------------------------------------
# Project imports
# ----------------------------------------------------------------------------
import signet

# ----------------------------------------------------------------------------
# Module level initializations
# ----------------------------------------------------------------------------
__version__ = '2.5.1'
__author__ = 'Jim Carroll'
__email__ = 'jim@carroll.com'
__status__ = 'Distribution'
__copyright__  = 'Copyright(c) 2014, Carroll-Net, Inc., All Rights Reserved'

long_description = []
try:
    with open('docs/index.rst') as fin:
        for line in fin:
            if line.startswith('Project Background'):
                break
            long_description.append(line)
except IOError:
    pass

setup_requires  = ['nose>=1.0']
install_requires = ['snakefood']
if os.name == 'nt':
    setup_requires.append('pywincert')
    install_requires.append('pywincert')

setup(
    name = 'signet',
    version = signet.__version__,
    description = ('Signet provides support for building and '
                        'delivering tamper resistant python to your '
                        'users and customers.'),
    long_description = ''.join(long_description),
    author = 'Jim Carroll',
    author_email = 'jim@carroll.com',
    url = 'http://jamercee.github.io/signet',
    download_url = 'http://github.com/jamercee/signet',
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Topic :: Security',
        'Topic :: Software Development :: Build Tools',
        'Topic :: System :: Software Distribution',
        ],
    license = 'Signet is licensed under the 3-clause BSD License',

    # project details

    packages = ['signet', 'signet.command'],
    package_data = {'signet': ['command/templates/*',
                               'command/lib/*',
                               'command/static/*',
                               ]},

    # testing (assumes you have nose installed)

    test_suite = 'nose.collector',
    setup_requires = setup_requires,
    install_requires = install_requires,
    )
