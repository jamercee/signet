#!/usr/bin/env python2.7
## \file setup.py
# \brief Signet distutils setup.py
# \date July 8th, 2014
# \copyright Copyright(c), 2014, Carroll-Net, Inc.
# \copyright All Rights Reserved.
r"""Signet distutils setup.py

Copyright(c), 2014, Carroll-Net, Inc.
All Rights Reserved"""

# ----------------------------------------------------------------------------
# Standard library imports
# ----------------------------------------------------------------------------
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
__pychecker__  = 'unusednames=__maintainer__,__status__'
__version__    = '2.4.1'
__author__     = 'Jim Carroll'
__maintainer__ = 'Jim Carroll'
__email__      = 'jim@carroll.com'
__status__     = 'Distribution'
__copyright__  = 'Copyright(c) 2014, Carroll-Net, Inc., All Rights Reserved'

long_description = []

with open('docs/index.rst') as fin:
    for line in fin:
        if line.startswith('Project Background'):
            break
        long_description.append(line)

setup(
    # project meta-data

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
                               'command/static/*',]},

    # testing (assumes you have nose installed)

    test_suite      = 'nose.collector',
    setup_requires  = ['nose>=1.0'],

    )
     
