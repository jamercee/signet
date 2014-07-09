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

setup(
    # project meta-data

    name = 'signet',
    version = signet.__version__,
    description = 'signet loader',
    author = 'Jim Carroll',
    author_email = 'jim@carroll.com',
    url = 'http://www.carroll.net',

    # project details

    packages = ['signet', 'signet.command'],
    package_data = {'signet': ['command/templates/*', 'command/lib/*',]},

    # testing (assumes you have nose installed)

    test_suite      = 'nose.collector',
    setup_requires  = ['nose>=1.0'],
    )
     
