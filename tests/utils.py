#!/usr/bin/env python2.7
## \file tests/utils.py
# \brief utils for testing signet project
# \date July 16th, 2014
# \copyright Copyright(c), 2014, Carroll-Net, Inc.
# \copyright All Rights Reserved.
r"""used by unittesting for signet

Copyright(c), 2014, Carroll-Net, Inc.
All Rights Reserved"""

# ----------------------------------------------------------------------------
# Standard library imports
# ----------------------------------------------------------------------------
import os
import subprocess
import sys

# ----------------------------------------------------------------------------
# Module level initializations
# ----------------------------------------------------------------------------
__pychecker__  = 'unusednames=__maintainer__,__status__'
__version__    = '2.4.1'
__author__     = 'Jim Carroll'
__maintainer__ = 'Jim Carroll'
__email__      = 'jim@carroll.com'
__status__     = 'Testing'
__copyright__  = 'Copyright(c) 2014, Carroll-Net, Inc., All Rights Reserved'

def run_setup(dirname, cmd, opts=None, debug=False):
    r"""run setup.py command from directory"""

    opts = opts or []

    # Populate the PYTHONPATH with the parent's path (set in __init__.py)
    # to make sure we run the development version of signet.command

    python_path = os.environ.get('PYTHONPATH')
    if not python_path:
        os.environ['PYTHONPATH'] = sys.path[0]
    elif python_path and python_path.split(os.pathsep)[0] != sys.path[0]:
        new_path = '%s%s%s' % (sys.path[0], os.pathsep, python_path)
        os.environ['PYTHONPATH'] = new_path

    if debug:
        os.environ['DISTUTILS_DEBUG'] = '1'

    command = [sys.executable, 'setup.py', cmd]
    if opts:
        command += opts

    cwd = os.getcwd()
    os.chdir(dirname)
    try:
        task = subprocess.Popen(command, universal_newlines=True,
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE)
        (stdout, stderr) = task.communicate()
        return (task.returncode, stdout, stderr)
    finally:
        os.chdir(cwd)
        if python_path:
            os.environ['PYTHONPATH'] = python_path
        else:
            del os.environ['PYTHONPATH']


