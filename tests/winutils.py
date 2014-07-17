#!/usr/bin/env python2.7
## \file tests/winutils.py
# \brief windows utils for testing signet project
# \date July 16th, 2014
# \copyright Copyright(c), 2014, Carroll-Net, Inc.
# \copyright All Rights Reserved.
r"""used by unittesting for signet on windows

Copyright(c), 2014, Carroll-Net, Inc.
All Rights Reserved"""

# ----------------------------------------------------------------------------
# Standard library imports
# ----------------------------------------------------------------------------
import os
import shutil
import subprocess
import tempfile
import time
import win32com.client

# ----------------------------------------------------------------------------
# Project library imports
# ----------------------------------------------------------------------------
from signet.command.sign_code import get_winsdk_path

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


def make_pfx(password, pfx_filename):
    r"""create person info exchange file (\*.pfx). *password* is the secret
        used to protect the new pfx file. *pfx_filename* where to store the new
        pfx file. -1 indicates an error, 0 is sucess."""

    sdkpath = os.path.join(get_winsdk_path(), 'Bin')

    tmpd = tempfile.mkdtemp()

    pvk = os.path.join(tmpd, 'mykey.pvk')
    cer = os.path.join(tmpd, 'mycert.cer')
    spc = os.path.join(tmpd, 'mycert.spc')

    mkcert   = os.path.join(sdkpath, 'makecert.exe')
    cert2spc = os.path.join(sdkpath, "cert2spc.exe")
    pvk2pfx  = os.path.join(sdkpath, "pvk2pfx")

    # wait for makecert popup window
    shell = win32com.client.Dispatch('WScript.Shell')

    # create private key (*.pvk) & certificate (*.cer)
    shell.Run("\"%s\" -r -sv \"%s\" -n \"CN=TESTING\" \"%s\"" 
                % (mkcert, pvk, cer), 1, False)

    for _ in xrange(10):
        if shell.AppActivate('Create Private Key Password'):
            break
        time.sleep(1.0)
    if not shell.AppActivate('Create Private Key Password'):
        print("makecert timeout expired, exiting...")
        return -1

    # Main screen
    shell.SendKeys(password)
    time.sleep(0.2)
    shell.SendKeys('{TAB}')
    time.sleep(0.2)
    shell.SendKeys(password)
    time.sleep(0.2)
    shell.SendKeys('{TAB}')
    time.sleep(0.2)
    shell.SendKeys('{ENTER}')
    time.sleep(0.2)

    # Second screen (subject password)
    shell.SendKeys(password)
    time.sleep(0.2)
    shell.SendKeys('{TAB}')
    time.sleep(0.2)
    shell.SendKeys('{ENTER}')
    time.sleep(0.2)

    # convert cert (*.cer) -> software publish certificate (*.spc)
    subprocess.check_call([cert2spc, cer, spc])

    # combine private key + cert -> personal info exchange (*.pfx)
    subprocess.check_call([pvk2pfx, 
                            "-pvk", pvk, 
                            "-pi", password,
                            "-spc", spc,  
                            "-pfx", pfx_filename,
                            "-po", password])
    return 0

