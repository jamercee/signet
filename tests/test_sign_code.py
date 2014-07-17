#!/usr/bin/env python2.7
## \file tests/build_ext.py
# \brief signet.command.sign_code unittests
# \date July 16th, 2014
# \copyright Copyright(c), 2014, Carroll-Net, Inc.
# \copyright All Rights Reserved.
r"""unittests for signet.command.sign_code

Copyright(c), 2014, Carroll-Net, Inc.
All Rights Reserved"""

# ----------------------------------------------------------------------------
# Standard library imports
# ----------------------------------------------------------------------------
import os
import shutil
import subprocess
import tempfile
import unittest

# ----------------------------------------------------------------------------
# 3rd Party library imports
# ----------------------------------------------------------------------------
import pkg_resources

# ----------------------------------------------------------------------------
# project imports
# ----------------------------------------------------------------------------
from tests.utils import run_setup
from tests.winutils import make_pfx

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

class TestSignCode(unittest.TestCase):
    r"""test the signet.command.build_signet class"""

    def setUp(self):
        r"""initialize test fixture"""
        self.tmpd = tempfile.mkdtemp()

    def tearDown(self):
        r"""test fixture cleanup"""
        shutil.rmtree(self.tmpd, ignore_errors=True)

    def test_simple(self):
        r"""simple test of version (to confirm we got right)"""

        import signet
        self.assertGreaterEqual(
            pkg_resources.parse_version(signet.__version__),
            pkg_resources.parse_version("1.0.2"))

    @unittest.skipUnless(os.name == 'nt', 'requires windows')
    def test_make_pfx(self):
        r"""test pfx generation"""
        passwd = 'abc123'
        pfx = os.path.join(self.tmpd, "mycert.pfx")
        self.assertEqual(make_pfx(passwd, pfx), 0)

    @unittest.skipUnless(os.name == 'nt', 'requires windows')
    def test_sign_simple(self):
        r"""build a simple package"""

        passwd = 'abc123'
        pfx = os.path.join(self.tmpd, "mycert.pfx")
        self.assertEqual(make_pfx(passwd, pfx), 0)
        self.assertTrue(os.path.isfile(pfx))

        hello_py = os.path.join(self.tmpd, 'hello.py')
        setup_py = os.path.join(self.tmpd, 'setup.py')

        with open(hello_py, 'w') as fout:
            fout.write("print('Hello world')\n")
        with open(setup_py, 'w') as fout:
            fout.write(
                "from distutils.core import setup, Extension\n"
                "from signet.command.build_signet import build_signet\n"
                "from signet.command.sign_code import sign_code\n"
                "setup(name = 'hello',\n"
                "    cmdclass = {'build_signet': build_signet,\n"
                "                'sign_code': sign_code,\n"
                "               },\n"
                "    options = { 'build_signet' : {\n"
                "                       'detection': 3\n"
                "                       },\n"
                "                'sign_code' : {\n"
                "                       'password': '%s',\n"
                "                       'pfx_file': '%s',\n"
                "                       },\n"
                "               },\n"
                "    ext_modules = [Extension('hello', \n"
                "                      sources=['hello.py'])],\n"
                ")\n" % (passwd, '\\\\'.join(pfx.split('\\'))))
        
        (rc, stdout, stderr) = run_setup(self.tmpd, 'build_signet')
        if rc or len(stderr):
            self.fail(stdout + "\n" + stderr)

        self.assertIn('hello.exe', os.listdir(self.tmpd))

        (rc, stdout, stderr) = run_setup(self.tmpd, 'sign_code')
        if rc or len(stderr):
            self.fail(stdout + "\n" + stderr)

        # Run the signet loader, validate output

        exe = os.path.join(self.tmpd, 'hello.exe')
        self.assertEqual(
            subprocess.check_output([exe], universal_newlines=True), 
            "Hello world\n")

