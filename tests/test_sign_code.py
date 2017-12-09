#!/usr/bin/env python2.7
# pylint: disable=C0301
r""":mod:`test_sign_code` - Windows unittests for sign_code
===========================================================

.. module:: signet.tests.test_sign_code
   :synopsis: Windows unittests for signet.command.sign_code
.. moduleauthor:: Jim Carroll <jim@carroll.com>

These tests are for Windows only.

Copyright(c), 2014, Carroll-Net, Inc.
All Rights Reserved"""

# ----------------------------------------------------------------------------
# Standard library imports
# ----------------------------------------------------------------------------
import datetime
import mmap
import os
import shutil
import subprocess
import tempfile
import time
import unittest

# ----------------------------------------------------------------------------
# 3rd Party library imports
# ----------------------------------------------------------------------------
import pkg_resources

# ----------------------------------------------------------------------------
# project imports
# ----------------------------------------------------------------------------
from tests.utils import run_setup
from pywincert import make_ca, make_pfx, remove_ca

# ----------------------------------------------------------------------------
# Module level initializations
# ----------------------------------------------------------------------------
__version__ = '2.4.2'
__author__ = 'Jim Carroll'
__email__ = 'jim@carroll.com'
__status__ = 'Testing'
__copyright__ = 'Copyright(c) 2014, Carroll-Net, Inc., All Rights Reserved'

class TestSignCode(unittest.TestCase):
    r"""test the signet.command.build_signet class"""

    @classmethod
    def setUpClass(cls):
        r"""initialize class test fixture"""

        # Create self-signed Certificate Authority (CA)

        cls.cls_tmpd = tempfile.mkdtemp()
        cls.password = "abc123"
        cls.ca_pvk = os.path.join(cls.cls_tmpd, "ca.pvk")
        cls.ca_cer = os.path.join(cls.cls_tmpd, "ca.cer")
        make_ca('TESTCA', cls.password, cls.ca_pvk, cls.ca_cer)

        # Create code-signing (SPC) Certificate

        cls.pfx = os.path.join(cls.cls_tmpd, "my.pfx")
        make_pfx('TESTCA', cls.password, cls.ca_pvk, cls.ca_cer, cls.pfx)

        # Must wait until next minute before cert is valid,
        # if you remove this -- certutil will fail -1

        wait = 61 - datetime.datetime.now().second
        time.sleep(wait)

    @classmethod
    def tearDownClass(cls):
        r"""destroy class fixture"""
        shutil.rmtree(cls.cls_tmpd, ignore_errors=True)
        remove_ca('TESTCA')

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
    def test_sign_simple(self):
        r"""build a simple package"""

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
                ")\n" % (self.password, '\\\\'.join(self.pfx.split('\\'))))

        (rc, stdout, stderr) = run_setup(self.tmpd, 'build_signet')
        if rc or stderr:
            self.fail(stdout + "\n" + stderr)

        # Confirm *.exe exists

        self.assertIn('hello.exe', os.listdir(self.tmpd))

        # Sign *.exe

        (rc, stdout, stderr) = run_setup(self.tmpd, 'sign_code')
        if rc or stderr:
            self.fail(stdout + "\n" + stderr)

        # Run *.exe, validate output

        exe = os.path.join(self.tmpd, 'hello.exe')
        self.assertEqual(
            subprocess.check_output([exe], universal_newlines=True),
            "Hello world\n")

    @unittest.skipUnless(os.name == 'nt', 'requires windows')
    def test_tampering(self):
        r"""tamper with code -- ensure PE verify fails"""

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
                ")\n" % (self.password, '\\\\'.join(self.pfx.split('\\'))))

        # Build *.exe

        (rc, stdout, stderr) = run_setup(self.tmpd, 'build_signet')
        if rc or stderr:
            self.fail(stdout + "\n" + stderr)
        self.assertIn('hello.exe', os.listdir(self.tmpd))

        # Sign code

        (rc, stdout, stderr) = run_setup(self.tmpd, 'sign_code')
        if rc or stderr:
            self.fail(stdout + "\n" + stderr)

        exe = os.path.join(self.tmpd, 'hello.exe')

        # TAMPER with binary

        with open(exe, 'r+b') as fout:
            mm = mmap.mmap(fout.fileno(), 0)
            off = mm.find('hello.py')
            mm.seek(off)
            mm.write('HELLO.py')
            mm.close()

        # Run *.exe, confirm security violation

        task = subprocess.Popen([exe], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            universal_newlines=True)
        _, stderr = task.communicate()
        self.assertRegexpMatches(stderr,
                'SECURITY VIOLATION: .+ tampered binary')
        self.assertEqual(task.returncode, -1)
