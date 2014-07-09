#!/usr/bin/env python2.7
## \file tests/build_ext.py
# \brief signet.command.build_signet unittests
# \date July 7th, 2014
# \copyright Copyright(c), 2014, Carroll-Net, Inc.
# \copyright All Rights Reserved.
r"""unittests for signet.command.build_signet

Copyright(c), 2014, Carroll-Net, Inc.
All Rights Reserved"""

# ----------------------------------------------------------------------------
# Standard library imports
# ----------------------------------------------------------------------------
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

# ----------------------------------------------------------------------------
# 3rd Party library imports
# ----------------------------------------------------------------------------
import pkg_resources

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

# W0212 Disable Access to a protected member
# R0904 Disable Too many public methods
# pylint: disable=W0212, R0904

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

class TestBuildSignet(unittest.TestCase):
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

    def test_build_simple(self):
        r"""build a simple package"""

        hello_py = os.path.join(self.tmpd, 'hello.py')
        setup_py = os.path.join(self.tmpd, 'setup.py')

        with open(hello_py, 'w') as fout:
            fout.write("print('Hello world')\n")
        with open(setup_py, 'w') as fout:
            fout.write(
                "from distutils.core import setup, Extension\n"
                "from signet.command.build_signet import build_signet\n"
                "setup(name = 'hello',\n"
                "    cmdclass = {'build_signet': build_signet},\n"
                "    ext_modules = [Extension('hello', \n"
                "                      sources=['hello.py'])],\n"
                ")\n"
                )

        (rc, stdout, stderr) = run_setup(self.tmpd, 'build_signet')
        if rc or len(stderr):
            self.fail(stdout + "\n" + stderr)

        if os.name == 'nt':
            exe = 'hello.exe'
        else:
            exe = 'hello'

        self.assertIn(exe, os.listdir(self.tmpd))

        # Run the signet loader, validate output

        exe = os.path.join(self.tmpd, exe)
        self.assertEqual(
            subprocess.check_output([exe], universal_newlines=True), 
            "Hello world\n")

    def test_tampering_function(self):
        r"""confirm tampering detection is functioning"""

        # Generate signet loader

        hello_py = os.path.join(self.tmpd, 'hello.py')
        setup_py = os.path.join(self.tmpd, 'setup.py')

        with open(hello_py, 'w') as fout:
            fout.write("print('Hello world')\n")
        with open(setup_py, 'w') as fout:
            fout.write(
                "from distutils.core import setup, Extension\n"
                "from signet.command.build_signet import build_signet\n"
                "setup(name = 'hello',\n"
                "    cmdclass = {'build_signet':build_signet},\n"
                "    ext_modules = [Extension('hello', \n"
                "                      sources=['hello.py'])],\n"
                ")\n"
                )

        (rc, stdout, stderr) = run_setup(self.tmpd, 'build_signet')
        if rc or len(stderr):
            self.fail(stdout + "\n" + stderr)

        # tamper with the SCRIPT

        with open(hello_py, 'a') as fout:
            fout.write('\n')

        # run the signet loader

        if os.name == 'nt':
            exe = 'hello.exe'
        else:
            exe = 'hello'

        # Confirm tamper detection

        task = subprocess.Popen([os.path.join(self.tmpd, exe)], 
                universal_newlines=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (_, stderr) = task.communicate()
        self.assertEqual(task.returncode, -1, "tamper detection failed")
        self.assertTrue(stderr and stderr.startswith('SECURITY VIOLATION:'),
                "unrecognized tampered output %s" % stderr)

    def test_custom_loader(self):
        r"""create & use a custom loader"""

        # Generate signet loader

        hello_py = os.path.join(self.tmpd, 'hello.py')
        setup_py = os.path.join(self.tmpd, 'setup.py')
        loader_c = os.path.join(self.tmpd, 'loader.c')

        with open(hello_py, 'w') as fout:
            fout.write("print('Hello world')\n")
        with open(setup_py, 'w') as fout:
            fout.write(
                "from distutils.core import setup, Extension\n"
                "from signet.command.build_signet import build_signet\n"
                "setup(name = 'hello',\n"
                "    cmdclass = {'build_signet':build_signet},\n"
                "    ext_modules = [Extension('hello', \n"
                "                      sources=['hello.py'])],\n"
                ")\n"
                )
        with open(loader_c, 'w') as fout:
            fout.write(
                "#include <stdio.h>\n"
                "struct Signature {\n"
                "   const char* hexdigest;\n"
                "   const char* mod_name;\n"
                "   };\n"
                "const char SCRIPT[]="";\n"
                "const Signature SIGS[] = {{NULL,NULL}};\n"
                "int TamperProtection = 2;\n"
                "int main() {\n"
                "   printf(\"CUSTOM\\n\");\n"
                "   return 0;\n"
                "   }\n"
                )

        (rc, stdout, stderr) = run_setup(self.tmpd, 'build_signet', 
                                ['--template', loader_c])
        if rc or len(stderr):
            self.fail(stdout + "\n" + stderr)

        # Run the signet loader, validate output

        if os.name == 'nt':
            exe = 'hello.exe'
        else:
            exe = 'hello'
        exe = os.path.join(self.tmpd, exe)

        self.assertEqual(
            subprocess.check_output([exe], universal_newlines=True), 
            "CUSTOM\n")

    def test_detection_levels(self):
        r"""test alternate detection levels 3, 1 & 0 (omit 2)"""

        # Generate signet loader

        hello_py = os.path.join(self.tmpd, 'hello.py')
        setup_py = os.path.join(self.tmpd, 'setup.py')

        with open(hello_py, 'w') as fout:
            fout.write("print('Hello world')\n")
        with open(setup_py, 'w') as fout:
            fout.write(
                "from distutils.core import setup, Extension\n"
                "from signet.command.build_signet import build_signet\n"
                "setup(name = 'hello',\n"
                "    cmdclass = {'build_signet':build_signet},\n"
                "    ext_modules = [Extension('hello', \n"
                "                      sources=['hello.py'])],\n"
                ")\n"
                )

        (rc, stdout, stderr) = run_setup(self.tmpd, 'build_signet')
        if rc or len(stderr):
            self.fail(stdout + "\n" + stderr)

        # tamper with the SCRIPT

        with open(hello_py, 'a') as fout:
            fout.write('\n')

        # run the signet loader

        if os.name == 'nt':
            exe = 'hello.exe'
        else:
            exe = 'hello'

        # Confirm signed detection

        task = subprocess.Popen([os.path.join(self.tmpd, exe), '--SECURITYMAX'], 
                universal_newlines=True, 
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (_, stderr) = task.communicate()
        self.assertEqual(task.returncode, -1, "signed detection failed")
        self.assertTrue(stderr and 
                'SECURITY MAXIMUM Enabled' in stderr and
                'SECURITY WARNING:' in stderr,
                "unrecognized tampered output %s" % stderr)

        # Confirm warn only

        task = subprocess.Popen(
                [os.path.join(self.tmpd, exe), '--SECURITYWARN'], 
                universal_newlines=True, 
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (_, stderr) = task.communicate()
        self.assertEqual(task.returncode, 0, "warn only failed")
        self.assertTrue(stderr and 
                'SECURITY DISABLED' in stderr and
                'SECURITY WARNING:' in stderr and
                'SECURITY VIOLATION:' in stderr,
                "unrecognized tampered output %s" % stderr)

        # Confirm disabled security

        task = subprocess.Popen([os.path.join(self.tmpd, exe), '--SECURITYOFF'], 
                universal_newlines=True, 
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (_, stderr) = task.communicate()
        self.assertEqual(task.returncode, 0, "warn only failed")
        self.assertTrue(stderr and 'SECURITY DISABLED' in stderr,
                "unrecognized tampered output %s" % stderr)

