#!/usr/bin/env python2.7
# pylint: disable=C0301
r""":mod:`build_signet` - Build a custom signet loader
=============================================================

.. module:: signet.command.build_signet
   :synopsis: Create a signet loader for a python script.
.. moduleauthor:: Jim Carroll <jim@carroll.com>

The :mod:`signet.command.build_signet` module is responsible for building
and compiling signet loaders. It provides all the facilities you require
for scanning your module's dependencies, and building a custom signet
loader.

The built loader will be installed in the same directory as the script file.

.. py:class:: build_signet

   .. py:method:: build_extension(arguments)

   This is the main function responsible for generating your signet loader. It
   is not expected to be invoked directly by your code, but installs itself
   into the distutils.command heirarcy by nature of it's inheritance from
   `disutils.command.build_ext <https://docs.python.org/2/distutils/apiref.html#module-distutils.core>`_ .

   **build_signet** makes available additional arguments you can specify
   when calling `distutils.core.setup() <https://docs.python.org/2/distutils/apiref.html#distutils.core.setup>`_ 

   .. tabularcolumns:: |l|L|l

   +----------------+---------------------------------------+-------------------------------+
   | argument name  | value                                 | type                          |
   +================+=======================================+===============================+
   | *template*     | The path to a custom loader           | a string                      |
   |                | to override the default loader        |                               |
   |                | provided by signet.                   |                               |
   +----------------+---------------------------------------+-------------------------------+
   | *cflags*       | any extra platform- and compiler-     | a list of strings             |
   |                | specific settings to use when         |                               |
   |                | **compiling** the custom loader.      |                               |
   |                | If you specify this setting on windows|                               |
   |                | you override our default '/EHsc'.     |                               |
   +----------------+---------------------------------------+-------------------------------+
   | *ldflags*      | any extra platform- and compiler-     | a list of strings             |
   |                | specific settings to use when         |                               |
   |                | **linking** the custom loader. If you |                               |
   |                | specify this setting on posix, you    |                               |
   |                | override our default '--strip-all'    |                               |
   +----------------+---------------------------------------+-------------------------------+
   | *detection*    | The default tamper protection used    | an int                        |
   |                | by your loader. Valid choices are;    |                               |
   |                | 3 require signed binary, 2 normal     |                               |
   |                | detection (default), 1 warn only,     |                               |
   |                | 0 disable detection                   |                               |
   +----------------+---------------------------------------+-------------------------------+
   | *ext_modules*  | The list of python modules to build   | a list of instances           |
   |                | signet loader(s) for. *REQUIRED*      | of distutils.core.Extension   |
   +----------------+---------------------------------------+-------------------------------+
   | *excludes*     | The list of python module dependencies| a list of strings             |
   |                | to exclude from the signet loader.    |                               |
   +----------------+---------------------------------------+-------------------------------+
   | *mkresource*   | Dynamic generation of windows         | a boolean                     |
   |                | resources. If you plan to use code    |                               |
   |                | signing, it's recommended you set     |                               |
   |                | this option to True                   |                               |
   +----------------+---------------------------------------+-------------------------------+
   | *skipdepends*  | Instruct signet to not scan script    | a boolean                     |
   |                | dependencies. This is a minimum       |                               |
   |                | securty option.                       |                               |
   +----------------+---------------------------------------+-------------------------------+
   | *virtualenv*   | Build a virtualenv compatible loader. | a boolean                     |
   |                | Exclude those modules that are        |                               |
   |                | replaced by the virtualenv pkg.       |                               |
   +----------------+---------------------------------------+-------------------------------+

Windows Resources
-----------------

In Windows, resources are read-only data embedded in exe's. These resources contain
meta-data about your executables that users can inspect with Explorer, Task Manager
and other administrative tools (`Read more <https://en.wikipedia.org/wiki/Resource_%28Windows%29>`_). 

From a secuity perspective, the VESIONINFO resources are an important tool to
verify the details of a binary.  **build_signet** will generate embedded
VERSIONINFO resources for your loader when you enable the *mkresource* option
in *setup.py*. Once enabled you need to specify the resource details for your
project. There are two mechanisms for specifying the required information. The
simplest is to add special variables to your script, which **build_signet** will
scan and extract.

There are seven resources scanned by **mkresource** option; six are
required and a seventh is optional. They are:

    +-----------------------+-----------------------------------------+
    | special string        | value                                   |
    +=======================+=========================================+
    | *__companyname__*     | REQUIRED: Your organization's name      |
    +-----------------------+-----------------------------------------+
    | *__fileversion__*     | REQUIRED: Version number of your script |
    +-----------------------+-----------------------------------------+
    | *__filedescription__* | REQUIRED: Simple file description.      |
    +-----------------------+-----------------------------------------+
    | *__legalcopyright__*  | REQUIRED: The copyright notice that     |
    |                       | applies to your script.                 |
    +-----------------------+-----------------------------------------+
    | *__productname__*     | REQUIRED: The name of the project this  |
    |                       | script is part of.                      |
    +-----------------------+-----------------------------------------+
    | *__productversion__*  | REQUIRED: Version number of the project |
    |                       | this script is part of.                 |
    +-----------------------+-----------------------------------------+
    | *__icon__*            | OPTIONAL: Path name of ico file to add  |
    |                       | to your .exe (defaults to app.ico)      |
    +-----------------------+-----------------------------------------+

The special variables must be in column 1 in your script, And their values must
be hard coded.  Try not to get too frisky with whitespace or formatting --
**build_signet** uses a simple regex pattern to find them.

The second mechanism to specify required resources is to add them to
*setup.py*, for example::

    setup(
        name = "hello",                 # mapped to __productname__
        maintainer = "Acme, Inc",       # mapped to __companyname__
        description = "Cheese Grater",  # mapped to __filedescription__
        license = 'BSD'                 # mapped to __leaglcopyright__
        version = '1.0.2'               # mapped to __fileversion__ and __productversion__
        ...

You can mix and match mechanism 1 and 2, specifying some settings in your
script and other in *setup.py*. Settings in your script take precendence.

Virtualenv Compatible Loaders
-----------------------------

`virtualenv <https://virtualenv.pypa.io>`_ is a tool for creating isolated
python environments. Essentially, it creates a complete python environment on
your client's computer, and populates it with the packages and modules your
software requires which solves the problem is dependency versioniong. You can
safely include any module you require without fear of breaking something in
your client's environment.

The virtualenv package includes replacements (overrides) for several system
packages. This presents a potential problems for signet.  If your script
imports one of these dependencies, the hashes calculated will likely not match
the version of virtualenv (unless you build your loader from an active
virtualenv environment). 

We've collected the module replacements from virtualenv into a predefined
exclude list. If your *setup.py* uses the **--virtualenv** option, the loader
will be built with these excludes.


Examples
--------

Simple example, ``hello.py``::

    print('hello world\n')

``setup.py``::

    from distutils.core import setup, Extension
    from signet.command.build_signet import build_signet

    setup(name = 'hello',
        cmdclass = {'build_signet': build_signet},
        ext_modules = [Extension('hello', sources=['hello.py'])],
        )

An example to create Windows resource file, ``hello.py``::

    __companyname__ = "Acme, Inc."
    __filedescription__ = "Cheese shop"
    __fileversion__ = "1"
    __legalcopyright__ = "BSD"
    __productname__ = "Cheesy Income"

    print('Hello world')

``setup.py``::

    from distutils.core import setup, Extension
    from signet.command.build_signet import build_signet

    setup(name = 'hello',
        cmdclass = {'build_signet': build_signet},
        options = {'build_signet' : { 
                        'mkresources': True,
                        }
                  },
        ext_modules = [Extension('hello', sources=['hello.py'])],
        )

An example to exclude certain dependencies

``setup.py``::

    from distutils.core import setup, Extension
    from signet.command.build_signet import build_signet

    setup(name = 'hello',
        cmdclass = {'build_signet': build_signet},
        options = {'build_signet' : { 
                        'excludes': ['distutils'] ,
                        }
                  },
        ext_modules = [Extension('hello', sources=['hello.py'])],
        )

An example to build a *virtualenv* compatible loaders

``setup.py``::

    from distutils.core import setup, Extension
    from signet.command.build_signet import build_signet

    setup(name = 'hello',
        cmdclass = {'build_signet': build_signet},
        options = {'build_signet' : { 
                        'virtualenv': True,
                        }
                  },
        ext_modules = [Extension('hello', sources=['hello.py'])],
        )


Utility Functions
-----------------

.. autofunction:: module_signatures

.. autofunction:: generate_sigs_decl

"""
# pylint: enable=C0301

# ----------------------------------------------------------------------------
# Standard library imports
# ----------------------------------------------------------------------------
from distutils import log
from distutils.command.build_ext import build_ext as _build_ext
from distutils.dep_util import newer_group
from distutils.dir_util import copy_tree
from distutils.errors import DistutilsSetupError
import StringIO
import modulefinder
import hashlib
import os
import re

# ----------------------------------------------------------------------------
# Module level initializations
# ----------------------------------------------------------------------------
__pychecker__  = 'unusednames=__maintainer__,__status__'
__version__    = '1.0.2'
__author__     = 'Jim Carroll'
__maintainer__ = 'Jim Carroll'
__email__      = 'jim@carroll.com'
__status__     = 'Production'
__copyright__  = 'Copyright(c) 2014, Carroll-Net, Inc., All Rights Reserved'

# Exclude these dependencies when building 
# virtualenv compatible loader

VIRTUALENV_EXCLUDES = [
        'distutils',
        'pip',
        'site',
        ]

def module_signatures(py_source, verbose=True):
    r"""Scan *py_source* for dependencies, and return list of
        2-tuples [(hexdigest, modulename), ...], sorted by modulename.

        To see what signatures signet will use when building your loader::

            from signet.command.build_signet import module_signatures
            for hash, mod in module_signatures('hello.py'):
                print hash, mod
    """

    signatures = []

    finder = modulefinder.ModuleFinder()
    finder.run_script(py_source)

    # Iterate over installed modules, and try to 
    # determine what filename they came from

    my_mod = os.path.basename(py_source)
    my_mod = os.path.splitext(my_mod)[0]

    modules = { my_mod: py_source }

    for modname, mod in finder.modules.items():

        if modname == '__main__':
            continue

        # If module has a custom loader (ala: egg),
        # use the name of the archive file.

        fname = (getattr(mod, '__loader__', None) or 
                 getattr(mod, '__file__', None))

        if not fname:
            if verbose:
                log.warn("can't find module '%s'", modname)
        else:
            modules[modname] = fname

    # Now iterate over the list of filenames we 
    # collected, and calculate each one's hash

    sha1 = hashlib.sha1

    for modname in sorted(modules.keys()):

        modpath = modules[modname]
        if modpath.endswith('.pyc'):
            modpath = modpath[:-1]

        with open(modpath, 'rb') as fin:
            digest = sha1(fin.read()).hexdigest()
            signatures.append( [digest, modname] )

    return sorted(signatures, key=lambda s: s[1])

def make_sigs_decl(sigs):
    r"""Accept list of signature tuples, and returns C declaration.
        *sigs* is a list of 2-tuples [(sha1, mod), ...]. 
    """
    sigs_decl = StringIO.StringIO()
    sigs_decl.write('const Signature SIGS[] = {\n')

    for sha1, mod in sigs:
        sigs_decl.write('\t{"%s", "%s"},\n' % (sha1, mod))
    sigs_decl.write('\t};\n')

    return sigs_decl.getvalue()


def generate_sigs_decl(py_source, verbose=True, excludes=None, includes=None):
    r"""Scan *py_source*, and returns C declaration as string. 
        If *verbose* is true, display diagnostic output. Any modules or it's
        decendants in the *excludes* list will be excluded from signatures
        declaration. If *includes* list is provided, ONLY generate declarations
        for the modules in the list.  
        
        The returned string will be formatted:

    .. code-block:: c
        
        const Signature SIGS[] = {
                {"hexdigest1", "module1"},
                {"hexdigest2", "module2"},
                };
    """

    excludes = excludes or []
    includes = includes or []
    sigs = []
    for sha1, mod in module_signatures(py_source, verbose):

        # See if module is in excludes list

        excluded = False
        for excl in excludes:
            # skip module and it's decendants
            if excl == mod or excl.startswith('%s.' % mod):
                excluded = True
                break
        if excluded:
            continue

        # Include the module if no includes were specified
        # OR the module is in the includes list

        if not includes or mod in includes:
            sigs.append([sha1, mod])

    return make_sigs_decl(sigs)

def parse_rc_version(vstring):
    r"""convert version -> rc version

    Microsoft requires versions consists four decimal numbers, comma
    seperated. Missing components are set to zero.

    Eg: "1.2.3" -> "1,2,3,0"
    """
    if not re.match(r'((\d+)[\.,]?){0,4}', vstring):
        raise ValueError('invalid RC version "%s"' % vstring)

    # accept version in dotted or comma'ed format

    parts = vstring.split('.')
    if not parts:
        parts = vstring.split(',')

    if len(parts) > 4:
        raise ValueError('RC version "%s" has too many digits' % vstring)

    while len(parts) < 4:
        parts.extend('0')

    return ('%d,%d,%d,%d' % 
            (int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3])))


# pylint: disable=C0301
def extract_resource_details(py_source):
    r"""extract resource(s) from py_source
   
    Each line of py_source is scanned for resource value(s) beginning in
    column 1. The expected pattern is ``__KEY__ = 'value'``, where KEY
    is one of the valid *string-name* parameters described by 
    `MSDN <http://msdn.microsoft.com/en-us/library/windows/desktop/aa381049%28v=vs.85%29.aspx>`_ 
    (and __icon__).
    """
    # pylint: enable=C0301

    ico = os.path.join(os.path.dirname(__file__), 'static', 'app.ico')

    resources = {
        'CompanyName': None, 
        'FileDescription': None,
        'FileVersion': '0.0.0.0',
        'LegalCopyright': None,
        'ProductName': None,
        'ProductVersion': None,
        'Icon': ico,
        }

    with open(py_source) as fin:
        for line in fin:
            for key in resources.keys():
                ma = re.match(r'(?i)__%s__\s*=\s*(\'|")(.+)\1' % key, line)
                if ma:
                    resources[key] = ma.group(2)
                    break

    resources['FileVersion'] = parse_rc_version(resources['FileVersion'])
    if not resources['ProductVersion']:
        resources['ProductVersion'] = resources['FileVersion']
    else:
        resources['ProductVersion'] = parse_rc_version(resources['FileVersion'])

    return resources

class build_signet(_build_ext):
    r"""Build signet loader."""

    description = "build signet loader"""
    user_options = _build_ext.user_options
    boolean_options = _build_ext.boolean_options

    loader_exts = ['.c', '.cpp', '.c++', '.c++'] # recognized loader extensions

    user_options.extend([

        # options that require parameters
        ('cflags=',  None,
         "optional compiler flags (MSVC default is /EHsc)"), 
        ('detection=', None,
         "tamper detection - 0 disabled, 1 warn, 2 normal, 3 signed-binary "
         "(default 2)"),
        ('excludes=', None,
         "list of dependant modules to exlcude from signet loader (comma separated)"),
        ('ldflags=', None,
         "optional linker flags (posix default is --strip-all)"),
        ('template=', None,
         "signet loader template (c or c++)"),

        # boolean options (no parameter expected)
        ('mkresource', None,
         "dynamic generation of windows resources"),
        ('skipdepends', None,
         "do not scan script dependencies"),
        ('virtualenv', None,
         "build virtualenv compatible loader"),
        ])

    boolean_options.extend(['mkresource', 'skipdepends', 'virtaulenv'])

    def __init__(self, dist):
        r"""initialize local variables -- BEFORE calling the
            base class __init__, which will cause a callback to
            our initialize_options()."""

        ## \var signet_root
        # \brief Where signet.command is installed

        self.signet_root = os.path.dirname(__file__)

        ## \var lib_root
        # \brif Default library subdirectory

        self.lib_root = os.path.join(self.signet_root, 'lib')

        _build_ext.__init__(self, dist)

    def initialize_options(self):
        r"""set default option values"""

        _build_ext.initialize_options(self)

        self.cflags = []
        self.detection = None
        self.excludes = None
        self.ldflags = []
        self.mkresource = None
        self.skipdepends = None
        self.template = None
        self.virtualenv = None


    def finalize_options(self):
        r"""finished initializing option values"""
        
        # R0912 (too-many-branches)
        # pylint: disable=R0912

        _build_ext.finalize_options(self)

        opts = self.distribution.get_option_dict('build_signet')

        # validate loader template

        if self.template is None and opts:
            self.template = opts.get('template', (None, None))[1]
        if self.template is None:
            self.template = os.path.join(self.signet_root, 
                                    'templates', 'loader.cpp')

        if not os.path.isfile(self.template):
            raise DistutilsSetupError("missing 'template' source '%s'" %
                    self.template)

        ext = os.path.splitext(self.template)[1]
        if ext not in self.loader_exts:
            raise DistutilsSetupError("'template' source '%s' "
                "is not a recognized c/c++ extension." % self.template)

        # validate cflags

        if not self.cflags and opts:
            self.cflags = opts.get('cflags', (None, []))[1]
        if not self.cflags and os.name == 'nt':
            self.cflags = ['/EHsc']
        if isinstance(self.cflags, str):
            # pylint: disable=E1103
            self.cflags = self.cflags.split(',')

        # validate ldflags
    
        if not self.ldflags and opts:
            self.opts = opts.get('ldflags', (None, []))[1]
        if not self.ldflags and os.name == 'posix':
            self.ldflags = ['--strip-all', '-lstdc++',]
        if isinstance(self.ldflags, str):
            # pylint: disable=E1103
            self.ldlags = self.ldlags.split(',')

        # validate tamper detection

        if self.detection is None:
            if opts:
                self.detection = int(opts.get('detection', (None, 2))[1])
            else:
                self.detection = 2
        else:
            self.detection = int(self.detection)

        # validate excludes

        if self.excludes is None:
            if opts:
                self.excludes = opts.get('excludes', (None, []))[1]
            else: 
                self.excludes = []

        if isinstance(self.excludes, str):
            # pylint: disable=E1103
            self.excludes = self.excludes.split(',')

        # validate skipdepends

        if self.skipdepends is None and opts:
            self.skipdepends = opts.get('skipdepends', (None, None))[1]

        # validate virtualenv

        if self.virtualenv is None and opts:
            self.virtualenv = opts.get('virtualenv', (None, None))[1]

        if self.virtualenv:
            self.excludes.extend(VIRTUALENV_EXCLUDES)

        # validate mkresource generation

        if self.mkresource is None and opts:
            self.mkresource = opts.get('mkresource', (None, None))[1]

        if self.mkresource and os.name != 'nt':
            raise DistutilsSetupError("'mkresource' is only a valid "
                    "option on windows")

    def generate_loader_source(self, py_source):
        r"""Generate loader source code

        Read from a loader template and write out c/c++ source code, making
        suitable substitutions.
        """
        # R0914 (too-many-locals)
        # pylint: disable=R0914

        includes = None
        if self.skipdepends:
            includes = [os.path.basename(py_source)[:-3]]

        sig_decls = generate_sigs_decl(py_source, verbose=False, 
                        excludes=self.excludes, includes=includes)

        self.debug_print(sig_decls)

        loader_source = os.path.join(self.build_lib, 
                            os.path.basename(py_source[0:-3]) + '.cpp')

        with open(self.template) as fin:
            with open(loader_source, 'w') as fout:
                for line in fin:
                    fout.write(line)

        script_tag = 'const char SCRIPT[]'
        sigs_tag = 'const Signature SIGS[]'
        tamp_tag = 'int TAMPER'

        found_script, found_sigs, found_tamp = False, False, False

        loader_hdr = os.path.join(self.signet_root, 'templates', 'loader.h')
        with open(loader_hdr) as fin:
            tgt_hdr = os.path.join(self.build_lib, 'loader.h')
            with open(tgt_hdr, 'w') as fout:
                for line in fin:
                    # found SCRIPT declaration ?
                    if line.startswith(script_tag):
                        fout.write('%s = "%s";\n' % (script_tag, py_source))
                        found_script = True
                    # found SIGS declatation ?
                    elif line.startswith(sigs_tag):
                        fout.write(sig_decls)
                        found_sigs = True
                    # found tamper protection decl?
                    elif line.startswith(tamp_tag):
                        fout.write('%s = %d;\n' % (tamp_tag, self.detection))
                        found_tamp = True
                    else:
                        fout.write(line)

        for found, tag in ((found_script, script_tag), 
                           (found_sigs, sigs_tag), 
                           (found_tamp, tamp_tag)):
            if not found:
                raise DistutilsSetupError("missing declaration '%s' in %s" 
                    % (tag, loader_hdr))

        return loader_source

    def generate_rcfile(self, py_source, tgt_dir):
        r"""create windows resource file"""

        try:
            rc = extract_resource_details(py_source)
        except ValueError, exc:
            raise DistutilsSetupError("error extracting detailed from %s, %s"
                    % (py_source, str(exc)))

        md = self.distribution.metadata

        rc['CompanyName'] = (rc.get('CompanyName') or
                                getattr(md, 'maintainer', None))
        rc['FileDescription'] = (rc.get('FileDescription') or 
                                getattr(md, 'description', None))
        rc['FileVersion'] = (rc.get('FileVersion') or 
                                getattr(md, 'version', None))
        rc['LegalCopyright'] = (rc.get('LegalCopyright') or 
                                getattr(md, 'license', None))
        rc['ProductName'] = (rc.get('ProductName') or 
                                getattr(md, 'name', None))
        rc['ProductVersion'] = (rc.get('ProductVersion') or 
                                getattr(md, 'version', None))

        for key, val in rc.items():
            if not val:
                raise DistutilsSetupError(
                    "when 'build_signet' mkresource=1, then "
                    "__%s__ must be set in %s" % (key, py_source))

        base = os.path.basename(py_source)
        exename = os.path.splitext(base)[0] + '.exe'

        rcfile = os.path.splitext(base)[0] + '.rc'
        rcfile = os.path.join(tgt_dir, rcfile)

        # RC requires a valid escapped path -- simplest to
        # just convert back slash -> forward slash

        rc['Icon'] = '/'.join(rc['Icon'].split('\\'))

        with open(rcfile, 'w') as fout:
            fout.write('1  ICON    "%s"\n' % rc['Icon'])
            fout.write('1  VERSIONINFO\n')
            fout.write('FILEVERSION %s\n' % rc['FileVersion'])
            fout.write('PRODUCTVERSION %s\n' % rc['ProductVersion'])
            fout.write('FILEFLAGSMASK 0x17L\n')
            fout.write('FILEFLAGS 0x0L\n')
            fout.write('FILEOS 0x4L\n')
            fout.write('FILETYPE 0x1L\n')
            fout.write('FILESUBTYPE 0x0L\n')

            fout.write('BEGIN\n')
            fout.write('\tBLOCK "StringFileInfo"\n')
            fout.write('\tBEGIN\n')
            fout.write('\t\tBLOCK "040904b0"\n')    # US English, Unicode
            fout.write('\t\tBEGIN\n')
            fout.write('\t\t\tVALUE "Comments", "Created by signet loader"\n')
            fout.write('\t\t\tVALUE "CompanyName", "%s"\n' 
                    % rc['CompanyName'])
            fout.write('\t\t\tVALUE "FileDescription", "%s"\n'
                    % rc['FileDescription'])
            fout.write('\t\t\tVALUE "FileVersion", "%s"\n'
                    % rc['FileVersion'])
            fout.write('\t\t\tVALUE "InternalName", "%s"\n'
                    % base)
            fout.write('\t\t\tVALUE "LegalCopyright", "%s"\n'
                    % rc['LegalCopyright'])
            fout.write('\t\t\tVALUE "OriginalFileName", "%s"\n' 
                    % exename)
            fout.write('\t\t\tVALUE "ProductName", "%s"\n'
                    % rc['ProductName'])
            fout.write('\t\t\tVALUE "ProductVersion", "%s"\n'
                    % rc['ProductVersion'])
            fout.write('\t\tEND\n')
            fout.write('\tEND\n')
            fout.write('\tBLOCK "VarFileInfo"\n')
            fout.write('\tBEGIN\n')
            fout.write('\t\tVALUE "Translation", 0x409, 1200\n')
            fout.write('\tEND\n')
            fout.write('END\n')

        return rcfile

    def build_extension(self, ext):
        r"""perform the build action(s)"""

        if ext.sources is None or len(ext.sources) > 1:
            raise DistutilsSetupError(
                "in 'ext_modules' options (extension '%s'), "
                "'sources' must be present and must be "
                "a single source filename" % ext.name)

        py_source = ext.sources[0]

        depends = ext.sources + ext.depends
        exe_path = os.path.splitext(py_source)[0]
        if os.name == 'nt':
            exe_path += '.exe'

        if not (self.force or newer_group(depends, exe_path, 'newer')):
            log.info("skipping '%s' loader (up-to-date)", ext.name)
            return
        else:
            log.info("building '%s' signet loader", ext.name)

        # Copy libary files from signet pakage to our intended
        # target directory

        lib_sources = copy_tree(self.lib_root, self.build_lib, verbose=0)

        # Build list of source files we are compiling -> objs
        # (loader template + library code)

        loader_sources = [self.generate_loader_source(py_source)]
        for lib_source in lib_sources:
            if os.path.splitext(lib_source)[1] in self.loader_exts:
                loader_sources.append(lib_source)

        if self.mkresource:
            loader_sources.append(self.generate_rcfile(py_source, self.build_lib))
                        
        # Add extra compiler args (from Extension or command line)

        extra_args = ext.extra_compile_args or []
        if self.cflags:
            extra_args += self.cflags

        # Add macros (and remove undef'ed macros)

        macros = ext.define_macros[:]
        for undef in ext.undef_macros:
            macros.append((undef,))

        # compile

        objects = self.compiler.compile(loader_sources,
                    macros = macros,
                    include_dirs = ext.include_dirs,
                    debug = self.debug,
                    extra_postargs = extra_args,
                    depends = ext.depends)

        self._built_objects = objects[:]

        # Add extra objs to link pass

        if ext.extra_objects:
            objects.extend(ext.extra_objects)

        # Add extra link arguments

        extra_args = ext.extra_link_args or []
        if self.ldflags:
            extra_args.extend(self.ldflags)

        # link

        self.compiler.link_executable(
                objects,
                os.path.splitext(py_source)[0],
                libraries = self.get_libraries(ext),
                runtime_library_dirs = ext.runtime_library_dirs,
                extra_postargs = extra_args,
                debug = self.debug)

