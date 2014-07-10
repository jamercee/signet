#!/usr/bin/env python2.7
# pylint: disable=C0301
r""":mod:`build_signet` - Build a custom signet loader
=============================================================

.. module:: signet.command.build_signet
   :synopsis: Create a signet loader for a python script.
.. moduleauthor:: Jim Carroll <jim@carroll.com>

The :mod:`signet.command.build_signet` module is responsible for building
and compiling signet loaders. It provides all the facilities you require
for scanning your module's dependencies, and building your custom signet
loader.

.. function:: setup(arguments)

   This is the main function responsible for generating your signet loader.
   It inherits from 
   `disutils.command.build_ext <https://docs.python.org/2/distutils/apiref.html#module-distutils.core>`_ 
   and supports all it's parameters.  It adds a few additional arguments of it's own.

   .. tabularcolumns:: |l|L|l

   +----------------+---------------------------------------+-------------------------------+
   | argument name  | value                                 | type                          |
   +================+=======================================+===============================+
   | *template*     | The source to a custom loader         | a string                      |
   |                | to override the default loader        |                               |
   |                | provided by signet.                   |                               |
   +----------------+---------------------------------------+-------------------------------+
   | *cflags*       | any extra platform- and compiler-     | a list of strings             |
   |                | specific settings to use when         |                               |
   |                | **compiling** the custom loader.      |                               |
   +----------------+---------------------------------------+-------------------------------+
   | *ldflags*      | any extra platform- and compiler-     | a list of strings             |
   |                | specific settings to use when         |                               |
   |                | **linking** the custom loader.        |                               |
   +----------------+---------------------------------------+-------------------------------+
   | *detection*    | The default tamper protection used    | an int                        |
   |                | by your loader. Valid choices are;    |                               |
   |                | 3 require signed binary, 2 normal     |                               |
   |                | detection (default), 1 warn only,     |                               |
   |                | 0 disable detection                   |                               |
   +----------------+---------------------------------------+-------------------------------+
   | *ext_modules*  | The list of python modules to build   | a list of instances           |
   |                | signet loader(s) for. *REQUIRED*      | of *distutils.core.Extension* |
   |                |                                       | [#f1]_                        |
   +----------------+---------------------------------------+-------------------------------+

    .. [#f1] `distutils.core.Exception <https://docs.python.org/2/distutils/apiref.html#distutils.core.Extension>`_


.. class
Example ``setup.py``:

.. code-block:: py

    from distutils.core import setup, Extension
    from signet.command.build_signet import build_signet

    setup(name = 'hello',
        cmdclass = {'build_signet': build_signet},
        ext_modules = [Extension('hello', sources=['hello.py'])],
        )
"""
# pylint: enable=C0301

# ----------------------------------------------------------------------------
# Standard library imports
# ----------------------------------------------------------------------------
from distutils import log
from distutils.command.build_ext import build_ext as _build_ext
from distutils.errors import DistutilsSetupError
import StringIO
import modulefinder
import hashlib
import os
import re
import shutil

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

def module_signatures(py_source):
    r"""Scan *py_source* for dependencies, and return list of
        2-tuples [(hexdigest, modulename), ...], sorted by modulename.
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

def generate_sigs_decl(py_source):
    r"""Scan *py_source*, return SIGS c++ declaration as string. The
    returned string will be formatted:

    .. code-block:: c
        
        const Signature SIGS[] = {
                {"hexdigest1", "module1"},
                {"hexdigest2", "module2"},
                };
    """

    sigs_decl = StringIO.StringIO()
    sigs_decl.write('const Signature SIGS[] = {\n')

    for sha1, mod in module_signatures(py_source):
        sigs_decl.write('\t{"%s", "%s"},\n' % (sha1, mod))
    sigs_decl.write('\t};\n')

    return sigs_decl.getvalue()

def parse_rc_version(vstring):
    r"""convert version -> rc version

    Microsoft requires versions consists four decimal numbers, comma
    comma seperated. Missing components are set to zero.

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
def extract_manifest_details(py_source):
    r"""extract manifest from py_source
   
    Each line of py_source is scanned for a manifest value beginning in
    column 1. The expected pattern is ``__KEY__ = 'value'``, where KEY
    is one of the valid *string-name* parameters described by 
    `MSDN <http://msdn.microsoft.com/en-us/library/windows/desktop/aa381049%28v=vs.85%29.aspx>`_ 
    (and __icon__).
    """
    # pylint: enable=C0301

    manifest = {
        'CompanyName': None, 
        'FileDescription': None,
        'FileVersion': '0.0.0.0',
        'LegalCopyright': None,
        'ProductName': None,
        'ProductVersion': None,
        'Icon': 'app.ico',
        }

    with open(py_source) as fin:
        for line in fin:
            for key in manifest.keys():
                ma = re.match(r'(?i)__%s__\s*=\s*(\'")(.+)\1' % key, line)
                if ma:
                    manifest[key] = ma.group(2)
                    break

    manifest['FileVersion'] = parse_rc_version(manifest['FileVersion'])
    if not manifest['ProductVersion']:
        manifest['ProductVersion'] = manifest['FileVersion']
    else:
        manifest['ProductVersion'] = parse_rc_version(manifest['FileVersion'])

    return manifest

def copy_lib_source(lib_root, tgt_root):
    r"""Recursively copy copy *lib_root* to *tgt_root* directory"""

    libs = []

    for root, _, files in os.walk(lib_root):
        for fname in files:
            src_fname = os.path.join(root, fname)
            shutil.copy(src_fname, tgt_root)
            libs.append(fname)

    return libs

class build_signet(_build_ext):
    r"""Build signet loader."""

    description = "build signet loader"""
    user_options = _build_ext.user_options
    boolean_options = _build_ext.boolean_options

    loader_exts = ['.c', '.cpp', '.c++', '.c++'] # recognized loader extensions

    user_options.extend([
        ('template=', None,
         "signet loader template (c or c++)"),
        ('cflags=',  None,
         "optional compiler flags (MSVC default is /EHsc)"), 
        ('ldflags=', None,
         "optional linker flags (posix default is --strip-all)"),
        ('detection=', None,
         "tamper detection - 0 disabled, 1 warn, 2 normal, 3 signed-binary "
         "(default 2)"),
        ('manifest', None,
         "dynamic generation of windows manifest"),
        ])

    boolean_options.extend(['manifest'])

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

        self.template = None
        self.cflags = []
        self.ldflags = []
        self.detection = None
        self.manifest = None

    def finalize_options(self):
        r"""finished initializing option values"""

        _build_ext.finalize_options(self)

        # validate loader template

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

        if not self.cflags and os.name == 'nt':
            self.cflags = ['/EHsc']

        # validate ldflags

        if not self.ldflags and os.name == 'posix':
            self.ldflags = ['--strip-all']

        # validate tamper detection

        if self.detection is None:
            self.detection = 2

        # validate manifest generation

        if self.manifest and os.name != 'nt':
            raise DistutilsSetupError("'manifest' is only a valid "
                    "option on windows")

    def generate_loader_source(self, py_source):
        r"""Generate loader source code

        Read from a loader template and write out c/c++ source code, making
        suitable substitutions.
        """

        sig_decls = generate_sigs_decl(py_source)

        self.debug_print(sig_decls)

        loader_source = py_source[0:-3] + '.cpp'

        script_tag = 'const char SCRIPT[]'
        sigs_tag = 'const Signature SIGS[]'
        tamp_tag = 'int TamperProtection'

        found_script, found_sigs, found_tamp = False, False, False

        with open(self.template) as fin:
            with open(loader_source, 'w') as fout:
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
                raise DistutilsSetupError("missing declaration '%s' in loader" 
                    % tag)

        return loader_source

    def generate_rcfile(self, py_source, tgt_dir):
        r"""create windows resource file"""

        try:
            mnf = extract_manifest_details(py_source)
        except ValueError, exc:
            raise DistutilsSetupError("error extracting detailed from %s, %s"
                    % (py_source, str(exc)))

        md = self.distribution.metadata

        mnf['CompanyName'] = mnf['CompanyName'] or md.maintainer
        mnf['FileDescription'] = mnf['FileDescription'] or md.description
        mnf['FileVersion'] = mnf['FileVersion'] or md.version
        mnf['LegalCopyright'] = mnf['LegalCopyright'] or md.copyright
        mnf['ProductName'] = mnf['ProductName'] or md.name
        mnf['ProductVersion'] = mnf['ProductVersion'] or md.version

        for key, val in mnf.items():
            if not val:
                raise DistutilsSetupError(
                    "when 'build_signet' manifest=1, then "
                    "__%s__ must be set in %s" % (key, py_source))

        base = os.path.basename(py_source)
        exename = os.path.splitext(base)[0] + '.exe'

        rcfile = os.path.splitext(base)[0] + '.rc'
        rcfile = os.path.join(tgt_dir, rcfile)

        with open(rcfile, 'w') as fout:
            fout.write('1  ICON    "%s"\n' % mnf['Icon'])
            fout.write('1  VERSIONINFO\n')
            fout.write('FILEVERSION %s\n' % mnf['FileVersion'])
            fout.write('PRODUCTVERSION %s\n' % mnf['ProductVersion'])
            fout.write('FILEFLAGSMASK 0x17L\n')
            fout.write('FILEFLAGS 0x0L\n')
            fout.write('FILEOS 0x4L\n')
            fout.write('FILETYPE 0x1L\n')
            fout.write('FILESUBTYPE 0x0L\n')

            fout.write('BEGIN\n')
            fout.write('\tBLOCK "StringFileInfo"\n')
            fout.write('\tBEGIN\n')
            # U.S. English, Unicode
            fout.write('\t\tBLOCK "040904b0"\n')
            fout.write('\t\tBEGIN\n')
            fout.write('\t\t\tVALUE "Comments", "Created by signet loader"\n')
            fout.write('\t\t\tVALUE "CompanyName", "%s"\n' 
                    % mnf['CompanyName'])
            fout.write('\t\t\tVALUE "FileDescription", "%s"\n'
                    % mnf['FileDescription'])
            fout.write('\t\t\tVALUE "FileVersion", "%s"\n'
                    % mnf['FileVersion'])
            fout.write('\t\t\tVALUE "InternalName", "%s"\n'
                    % base)
            fout.write('\t\t\tVALUE "LegalCopyright", "%s"\n'
                    % mnf['LegalCopyright'])
            fout.write('\t\t\tVALUE "OriginalFileName", "%s"\n' 
                    % exename)
            fout.write('\t\t\tVALUE "ProductName", "%s"\n'
                    % mnf['ProductName'])
            fout.write('\t\t\tVALUE "ProductVersion", "%s"\n'
                    % mnf['ProductVersion'])
            fout.write('\t\tEND\n')
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

        log.info("building '%s' signet loader", ext.name)

        # Copy libary files from signet pakage to our intended
        # target directory

        tgt_dir = os.path.dirname(os.path.abspath(py_source))
        lib_sources = copy_lib_source(self.lib_root, tgt_dir)

        # Build list of source files we are compiling -> objs
        # (loader template + library code)

        loader_sources = [self.generate_loader_source(py_source)]
        for lib_source in lib_sources:
            if os.path.splitext(lib_source)[1] in self.loader_exts:
                loader_sources.append(lib_source)

        if self.manifest:
            loader_sources.append(self.generate_rcfile(py_source, tgt_dir))
                        
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
                    output_dir = self.build_temp,
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

