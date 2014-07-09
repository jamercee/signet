#!/usr/bin/env python2.7
## \file command.py
# \brief Create signmet loader
# \date January 1st, 2014
# \copyright Copyright(c), 2014, Carroll-Net, Inc.
# \copyright All Rights Reserved.
r"""Create sigmet loader

This process will scan a python module for dependencies, and for each it will
pre-calculate it's sha1 hash. The hash signatures will then be written into
a custom python loader, that on startup will check the installed dependencies
to confirm they match their pre-calculated values.

Basic template (which performs no tamper testing)

    struct Signature {
       const char* hexdigest;
       const char* mod_name;
       };
    /* the following three globals are replaced */
    const char SCRIPT[] = "";
    const Signature SIGS[] = {};
    int TamperProtection = 2;
    int main() {
       return 0;
       }

Copyright(c), 2014, Carroll-Net, Inc.
All Rights Reserved"""

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
    r"""return list of 2-tuples [(hexdigest, modulename), ...]"""

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
    r"""create SIGS c++ declaration"""

    sigs_decl = StringIO.StringIO()
    sigs_decl.write('const Signature SIGS[] = {\n')

    for sha1, mod in module_signatures(py_source):
        sigs_decl.write('\t{"%s", "%s"},\n' % (sha1, mod))
    sigs_decl.write('\t};\n')

    return sigs_decl.getvalue()

def copy_lib_source(lib_root, tgt_root):
    r"""copy lib(s) to tgt_root directory"""

    libs = []

    for root, _, files in os.walk(lib_root):
        for fname in files:
            src_fname = os.path.join(root, fname)
            shutil.copy(src_fname, tgt_root)
            libs.append(fname)

    return libs

class build_signet(_build_ext):
    r"""build signet loader"""

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
        ])

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
        r"""set default values"""
        _build_ext.initialize_options(self)

        self.template = None
        self.cflags = []
        self.ldflags = []
        self.detection = None

    def finalize_options(self):
        r"""set final values"""

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

    def generate_loader_source(self, py_source):
        r"""generate loader source code"""

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

    def build_extension(self, ext):
        r"""perform the build action(s)"""

        py_sources = ext.sources

        if py_sources is None or not isinstance(py_sources, (list, tuple)):
            raise DistutilsSetupError(
                "in 'ext_modules' options (extension '%s'), "
                "'sources' must be present and must be "
                "a list of source filenames" % ext.name)

        for py_source in list(py_sources):

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

