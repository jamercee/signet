signet default loader
=====================

:mod:`signet <signet.command.build_signet>` comes with a default loader written in c++. The
heirarchy for the loader is::

    signet.command/
    |-- lib/
    |   |-- sha1.cpp            -- sha1 calculator
    |   |-- sha1.h
    |   |-- verifytrust.cpp     -- windows pe verifier
    |   |-- verifytrust.h
    |
    |-- static/
    |   |-- app.ico             -- windows default icon
    |
    |-- templates/
    |   |-- loader.cpp          -- loader c++ code
    |   |-- loader.h

signet comes with two library modules, *sha1* and *verifytrust*.  The *sha1* module provides
an open source sha1 calculator. The *verifytrust* modules provides windows pe verification.

How It works
------------

The default loader is a two pass system, with each pass creating a separate
instance of python.  The first pass performs verification, and the second pass
runs the target script. 

The two pass architecture was to solve the fact that the loader wants to scan
the modules in alphabectical order (which is required for security). But
importing modules alphabetically does not allow modules to initialize
themselves in the way their designers may have intended. So after the first
pass finishes validation, we finalize the fist pass python and initialize an
new instance.

The heart of the loader is the *validate()* function. It iterates over the array
of *signature* objects embedded in the loader verifying each module's sha1 hash.
The *validate()* function makes use of python's 
`imp.find_module <https://docs.python.org/2/library/imp.html#imp.find_module>`_
infrastructure to locate the installed module's path (which is why we need to import
modules alphabetically).

Import Side-effects
+++++++++++++++++++

The two pass solution has one draw back, namely *import sidee-ffects*. First, let me
say **import sideeffects are evil** ! Imported code should stick to strictly initializing
its internal state. Imported code should NOT connect to databases, the Internet, make
changes to the filesystem nor should it output to the console. Code that needs to do
these things should wait until the user specifically requests initialization.

If your code has import side-effects, then it's up to you to make sure the side-effects
are harmless during signet's pass one validation phase. At a minimum, you need to ensure
it's safe to run these side-effects twice.

Command Line Handling
---------------------
The loader supports several commandline options. They are:

   .. tabularcolumns:: |l|L

   +----------------+---------------------------------------+-------------------------------+
   | argument name  | value                                 | type                          |
   +================+=======================================+===============================+
   | --SECURITYOFF  | Disable all seurity checks. Provide no warnings
   | --SECURITYWARN | Scan script and dependencies for tampering and emit warnings, but run
                      the script even if tampering is detected.

   | *template*     | The path to a custom loader           | a string                      |
   |                | to override the default loader        |                               |
   |                | provided by signet.                   |                               |
Explain loader command line '--SECURITY*', and pass through

Environment Variables
---------------------
Notify 'SIGNET=1' environment


