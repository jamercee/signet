the loader
==========

:mod:`signet <signet.command.build_signet>` comes with a default loader written
in c++, which you can replace if you choose.

The heirarchy for the loader is::

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

signet comes with two library modules, *sha1* and *verifytrust*.  The *sha1*
module provides an open source sha1 calculator. The *verifytrust* modules
provides windows pe verification.

How It works
------------

The default loader is a two pass system, with each pass creating a separate
instance of python.  The first pass performs verification, and the second pass
runs the target script. 

The two pass architecture was to eanble the loader to scan the modules in
alphabectical order (which is required for security). But importing modules
alphabetically does not allow modules to initialize themselves in the way their
designers may have intended. So after the first pass finishes validation, we
finalize the first pass python and initialize a new instance.

The heart of the loader is the *validate()* function. It iterates over the array
of embedded *signature* objects verifying each module's sha1 hash.
The *validate()* function makes use of python's 
`imp.find_module <https://docs.python.org/2/library/imp.html#imp.find_module>`_
infrastructure to locate the installed module's path (which is why we need to import
modules alphabetically).

Import Side-effects
+++++++++++++++++++

The two pass solution has one draw back, namely *import sidee-ffects*. First,
let me say **import side-effects are evil**. Imported code should stick to
strictly initializing its internal state. Imported code should NOT connect to
databases, the Internet, make changes to the filesystem nor should it output to
the console. Code that needs to do these things should wait until the user
specifically requests initialization.

If your code has import side-effects, then it's up to you to make sure the
side-effects are harmless during signet's first pass validation phase. At a
minimum, you need to ensure it's safe to run these side-effects twice.

Command Line Handling
---------------------
The loader supports several commandline options. They are:

   .. tabularcolumns:: |l|L

   +------------------+-------------------------------------------------+
   |  setting         | description                                     |
   +==================+=================================================+
   | *--SECURITYOFF*  | Disable security checks (provide no warnings).  |
   |                  | This option is available for those instances    |
   |                  | you need to run code you've modified and have   |
   |                  | not yet rebuilt the loader (typically during    |
   |                  | python debugging).                              |
   +------------------+-------------------------------------------------+
   | *--SECURITYWARN* | Scan script and dependencies for tampering and  |
   |                  | emit warnings, but run the script even if       |
   |                  | tampering is detected.                          |
   +------------------+-------------------------------------------------+
   | *--SECURITYMAX*  | Set tamper security to highest level (PE        |
   |                  | verification + hash check)                      |
   +------------------+-------------------------------------------------+

These settings will be passed through to your script to allow it to know it's
security context.

Environment Variables
---------------------
The loader sets the environment variable **SIGNET=1** before running the python
child script.  This is testable in your script, and is useful to know you were
launched by the signet loader.


