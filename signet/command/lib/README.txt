This direcotye contains library code used by signet. Each
executable will receive a static copy of this code. The following
library modules are provided:

sha1 - Simple sha1 calculation library. The presence of this means 
        we don't need to require the target environment to have openssl.

verifytrust - A Windows only library for performing PE validation. PE
        validation means to read an executable to validate it's
        embeded code signing certificate (if it has one).

