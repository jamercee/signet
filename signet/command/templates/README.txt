This directory contains the signet secure loader template. It will be
customized by signet.commands.build_ext during the build phase.

If you provide you're own loader template, you'll need the following three
declarations:

    const char SCRIPT = "name-of-script";
    const Signature SIGS = { {"hexdigest", "modname"},...};
    int TamperProtection = 2;

Declarations must start in column 1 (don't get too frisky with whitespace
formatting as the parser logic is quite simple).

