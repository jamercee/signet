
struct Signature {				/* module signatures */
	const char* hexdigest;
	const char* modname;
    const char* filename;
	};

// ---------------------------------------------------------------------------
// REPLACED GLOBALS (replaced by signet.command.build_signet)
//
// SCRIPT	- will be replaced with the script name we are loading.
// SCRIPT_HEXDIGEST - will be replaced with SHA1 of script
// SIGS   	- module signatures {{"hexdigest","modulename","filename"},...}
// TAMPER 	- controls how tampering is handled
//	3  - maximum, SCRIPT & dependency check + require signed binary
//		 (windows only)
//	2  - normal, SCRIPT & dependency check
//	1  - warn only, report tampering, but continue anyway
//	0  - disable tamper checks
// ---------------------------------------------------------------------------

const char SCRIPT[] = "";
const char SCRIPT_HEXDIGEST[] = "";
const Signature SIGS[] = {{NULL,NULL,NULL}};
int TAMPER = 2;


