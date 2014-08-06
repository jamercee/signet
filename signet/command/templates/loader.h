
struct Signature {				/* module signatures */
	const char* hexdigest;
	const char* mod_name;
	};

// ---------------------------------------------------------------------------
// REPLACED GLOBALS (replaced by signet.command.build_signet)
//
// SCRIPT	- will be replaced with the script name we are loading.
// SIGS   	- module signatures {{"hexdigest","module-name"},...}
// TAMPER 	- controls how tampering is handled
//	3  - maximum, SCRIPT & dependency check + require signed binary
//		 (windows only)
//	2  - normal, SCRIPT & dependency check
//	1  - warn only, report tampering, but continue anyway
//	0  - disable tamper checks
// ---------------------------------------------------------------------------

const char SCRIPT[] = "";
const Signature SIGS[] = {{NULL,NULL}};
int TAMPER = 2;


