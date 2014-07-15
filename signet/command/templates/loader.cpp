#include <Python.h>
#include <stdarg.h>
#include <stdio.h>

#include <string>
#include <vector>

#include "sha1.h"
#include "verifytrust.h"


// ---------------------------------------------------------------------------
// MACROS 
// ---------------------------------------------------------------------------

#ifdef _MSC_VER
#define STAT _stat
#else
#define STAT stat
#endif

// ---------------------------------------------------------------------------
// TYPES 
// ---------------------------------------------------------------------------

class PyPtr {					/* pythonic "smart" pointers */

private:
	PyObject* o;

public:
	PyPtr(PyObject* ptr) : o(ptr) {}
	~PyPtr() { 
		Py_XDECREF(o); 
		}
	PyObject* get() { 
		return o; 
		}
	void chg(PyObject* ptr) {
		Py_XDECREF(o);
		o = ptr;
		}
	};

struct Signature {				/* module signatures */
	const char* hexdigest;
	const char* mod_name;
	};

// ---------------------------------------------------------------------------
// REPLACED GLOBALS (replaced by signet.command.build_signet)
//
// SCRIPT	- will be replaced with the script name we are loading.
// SIGS   	- module signatures {{"hexdigest","module-name"},...}
// TamperProtection - controls how tampering is handled
//	3  - maximum, SCRIPT & dependency check + require signed binary
//		 (windows only)
//	2  - normal, SCRIPT & dependency check
//	1  - warn only, report tampering, but continue anyway
//	0  - disable tamper checks
// ---------------------------------------------------------------------------

const char SCRIPT[] = "";
const Signature SIGS[] = {};
int TamperProtection = 2;


PyObject* FndFx;				/* import imp; FndFx = imp.find_module */
std::vector<PyObject*> Imports;	/* list of imported modules */

// ---------------------------------------------------------------------------
// FUNCTIONS
// ---------------------------------------------------------------------------

/* return the directory name of path */

std::string dirname(const char path[]) {

	std::string dname = path;
	int slash = dname.find_last_of("/\\");

	if (slash == std::string::npos)
		return std::string("");

	return dname.substr(0, slash+1);
	}

/* return the base name of pathname path */

std::string basename(const char path[]) {

	std::string pathname = path;
	int slash = pathname.find_last_of("/\\");
	if (slash != std::string::npos)
		pathname = pathname.substr(slash+1);

	return pathname;
	}

/* log python error to stderr */

void python_err(const char fmt[], ...) {

	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	if (PyErr_Occurred()) {
		PyErr_Print();
		return;
		}
	fprintf(stderr, "No python error ocurred.\n");
	}

/* Calculate sha1 file hash, return hexdigest as ascii string (lowercase) */

char* sha1hexdigest(const char fname[]) {

	Sha1Context ctx;
    Sha1Initialise(&ctx);

	FILE* fin = fopen(fname, "rb");
	if (fin == NULL) {
		fprintf(stderr, "unable to open %s:%s\n", fname, strerror(errno));
		return NULL;
		}

	char buf[64*1024];
	size_t rdsz;

	while((rdsz=fread(buf, 1, sizeof(buf), fin)) > 0) {
		Sha1Update(&ctx, buf, rdsz);
		}

	fclose(fin);

	SHA1_HASH digest;
	Sha1Finalise(&ctx, &digest);

	static char hexdigest[40+1];
	char* hp = hexdigest;

	unsigned char* dp = digest.bytes;
	unsigned char* ep = dp + sizeof(digest);

	while(dp < ep) {
		hp += sprintf(hp, "%02x", *dp++);
		}
	return hexdigest;
	}

/* invoke imp.find_module() */

int find_module(const char mod_name[], PyObject* paths, std::string& pathname) {

	PyPtr results( PyObject_CallFunction(FndFx, "sO", mod_name, paths) );
	if (results.get() == NULL) {
		if (PyErr_Occurred() && PyErr_ExceptionMatches(PyExc_ImportError)) {
			fprintf(stderr, "warning: could not find %s\n", mod_name);
			}
		else{
			python_err("unexpected exception from imp.find_module()");
			}
		return -1;
		}

	PyObject* file, *descr;
	char* _pathname;

	if (!PyArg_ParseTuple(results.get(), "OsO", &file, &_pathname, &descr)) {
		python_err("error retrieving imp.find_module results");
		return -1;
		}

	if (file != Py_None) {
		PyObject_CallMethod(file, "close", NULL);
		}

	pathname = _pathname;

	return 0;
	}

/* retrieve a module's full filename (ie: M.__file__) */

int get_module_path(const char mod_name[], std::string& pathname) {

	/* This module uses imp.find_module() to locate a module's pathname. Because
	 * find_module does not handle heirarchical module names (names containing
	 * dots), in order to find P.M, we use find_module() to locate P, and
	 * import P, then use find_module with the path argument set to P.__path__
	 */

	PyPtr py_parent_paths(Py_None);		/* last parent we encountered (as list) */

	/* Iterate module heirarchy */

	const char* dot;
	for(dot = mod_name; (dot = strchr(dot, '.')) != NULL; dot++) {

		/* find P */

		int plen = dot - mod_name;
		std::string parent(mod_name, plen);

		if (find_module(parent.c_str(), py_parent_paths.get(), pathname)) {
			return -1;
			}

		/* import P */

		PyObject* py_parent = PyImport_ImportModule(parent.c_str());
		if (py_parent == NULL) {
			python_err("error importing parent %s", parent.c_str());
			return -1;
			}
		Imports.push_back(py_parent);

		/* save P.__path__ */

		PyObject* py_path = PyObject_GetAttrString(py_parent, "__path__");
		if (py_path != NULL) {
			py_parent_paths.chg( py_path );
			}
		}

	/* seek to last module is heirarchy */

	dot = strrchr(mod_name, '.');
	if (dot == NULL)
		dot = mod_name;
	else
		dot += 1;

	/* find M */

	if (find_module(dot, py_parent_paths.get(), pathname)) {
		return -1;
		}

	/* if dir, append package __init__.py */

	struct STAT st;
	if (STAT(pathname.c_str(), &st) != 0) {
		fprintf(stderr, "stat %s: %s\n", pathname.c_str(), strerror(errno));
		return -1;
		}
	if (S_ISDIR(st.st_mode)) {
		pathname += "/__init__.py";
		}

	return 0;
	}

int validate() {

	/* we need to the module name of SCRIPT (so we can skip importing) */

	std::string my_mod = basename(SCRIPT);
	int dot = my_mod.find_last_of(".");
	if (dot != std::string.npos)
		my_mod = my_mod.substr(0, dot);

	/* import imp */

	PyObject* imp_mod = PyImport_ImportModule("imp");
	if (imp_mod == NULL) {
		python_err("error importing imp");
		return -1;
		}
	Imports.push_back(imp_mod);

	/* FndFx = imp.find_module */

	FndFx = PyObject_GetAttrString(imp_mod, "find_module");
	if (FndFx == NULL) {
		python_err("error linking with imp.find_module");
		return -1;
		}

	/* iterate signatures, compare them to installed editions */

	size_t max = sizeof(SIGS) / sizeof(SIGS[0]);

	for(size_t i=0; i < max; i++) {

		const Signature* sp = &SIGS[i];

		std::string pathname;
		if (get_module_path(sp->mod_name, pathname))
			continue;

		const char* hexdigest = sha1hexdigest(pathname.c_str());
		if (hexdigest != NULL && strcmpi(hexdigest, sp->hexdigest) != 0) {
			fprintf(stderr, "SECURITY VIOLATION: '%s' has been tampered with!\n", pathname.c_str());
			if (TamperProtection >= 2)
				return -1;
			}

		/* do not import SCRIPT */

		if (strcmp(sp->mod_name, my_mod.c_str()) == 0)
			continue;

		/* import the certified module */

		PyObject* py_import = PyImport_ImportModule(sp->mod_name);
		if (py_import == NULL) {
			python_err("unable to import certified module %s\n", sp->mod_name);
			return -1;
			}
		Imports.push_back(py_import);
		}

	return 0;
	}

/* extract our opts, pass the rest to python */

int parse_options(int argc, char* argv[]) {

	char** args = new char*[argc];
	int args_used = 1;

	args[0] = strdup(SCRIPT);

	for(int i = 1; i < argc; i++) {

		if (strcmp(argv[i], "--SECURITYOFF") == 0) {
			TamperProtection = 0;
			fprintf(stderr, "SECURITY DISABLED\n");
			}

		else if (strcmp(argv[i], "--SECURITYWARN") == 0) {
			TamperProtection = 1;
			fprintf(stderr, "SECURITY DISABLED\n");
			}

		else if (strcmp(argv[i], "--SECURITYMAX") == 0) {
			TamperProtection = 3;
			fprintf(stderr, "SECURITY MAXIMUM Enabled\n");
			}

		else if (strncmp(argv[i], "--SECURITY", 10) == 0) {
			fprintf(stderr, "error: invalid setting, "
					"valid choices are SECURITY(OFF|WARN|MAX)\n");
			return -1;
			}

		else{
			args[args_used++] = strdup(argv[i]);
			}
		}

	PySys_SetArgv(args_used, args);

	return 0;
	}

/* Initialize python, 
 * Validate module security
 * Run SCRIPT
 * Cleanup
 */

int main(int argc, char* argv[]) {

	/* initialize python */

	Py_SetProgramName((char*)SCRIPT);

	Py_Initialize();

	/* parse command line */

	if (parse_options(argc, argv)) {
		Py_Finalize();
		return -1;
		}

	int rc = 0;

	/* tamper protection set to warn or max? */

	if (TamperProtection == 1 || TamperProtection == 3) {

		/* validate binary signature */

		int trusted = verify_trust(argv[0], 1);

		/* if untrusted, and max protection, exit */

		if (trusted < 1 && TamperProtection == 3)
			rc = -1;
		}

	/* validate module security */

	if (rc == 0 && TamperProtection >= 1)
		rc = validate();

	/* run successfully validated script */

	if (rc == 0) {
		std::string script = dirname(argv[0]) + SCRIPT;
		FILE* fin = fopen(script.c_str(), "r");
		if (fin) {
			rc = PyRun_SimpleFileEx(fin, SCRIPT, 1);

			/* catch and report exception */

			if (rc && PyErr_Occurred())
				PyErr_Print();
			}
		else{
			fprintf(stderr, "could not open %s", script.c_str());
			rc = -1;
			}
		}

	/* release references */

	for(std::vector<PyObject*>::iterator it = Imports.begin();
			it != Imports.end(); it++) {
		if (*it != NULL)
			Py_XDECREF(*it);
		}

	if (FndFx != NULL) {
		Py_XDECREF(FndFx);
		}

	Py_Finalize();

	return rc;
	}

