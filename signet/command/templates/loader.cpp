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
		/* steal reference to ptr */
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


PyObject* FndFx;				/* import imp; FndFx = imp.find_module */
PyObject* LoadFx;				/* import imp; LoadFx = imp.load_module */

std::vector<PyObject*> Imports;	/* list of imported modules */

// Enable debug logging during build by passing extra args, eg:
// 		python setup.py build_signet --define LOGGING=10
//
// Levels are adapted from python's logging levels:
// https://docs.python.org/2/library/logging.html#loggin-levels

const int LOG_CRITICAL = 50;
const int LOG_ERROR = 40;
const int LOG_WARNING = 30;
const int LOG_INFO = 20;
const int LOG_DEBUG = 10;
const int LOG_NOTSET = 0;

#ifdef LOGGING
int Debug = LOGGING;
#else
int Debug = LOG_WARNING;
#endif


// ---------------------------------------------------------------------------
// FUNCTIONS
// ---------------------------------------------------------------------------

/* return the directory name of path */

std::string dirname(const char path[]) {

	std::string dname = path;
	std::size_t slash = dname.find_last_of("/\\");

	if (slash == std::string::npos)
		return std::string("");

	return dname.substr(0, slash+1);
	}

/* return the base name of pathname path */

std::string basename(const char path[]) {

	std::string pathname = path;
	std::size_t slash = pathname.find_last_of("/\\");
	if (slash != std::string::npos)
		pathname = pathname.substr(slash+1);

	return pathname;
	}

/* return 1 if filename is a file, otherwise 0 */

int isfile(const char filename[]) {

	struct STAT st;
	if (STAT(filename, &st) != 0) {
		return 0;
		}
	return S_ISREG(st.st_mode) ? 1 : 0;
	}

/* return 1 if pathname is a dir, otherwise 0 */

int isdir(const char pathname[]) {

	struct STAT st;
	if (STAT(pathname, &st) != 0) {
		return 0;
		}
	return S_ISDIR(st.st_mode) ? 1 : 0;
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

void log(int level, const char fmt[], ...) {

	/* level too low? */

	if (level < Debug)
		return;

	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	}

/* accept python list, return printable string */

std::string list_asstring(PyObject* py_list) {

	/* validate the py_list */

	if (py_list == Py_None)
		return std::string("");
	if (!PyList_Check(py_list))
			return std::string("py_list not a list");
	if (PyList_Size(py_list) < 1)
			return std::string("[]");

	/* iterate py_list, build response */

	std::string rsp = "[";
	for(int i = 0; i < PyList_Size(py_list); i++) {

		PyObject* py_item = PyList_GetItem(py_list, i);
		const char* item;
		if (PyString_Check(py_item))
			item = PyString_AsString(py_item);
		else
			item = "(not a string type)";

		/* add item to response */

		if (rsp.length() > 1)
			rsp += ", ";
		rsp += item;
		}

	return rsp + "]";
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

int find_module(const char mod_name[], PyObject* paths, PyObject** file, 
		PyObject** pathname, PyObject** description) {

	PyPtr results( PyObject_CallFunction(FndFx, (char*)"sO", mod_name, paths) );
	if (results.get() == NULL) {
		if (PyErr_Occurred() && PyErr_ExceptionMatches(PyExc_ImportError)) {
			fprintf(stderr, "warning: could not find %s\n", mod_name);
			}
		else{
			python_err("unexpected exception from imp.find_module()");
			}
		return -1;
		}

	if (!PyArg_ParseTuple(results.get(), "OOO", file, pathname, description)) {
		python_err("error retrieving imp.find_module results");
		return -1;
		}

	Py_INCREF(*file);
	Py_INCREF(*pathname);
	Py_INCREF(*description);

	return 0;
	}

/* invoke imp.load_module() */

int load_module(const char mod_name[], PyObject* py_file, PyObject* py_pathname, 
		PyObject* py_description) {

	PyPtr results( PyObject_CallFunction(LoadFx, (char*)"sOOO", mod_name,
				py_file, py_pathname, py_description) );
	if (results.get() == NULL) {
		python_err("error loading module %s\n", mod_name);
		return -1;
		}

	if (py_file != Py_None) {
		PyObject_CallMethod(py_file, (char*)"close", NULL);
		}

	return 0;
	}

/* retrieve a module's full filename (ie: M.__file__) */

int get_module_path(const char mod_name[], std::string& pathname) {

	/* This module uses imp.find_module() to locate a module's pathname. Because
	 * find_module does not handle heirarchical module names (names containing
	 * dots), in order to find P.M, we use find_module() to locate P, and
	 * import P, then use find_module with the path argument set to P.__path__
	 */

	PyPtr py_parent_path(Py_None);		/* last parent we encountered (as list) */

	PyObject* py_file = NULL;
	PyObject* py_pathname = NULL;
	PyObject* py_description = NULL;

	int rc = 0;

	log(LOG_DEBUG, ">>> get_module_path %s\n", mod_name);

	/* Iterate module heirarchy */

	const char* mp, *dot;
	for(mp = dot = mod_name; (dot = strchr(dot, '.')) != NULL; dot++) {

		/* find P */

		int plen = dot - mp;
		std::string parent(mp, plen);

		log(LOG_DEBUG, "\tfind M %s, P.__path__ %s\n", 
				parent.c_str(), list_asstring(py_parent_path.get()).c_str());

		if (find_module(parent.c_str(), py_parent_path.get(), &py_file, 
					&py_pathname, &py_description)) {
			rc = -1;
			goto _return;
			}

		/* load_module P.M */

		std::string heirarchy = std::string(mod_name, dot - mod_name);
		log(LOG_DEBUG, "\tload_module P.M %s\n", heirarchy.c_str());

		if (load_module(heirarchy.c_str(), py_file, py_pathname, 
					py_description)) {
			rc = -1;
			goto _return;
			}

		/* save P.__path__ */

		log(LOG_DEBUG, "\tsave P.__path__ %s\n", PyString_AsString(py_pathname));

		PyObject* py_plist = PyList_New(0);
		if (py_plist == NULL) {
			python_err("out-of-memory in get_module_path()\n");
			rc = -1;
			goto _return;
			}
		if (PyList_Append(py_plist, py_pathname)) {
			python_err("append to list error in get_module_path()\n");
			Py_CLEAR(py_plist);
			rc = -1;
			goto _return;
			}

		/* steals the reference */

		py_parent_path.chg(py_plist);
		py_plist = NULL;

		Py_CLEAR(py_file);
		Py_CLEAR(py_description);

		/* move to next module (if one exists) */

		mp = dot + 1;
		}

	/* seek to last module is heirarchy */

	dot = strrchr(mod_name, '.');
	if (dot == NULL)
		dot = mod_name;
	else
		dot += 1;

	/* find M */

	log(LOG_DEBUG, "\tlast find M %s, P.__path__ %s\n\n", 
			dot, list_asstring(py_parent_path.get()).c_str());

	if (find_module(dot, py_parent_path.get(), &py_file, &py_pathname, 
				&py_description)) {
		rc = -1;
		goto _return;
		}

	pathname = PyString_AsString(py_pathname);

	/* if dir, append package __init__.py */

	if (isdir(pathname.c_str())) {
		pathname += "/__init__.py";
		}

_return:
	Py_XDECREF(py_file);
	Py_XDECREF(py_pathname);
	Py_XDECREF(py_description);

	return rc;
	}

/* compare two sha1 hexdigests for equality */

int sha1equal(const char* h1, const char* h2) {
	for(const char* ep = h1 + 40; h1 < ep; h1++, h2++) {
		if (tolower(*h1) != tolower(*h2))
			return 0;
		}
	return 1;
	}

int validate() {

	/* we need to the module name of SCRIPT (so we can skip importing) */

	std::string my_mod = basename(SCRIPT);
	std::size_t dot = my_mod.find_last_of(".");
	if (dot != std::string::npos)
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

	/* LoadFx = imp.load_module */

	LoadFx = PyObject_GetAttrString(imp_mod, "load_module");
	if (FndFx == NULL) {
		python_err("error linking with imp.load_module");
		return -1;
		}

	std::string ignore;
	get_module_path("logging", ignore);

	/* iterate signatures, compare them to installed editions */

	size_t max = sizeof(SIGS) / sizeof(SIGS[0]);

	for(size_t i=0; i < max; i++) {

		const Signature* sp = &SIGS[i];

		std::string pathname;
		if (get_module_path(sp->mod_name, pathname))
			continue;

		log(LOG_INFO, ">>> Found module %s -> %s\n", sp->mod_name, pathname.c_str());

		const char* hexdigest = sha1hexdigest(pathname.c_str());
		if (hexdigest != NULL && !sha1equal(hexdigest, sp->hexdigest)) {
			fprintf(stderr, "SECURITY VIOLATION: '%s' has been tampered with!\n", pathname.c_str());
			if (TAMPER >= 2)
				return -1;
			}

		/* do not import SCRIPT */

		if (strcmp(sp->mod_name, my_mod.c_str()) == 0)
			continue;

		/* import the certified module */

		PyObject* py_import = PyImport_ImportModule(sp->mod_name);
		if (py_import != NULL) {
			Imports.push_back(py_import);
			}

		/* only log import errors if debug was select during build */

		else if (Debug <= LOG_DEBUG) {
			python_err("unable to import certified module %s\n", sp->mod_name);
			}
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
			TAMPER = 0;
			fprintf(stderr, "SECURITY DISABLED\n");
			}

		else if (strcmp(argv[i], "--SECURITYWARN") == 0) {
			TAMPER = 1;
			fprintf(stderr, "SECURITY DISABLED\n");
			}

		else if (strcmp(argv[i], "--SECURITYMAX") == 0) {
			TAMPER = 3;
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

/* optionally initialize virtualenv */

int initialize_virtualenv() {

	/* is vritualenv active? */

	const char* venv = getenv("VIRTUAL_ENV");
	if (venv == NULL)
		return 0;

	/* look for activate_this.py, posix first, then windows */

	std::string activate_this = venv;
	activate_this += "/bin/activate_this.py";

	if (!isfile(activate_this.c_str())) {
		activate_this = venv;
		activate_this += "/Scripts/activate_this.py";
		}

	if (!isfile(activate_this.c_str())) {
		return 0;
		}

	/* globals = { '__file__': 'path/to/activate_this.py' } */

	PyPtr globals( PyDict_New() );
	if (globals.get() == NULL) {
		python_err("unable to create globals dict()\n");
		return -1;
		}
	PyPtr py_activate_this( PyString_FromString(activate_this.c_str()) );
	if (py_activate_this.get() == NULL) {
		python_err("unable to initialize globals dict()\n");
		return -1;
		}

	if (PyDict_SetItemString(globals.get(), "__file__", py_activate_this.get())) {
		python_err("unable to assign to globals dict()\n");
		return -1;
		}

	/* open activate_this */

	FILE* fin = fopen(activate_this.c_str(), "r");
	if (!fin) {
		fprintf(stderr, "unable to open virtualenv script %s: %s\n", 
				activate_this.c_str(), strerror(errno));
		return -1;
		}

	PyObject* execfile = PyRun_File(fin, activate_this.c_str(), 
							Py_file_input, globals.get(), NULL);
	if (execfile == NULL) {
		python_err("failed execfile()\n");
		fclose(fin);
		return -1;
		}
	Imports.push_back(execfile);

	return 0;
	}

/* Initialize python, 
 * Validate module security
 * Cleanup
 */

int run(int argc, char* argv[]) {

	/* initialize python */

	Py_SetProgramName((char*)SCRIPT);

	Py_Initialize();

	/* parse command line */

	if (parse_options(argc, argv)) {
		Py_Finalize();
		return -1;
		}

	/* initialize virtualenv (if present) */

	if (initialize_virtualenv())
		return -1;

	int rc = 0;

	/* tamper protection set to warn or max? */

	if (TAMPER == 1 || TAMPER == 3) {

		/* retrieve fully qualified path of executable */

		std::string exename;
		rc = get_executable(argv, exename);

		/* validate binary signature */

		if (rc == 0) {
			int trusted = verify_trust(exename.c_str(), 1);

			/* if untrusted, and max protection, exit */

			if (trusted < 1 && TAMPER == 3)
				rc = -1;
			}
		}

	/* validate module security */

	if (rc == 0 && TAMPER >= 1)
		rc = validate();

	/* release references */

	for(std::vector<PyObject*>::iterator it = Imports.begin();
			it != Imports.end(); it++) {
		if (*it != NULL)
			Py_XDECREF(*it);
		}

	if (FndFx != NULL) {
		Py_XDECREF(FndFx);
		}
	if (LoadFx != NULL) {
		Py_XDECREF(LoadFx);
		}

	Py_Finalize();

	return rc;
	}

int main(int argc, char* argv[]) {

	log(LOG_INFO, ">>> Validation step\n");

	if (run(argc, argv))
		return -1;

	log(LOG_INFO, ">>> Run SCRIPT %s\n", SCRIPT);

	/* initialize python */

	Py_SetProgramName((char*)SCRIPT);

	Py_Initialize();

	/* parse command line */

	if (parse_options(argc, argv)) {
		Py_Finalize();
		return -1;
		}

	/* initialize virtualenv (if present) */

	if (initialize_virtualenv())
		return -1;

	int rc = 0;

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

	Py_Finalize();

	return rc;
	}

