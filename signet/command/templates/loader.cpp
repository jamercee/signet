#include <Python.h>
#include <stdarg.h>
#include <stdio.h>

#include <algorithm>
#include <string>
#include <sstream>
#include <vector>

#include "loader.h"
#include "sha1.h"
#include "verifytrust.h"


#ifdef _MSC_VER
#include <Windows.h>
#else
#include <dirent.h>
#endif

using namespace std;

// ---------------------------------------------------------------------------
// MACROS 
// ---------------------------------------------------------------------------

#ifdef _MSC_VER
#define STAT _stat
#define SEP "\\"
#else
#define STAT stat
#define SEP "/"
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

/* log formatted message if Debug >= level */

void log(int level, const char fmt[], ...) {

	if (level < Debug)
		return;

	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	}

/* return the directory name of path */

string _dirname(const char path[]) {

	string dname = path;
	size_t slash = dname.find_last_of("/\\");

	if (slash == string::npos)
		return string("");

	return dname.substr(0, slash+1);
	}

/* return the base name of pathname path */

string _basename(const char path[]) {

	string pathname = path;
	size_t slash = pathname.find_last_of("/\\");
	if (slash != string::npos)
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

/* return 1 if *str* ends with the string *end* (str.endswith()) */

int endswith(const string& str, const string& end) {
    if (end.size() > end.size())
        return false;
    return equal(end.rbegin(), end.rend(), str.rbegin());
    }

/* return the list of strings in *str* seperated by *delim* (str.split()) */

vector<string> split(const string str, const char delim) {
    stringstream ss(str);
    string item;
    vector<string> tokens;
    while(getline(ss, item, delim)) {
        tokens.push_back(item);
        }
    if (tokens.size() == 0)
        tokens.push_back(str);
    return tokens;
    }

/* return the list of files in *path* (os.listdir()) */

vector<string> listdir(const string& path) {
    vector<string> files;
#ifdef _MSC_VER
    string search(path);
    if (!endswith(search, SEP)) {
        search += SEP;
        }
    search += "*";

    HANDLE fnd;
    WIN32_FIND_DATA fdata;
    if ((fnd = ::FindFirstFile(search.c_str(), &fdata)) 
            != INVALID_HANDLE_VALUE) {
        do {
            files.push_back(fdata.cFileName);
            } while(::FindNextFile(fnd, &fdata));
        ::FindClose(fnd);
        }
#else
    DIR* dirp = opendir(path.c_str());
    if (!dirp) {
        log(LOG_ERROR, "error opening dir %s: %d\n", path.c_str(), errno);
        return files;
        }
    struct dirent* dent;
    while((dirent = readdir(dirp)) != NULL) {
        files.push_back(dent->d_name);
        }
    closedir(dirp);
#endif
    return files;
    }

/* Calculate sha1 file hash, return hexdigest as ascii string (lowercase) */

char* sha1hexdigest(const char fname[]) {

	Sha1Context ctx;
	Sha1Initialise(&ctx);

	FILE* fin = fopen(fname, "rb");
	if (fin == NULL) {
		log(LOG_ERROR, "sha1hexdigest() unable to open %s:%s\n", 
				fname, strerror(errno));
		return NULL;
		}

	char buf[64 * 1024];
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

/* compare two sha1 hexdigests for equality, return 1 if equal */

int sha1equal(const char* h1, const char* h2) {
	for(const char* ep = h1 + 40; h1 < ep; h1++, h2++) {
		if (tolower(*h1) != tolower(*h2))
			return 0;
		}
	return 1;
	}

/* Search *paths* for a sub-directory *modname* or a file *fname*, and return
 * the match in *found_path*. Returns 1 if matched, 0 otherwise.  *found_path*
 * will be the fully qualified path of the match */

int find_module(const string& modname, const string& fname, 
        const vector<string>& paths, string& found_path) {

	for(vector<string>::const_iterator it = paths.begin();
			it != paths.end(); it++) {
        if (!isdir((*it).c_str())) {
            continue;
            }
        vector<string> files = listdir(*it);

        if (find(files.begin(), files.end(), modname) != files.end()) {
            found_path = *it;
            found_path += SEP;
            found_path += modname;
            return 1;
            }
        else if (find(files.begin(), files.end(), fname) != files.end()) {
            found_path = *it;
            found_path += SEP;
            found_path += fname;
            return 1;
            }
        }
    return 0;
    }

int find_module_path(const string& modname, const string& filename, 
        const vector<string>& paths, string& pathname) {

    vector<string> localpaths = paths;
    vector<string> modparts = split(modname, '.');
	for(vector<string>::iterator it = modparts.begin();
			it != modparts.end(); it++) {
        string found_path;
        if (!find_module(*it, filename, localpaths, found_path))
            return 0;
        if (isfile(found_path.c_str()))
            return 1;
        // we've found a subdir matching our modpart
        localpaths.clear();
        localpaths.push_back(found_path);
        }
    return 0;
    }

/* perform validation (the heart of this code) */

int validate(const string script_path) {

    /* store sys.paths in vector of strings */

	PyPtr sys_mod( PyImport_ImportModule("sys") );
	if (sys_mod.get() == NULL) {
		python_err("error importing sys");
		return -1;
		}
    PyPtr pypath( PyObject_GetAttrString(sys_mod.get(), "path") );
    if (pypath.get() == NULL) {
		python_err("'sys' module has no attribute 'path'");
        return -1;
        }
    vector<string> paths;
	for(Py_ssize_t i = 0; i < PyList_Size(pypath.get()); i++) {
		PyObject* py_item = PyList_GetItem(pypath.get(), i);
        paths.push_back(PyString_AsString(py_item));
        }

	/* iterate signatures, compare them to installed editions */

    const Signature* sp = SIGS;

    for(;sp->modname != NULL; sp++) {

		string pathname;
		if (find_module_path(sp->modname, sp->filename, paths, pathname))
			continue;

		log(LOG_INFO, ">>> Found module %s -> %s\n", sp->modname, pathname.c_str());

		const char* hexdigest = sha1hexdigest(pathname.c_str());
		if (hexdigest != NULL && !sha1equal(hexdigest, sp->hexdigest)) {
			log(LOG_ERROR, "SECURITY VIOLATION: '%s' has been tampered with!\n", 
					pathname.c_str());
            log(LOG_DEBUG, "expected %s, detected %s\n", 
                    sp->hexdigest, hexdigest);
			if (TAMPER >= 2)
				return -1;
			}
		}

    /* check script */

    const char* script_digest = sha1hexdigest(script_path.c_str());
    if (script_digest != NULL && !sha1equal(script_digest, SCRIPT_HEXDIGEST)) {
        log(LOG_ERROR, "SECURITY VIOLATION: '%s' has been tampered with!\n", 
                script_path.c_str());
        log(LOG_DEBUG, "expected %s, detected %s\n", 
                SCRIPT_HEXDIGEST, script_digest);
        if (TAMPER >= 2)
            return -1;
        }

	return 0;
	}

/* search for our opts, pass ALL python */

int parse_options(int argc, char* argv[], const char* script) {

	char** args = new char*[argc];
	int args_used = 1;

	args[0] = strdup(script);

	for(int i = 1; i < argc; i++) {

		if (strcmp(argv[i], "--SECURITYOFF") == 0) {
			TAMPER = 0;
			log(LOG_WARNING, "SECURITY DISABLED\n");
			}

		else if (strcmp(argv[i], "--SECURITYWARN") == 0) {
			TAMPER = 1;
			log(LOG_WARNING, "SECURITY DISABLED\n");
			}

		else if (strcmp(argv[i], "--SECURITYMAX") == 0) {
			TAMPER = 3;
			log(LOG_WARNING, "SECURITY MAXIMUM Enabled\n");
			}

		else if (strncmp(argv[i], "--SECURITY", 10) == 0) {
			log(LOG_WARNING, "error: invalid setting, "
					"valid choices are SECURITY(OFF|WARN|MAX)\n");
			return -1;
			}

		args[args_used++] = strdup(argv[i]);
		}

    /* search environment for security override */

	const char* senv = getenv("SIGNETSECURITY");
    if (senv) {
        if (strcmp(senv, "OFF") == 0) {
            TAMPER = 0;
            }
        else if (strcmp(senv, "WARN") == 0) {
            TAMPER = 1;
            }
        else if (strcmp(senv, "MAX") == 0) {
            TAMPER = 3;
            }
        else{
            log(LOG_WARNING, "unrecognized environment SIGNETSECURITY=%s\n",
                    senv);
            }
        }

    /* search environment for logging request */

    const char* lenv = getenv("SIGNET_LOGLEVEL");
    if (lenv) {
        int level = atoi(lenv);
        if (level < LOG_DEBUG || level > LOG_CRITICAL) {
            log(LOG_WARNING, 
                    "invalid environment setting SIGNET_LOGLEVEL=%s", lenv);
            }
        else{
            Debug = level;
            log(LOG_DEBUG, "SIGNET_LOGLEVEL set to %d\n", level);
            }
        }

	PySys_SetArgv(args_used, args);

	return 0;
	}

/* optionally initialize virtualenv */

void initialize_virtualenv() {

	/* is vritualenv active? */

	const char* venv = getenv("VIRTUAL_ENV");
	if (venv == NULL) {
		log(LOG_DEBUG, "no VIRTUAL_ENV defined\n");
		return;
		}

	/* look for posix first, then windows */

	string pyhome = venv;
	pyhome += "/bin";

	if (!isdir(pyhome.c_str())) {
		pyhome = venv;
		pyhome += "/Scripts";
		}

	if (!isdir(pyhome.c_str())) {
		log(LOG_WARNING, "VIRTUAL_ENV defined, but missing target %s\n", venv);
		return;
		}

	Py_SetPythonHome((char*)venv);
	}

int run_validation(int argc, char* argv[], const char* script) {

	/* initialize python */

	Py_SetProgramName((char*)script);
	initialize_virtualenv();
	Py_Initialize();

	/* parse command line */

	if (parse_options(argc, argv, script)) {
		Py_Finalize();
		return -1;
		}

    /* retrieve fully qualified path of executable */

    string exename;
    int rc = get_executable(argv, exename);

	/* tamper protection set to warn or max? */

	if (rc == 0 && (TAMPER == 1 || TAMPER == 3)) {

		/* validate binary signature */

        int trusted = verify_trust(exename.c_str(), 1);

        /* if untrusted, and max protection, exit */

        if (trusted < 1 && TAMPER == 3)
            rc = -1;
		}


	/* validate module security */

	if (rc == 0 && TAMPER >= 1) {
        string script_path = _dirname(exename.c_str());
        script_path += SCRIPT;
		rc = validate(script_path);
        }

	Py_Finalize();

	return rc;
	}

int main(int argc, char* argv[]) {

	string exename;
	if (get_executable(argv, exename)) {
		return -1;
		}
	string script = _dirname(exename.c_str()) + SCRIPT;

	log(LOG_INFO, ">>> Validation step\n");

	if (run_validation(argc, argv, script.c_str()))
		return -1;

	log(LOG_INFO, ">>> Run SCRIPT %s\n", script.c_str());

	/* let python script know about signet */

	putenv((char*)"SIGNET=1");

	int rc = 0;

	/* initialize python */

	Py_SetProgramName((char*)script.c_str());
	initialize_virtualenv();
	Py_Initialize();

	/* parse command line */

	if (parse_options(argc, argv, script.c_str())) {
		Py_Finalize();
		return -1;
		}

	if (rc == 0) {
		FILE* fin = fopen(script.c_str(), "r");
		if (fin) {
			rc = PyRun_SimpleFileEx(fin, SCRIPT, 1);

			/* catch and report exception */

			if (rc && PyErr_Occurred())
				PyErr_Print();
			}
		else{
			log(LOG_ERROR, "could not open %s\n", script.c_str());
			rc = -1;
			}
		}

	Py_Finalize();

	return rc;
	}

