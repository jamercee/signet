
#ifdef _MSC_VER
#define VERIFY_AVAILABLE 1
#else
#define VERIFY_AVAILABLE 0
#endif


/* return fully qualified path of executable */

int get_executable(char const* const * argv, std::string& exepath);

/* verify the binary is signed and the signature is valid.
 *
 * returns:
 * 
 * 	 1 - signed and trusted
 * 	 0 - signed and untrusted
 * 	-1 - unsigned
 * 	-2 - error during verification
 *
 */

int verify_trust(const char source[], int warn_unsigned=0);

