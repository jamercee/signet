#include <stdio.h>
#include <string>

#ifndef _MSC_VER

/* on linux, argv[0] has executable path */

int get_executable(char const* const* argv, std::string& exepath) {
	exepath = argv[0];
	return 0;
	}

/* Non-windows platforms do not provide the same facilities for
 * code verification. For now, just return -1 (unsigned)
 */

int verify_trust(const char source[], int warn_unsigned=0) {
	if (warn_unsigned)
		fprintf(stderr, "SECURITY WARNING: '%s' not signed\n", source);
	return -1;
	}

#else

#include <windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#pragma comment (lib, "wintrust")

/* on windows, we have to dig deeper than argv[0] accomodate 
 * order of precedence, http://support.microsoft.com/kb/35284
 */

int get_executable(char const* const* argv, std::string& exepath) {
	char fname[ 32*1024 ];
	if (! GetModuleFileNameA(NULL, fname, sizeof(fname))) {
		fprintf(stderr, "SECURITY FAILURE: cannot retrieve executable name\n");
		return -2;
		}
	exepath = fname;
	return 0;
	}

/* verify code is trusted */

int verify_trust(const char source[], int warn_unsigned=0) {

	int nchars = MultiByteToWideChar(CP_ACP, 0, source, -1, NULL, 0);

	wchar_t* wsource = new wchar_t[nchars];
	if (wsource == NULL) {
		fprintf(stderr, "SECURITY FAILURE: out-of-memory allocating wsource\n");
		return -2;
		}

	MultiByteToWideChar(CP_ACP, 0, source, -1, wsource, nchars);

	/* code adapted from 
	 * http://msdn.microsoft.com/en-us/library/windows/desktop/aa382384%28v=vs.85%29.aspx
	 */

    /* Initialize the WINTRUST_FILE_INFO structure. */

    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = wsource;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;

    /* Initialize the WinVerifyTrust input data structure. */

    memset(&WinTrustData, 0, sizeof(WinTrustData));
    WinTrustData.cbStruct = sizeof(WinTrustData);
    WinTrustData.pPolicyCallbackData = NULL;
    WinTrustData.pSIPClientData = NULL;
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE; 
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    WinTrustData.hWVTStateData = NULL;
    WinTrustData.pwszURLReference = NULL;
    WinTrustData.dwUIContext = 0;
    WinTrustData.pFile = &FileData;

	int trusted = 0;

    LONG status = WinVerifyTrust( NULL, &WVTPolicyGUID, &WinTrustData);
	DWORD err;

    switch (status) {

        case ERROR_SUCCESS:
			trusted = 1;
            break;
        
        case TRUST_E_NOSIGNATURE:
            /* check the error details */
            err = GetLastError();
            if (TRUST_E_NOSIGNATURE == err ||
				TRUST_E_SUBJECT_FORM_UNKNOWN == err ||
				TRUST_E_PROVIDER_UNKNOWN == err) {
				if (warn_unsigned)
					fprintf(stderr, "SECURITY WARNING: '%s' not signed\n", source);
				trusted = -1;
            	} 
            else{
				/* unknown error verifying signature */
				fprintf(stderr, "SECURITY FAILURE: trying to verify '%s' "
						"status=0x%lx, error=0x$lx\n", source, status, err);
				trusted = -2;
				}
            break;

        case TRUST_E_EXPLICIT_DISTRUST:
        case CRYPT_E_SECURITY_SETTINGS:
			/* subject or publisher was invalidated by machine admin */
			fprintf(stderr, "SECURITY VIOLATION: '%s' is blocked by local policy\n", source);
			trusted = 0;
            break;

        case TRUST_E_SUBJECT_NOT_TRUSTED:
            /* user clicked "No" when asked to install/run. */
			fprintf(stderr, "SECURTIY VIOLATION: '%s' has untrusted signature\n", source);
			trusted = 0;
            break;

		case TRUST_E_BAD_DIGEST:
			/* tampered binary */
			fprintf(stderr, "SECURITY VIOLATION: '%s' tampered binary\n", source);
			break;

        default:
			fprintf(stderr, "SECURITY FAILURE: verifying '%s' status=0x%lx\n", source, status);
            break;
    	}

	/* cleanup */

    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust( NULL, &WVTPolicyGUID, &WinTrustData);

	delete [] wsource;

    return trusted;
	}
#endif

