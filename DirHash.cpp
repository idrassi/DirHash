/*
* An implementation of directory hashing that uses lexicographical order on name
* for sorting. Based on OpenSSL for hash algorithms in order to support all versions
* of Windows from 2000 to 7 without relying on the presence of any specific CSP.
*
* Copyright (c) 2010-2018 Mounir IDRASSI <mounir.idrassi@idrix.fr>. All rights reserved.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
* or FITNESS FOR A PARTICULAR PURPOSE.
*
*/

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600 
#endif

/* We use UNICODE */
#ifndef UNICODE
#define UNICODE
#endif

#ifndef _UNICODE
#define _UNICODE
#endif

#ifndef ALG_SID_SHA_256
#define ALG_SID_SHA_256                 12
#endif

#ifndef ALG_SID_SHA_384
#define ALG_SID_SHA_384                 13
#endif

#ifndef ALG_SID_SHA_512
#define ALG_SID_SHA_512                 14
#endif

#ifndef CALG_SHA_256
#define CALG_SHA_256            (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256)
#endif

#ifndef CALG_SHA_384
#define CALG_SHA_384            (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_384)
#endif

#ifndef CALG_SHA_512
#define CALG_SHA_512            (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_512)
#endif

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4995)

#include <ntstatus.h>

#define WIN32_NO_STATUS
#include <windows.h>
#include <WinCrypt.h>
#include <bcrypt.h>
#include <Shlwapi.h>
#include <stdio.h>
#include <stdarg.h>
#include <tchar.h>
#include <io.h>
#include <time.h>
#include <strsafe.h>
#if !defined (_M_ARM64) && !defined (_M_ARM)
#include <openssl/sha.h>
#include <openssl/md5.h>
#endif
#include <string>
#include <list>
#include <map>
#include <vector>
#ifdef USE_STREEBOG
#include "Streebog.h"
#endif
using namespace std;

typedef vector<unsigned char> ByteArray;


static BYTE g_pbBuffer[4096];
static TCHAR g_szCanonalizedName[MAX_PATH + 1];
static WORD  g_wAttributes = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED;
static HANDLE g_hConsole = NULL;
static CONSOLE_SCREEN_BUFFER_INFO g_originalConsoleInfo;
static BYTE pbDigest[128];
static TCHAR szDigestHex[257];
static FILE* outputFile = NULL;
static bool g_bLowerCase = false;
static bool g_bUseMsCrypto = false;
static bool g_bCngAvailable = false;
static LPCTSTR g_szMsProvider = MS_ENH_RSA_AES_PROV;
static bool g_bMismatchFound = false;

// Used for sorting directory content
bool compare_nocase(LPCWSTR first, LPCWSTR second)
{
	return _wcsicmp(first, second) < 0;
}

TCHAR ToHex(unsigned char b)
{
	if (b >= 0 && b <= 9)
		return _T('0') + b;
	else if (b >= 10 && b <= 15)
		return (g_bLowerCase ? _T('a') : _T('A')) + b - 10;
	else
		return (g_bLowerCase ? _T('x') : _T('X'));
}

void ToHex(LPBYTE pbData, int iLen, LPTSTR szHex)
{
	unsigned char b;
	for (int i = 0; i < iLen; i++)
	{
		b = *pbData++;
		*szHex++ = ToHex(b >> 4);
		*szHex++ = ToHex(b & 0x0F);
	}
	*szHex = 0;
}

bool FromHex(TCHAR c, unsigned char& b)
{
	if (c >= _T('0') && c <= _T('9'))
		b = c - _T('0');
	else if (c >= _T('a') && c <= _T('f'))
		b = 10 + (c - _T('a'));
	else if (c >= _T('A') && c <= _T('F'))
		b = 10 + (c - _T('A'));
	else
		return false;
	return true;
}

bool FromHex(const TCHAR* szHex, ByteArray& buffer)
{
	bool bRet = false;
	if (szHex)
	{
		size_t l = _tcslen(szHex);
		if (l % 2 == 0)
		{
			size_t i;
			for (i = 0; i < l / 2; i++)
			{
				unsigned char b1, b2;
				if (FromHex(*szHex++, b1) && FromHex(*szHex++, b2))
				{
					buffer.push_back(b1 * 16 + b2);
				}
				else
					break;
			}

			if (i == (l / 2))
			{
				bRet = true;
			}
			else
				buffer.clear();
		}
	}

	return bRet;
}

void ShowError(LPCTSTR szMsg, ...)
{
	va_list args;
	va_start(args, szMsg);
	SetConsoleTextAttribute(g_hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
	_vtprintf(szMsg, args);
	SetConsoleTextAttribute(g_hConsole, g_wAttributes);
	va_end(args);
}

void ShowWarning(LPCTSTR szMsg, ...)
{
	va_list args;
	va_start(args, szMsg);
	SetConsoleTextAttribute(g_hConsole, FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY);
	_vtprintf(szMsg, args);
	SetConsoleTextAttribute(g_hConsole, g_wAttributes);
	va_end(args);
}

typedef  NTSTATUS(WINAPI* RtlGetVersionFn)(
	PRTL_OSVERSIONINFOW lpVersionInformation);

BOOL GetWindowsVersion(OSVERSIONINFOW* pOSversion)
{
	BOOL bRet = FALSE;
	HMODULE h = LoadLibrary(TEXT("ntdll.dll"));
	if (h != NULL)
	{
		RtlGetVersionFn pRtlGetVersion = (RtlGetVersionFn)GetProcAddress(h, "RtlGetVersion");
		if (pRtlGetVersion != NULL)
		{
			if (NO_ERROR == pRtlGetVersion((PRTL_OSVERSIONINFOW)pOSversion))
				bRet = TRUE;
		}

		FreeLibrary(h);
	}

	return bRet;
}

// ---------------------------------------------

class Hash
{
public:
	virtual void Init() = 0;
	virtual void Update(LPCBYTE pbData, size_t dwLength) = 0;
	virtual void Final(LPBYTE pbDigest) = 0;
	virtual int GetHashSize() = 0;
	virtual LPCTSTR GetID() = 0;
	virtual bool IsValid() const { return true; }
	virtual bool UsesMSCrypto() const { return false; }
	virtual Hash* Clone() { return GetHash(GetID()); }
	static bool IsHashId(LPCTSTR szHashId);
	static Hash* GetHash(LPCTSTR szHashId);
};

#if !defined (_M_ARM64) && !defined (_M_ARM)
class Md5 : public Hash
{
protected:
	MD5_CTX m_ctx;
public:
	Md5() : Hash()
	{
		MD5_Init(&m_ctx);
	}

	void Init() { MD5_Init(&m_ctx); }
	void Update(LPCBYTE pbData, size_t dwLength) { MD5_Update(&m_ctx, pbData, dwLength); }
	void Final(LPBYTE pbDigest) { MD5_Final(pbDigest, &m_ctx); }
	LPCTSTR GetID() { return _T("MD5"); }
	int GetHashSize() { return 16; }
};

class Sha1 : public Hash
{
protected:
	SHA_CTX m_ctx;
public:
	Sha1() : Hash()
	{
		SHA1_Init(&m_ctx);
	}

	void Init() { SHA1_Init(&m_ctx); }
	void Update(LPCBYTE pbData, size_t dwLength) { SHA1_Update(&m_ctx, pbData, dwLength); }
	void Final(LPBYTE pbDigest) { SHA1_Final(pbDigest, &m_ctx); }
	LPCTSTR GetID() { return _T("SHA1"); }
	int GetHashSize() { return 20; }
};

class Sha256 : public Hash
{
protected:
	SHA256_CTX m_ctx;
public:
	Sha256() : Hash()
	{
		SHA256_Init(&m_ctx);
	}

	void Init() { SHA256_Init(&m_ctx); }
	void Update(LPCBYTE pbData, size_t dwLength) { SHA256_Update(&m_ctx, pbData, dwLength); }
	void Final(LPBYTE pbDigest) { SHA256_Final(pbDigest, &m_ctx); }
	LPCTSTR GetID() { return _T("SHA256"); }
	int GetHashSize() { return 32; }
};

class Sha384 : public Hash
{
protected:
	SHA512_CTX m_ctx;
public:
	Sha384() : Hash()
	{
		SHA384_Init(&m_ctx);
	}

	void Init() { SHA384_Init(&m_ctx); }
	void Update(LPCBYTE pbData, size_t dwLength) { SHA384_Update(&m_ctx, pbData, dwLength); }
	void Final(LPBYTE pbDigest) { SHA384_Final(pbDigest, &m_ctx); }
	LPCTSTR GetID() { return _T("SHA384"); }
	int GetHashSize() { return 48; }
};

class Sha512 : public Hash
{
protected:
	SHA512_CTX m_ctx;
public:
	Sha512() : Hash()
	{
		SHA512_Init(&m_ctx);
	}

	void Init() { SHA512_Init(&m_ctx); }
	void Update(LPCBYTE pbData, size_t dwLength) { SHA512_Update(&m_ctx, pbData, dwLength); }
	void Final(LPBYTE pbDigest) { SHA512_Final(pbDigest, &m_ctx); }
	LPCTSTR GetID() { return _T("SHA512"); }
	int GetHashSize() { return 64; }
};
#endif

#ifdef USE_STREEBOG
class Streebog : public Hash
{
protected:
	STREEBOG_CTX m_ctx;
public:
	Streebog() : Hash()
	{
		STREEBOG_init(&m_ctx);
}

	void Init() { STREEBOG_init(&m_ctx); }
	void Update(LPCBYTE pbData, size_t dwLength) { STREEBOG_add(&m_ctx, pbData, dwLength); }
	void Final(LPBYTE pbDigest) { STREEBOG_finalize(&m_ctx, pbDigest); }
	LPCTSTR GetID() { return _T("Streebog"); }
	int GetHashSize() { return 64; }
};
#endif

class CngHash : public Hash
{
protected:
	BCRYPT_ALG_HANDLE m_hAlg;
	BCRYPT_HASH_HANDLE m_hash;
	LPWSTR m_wszAlg;
	ULONG m_cbHashObject;
	unsigned char* m_pbHashObject;
public:
	CngHash(LPCWSTR wszAlg) : Hash(), m_hAlg(NULL), m_hash(NULL), m_wszAlg(NULL), m_pbHashObject(NULL), m_cbHashObject(0)
	{
		m_wszAlg = _wcsdup(wszAlg);
		Init();
	}

	virtual ~CngHash()
	{
		Clear();
		if (m_wszAlg)
			free(m_wszAlg);
	}

	void Clear()
	{
		if (m_hash)
			BCryptDestroyHash(m_hash);
		if (m_hAlg)
			BCryptCloseAlgorithmProvider(m_hAlg, 0);
		if (m_pbHashObject)
			delete[] m_pbHashObject;
		m_pbHashObject = NULL;
		m_cbHashObject = 0;
		m_hash = NULL;
		m_hAlg = NULL;
	}

	virtual bool IsValid() const { return (m_hash != NULL); }
	virtual bool UsesMSCrypto() const { return true; }

	virtual void Init() {
		Clear();
		if (STATUS_SUCCESS == BCryptOpenAlgorithmProvider(&m_hAlg, m_wszAlg, MS_PRIMITIVE_PROVIDER, 0))
		{
			DWORD dwValue, count = sizeof(DWORD);
			if (STATUS_SUCCESS == BCryptGetProperty(m_hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&dwValue, count, &count, 0))
			{
				m_cbHashObject = dwValue;
				m_pbHashObject = new unsigned char[dwValue];
				if (STATUS_SUCCESS != BCryptCreateHash(m_hAlg, &m_hash, m_pbHashObject, m_cbHashObject, NULL, 0, 0))
				{
					m_cbHashObject = 0;
					delete[] m_pbHashObject;
					m_pbHashObject = NULL;
				}
			}
		}

		if (!m_pbHashObject)
		{
			Clear();
		}
	}

	virtual void Update(LPCBYTE pbData, size_t dwLength) {
		if (IsValid())
		{
			BCryptHashData(m_hash, (PUCHAR)pbData, (ULONG)dwLength, 0);
		}
	}

	virtual void Final(LPBYTE pbDigest) {
		if (IsValid())
		{
			ULONG dwHashLen = (ULONG)GetHashSize();
			BCryptFinishHash(m_hash, pbDigest, dwHashLen, 0);
		}
	}
};

class Md5Cng : public CngHash
{
public:
	Md5Cng() : CngHash(BCRYPT_MD5_ALGORITHM)
	{

	}

	~Md5Cng()
	{
	}

	LPCTSTR GetID() { return _T("MD5"); }
	int GetHashSize() { return 16; }
};

class Sha1Cng : public CngHash
{
public:
	Sha1Cng() : CngHash(BCRYPT_SHA1_ALGORITHM)
	{

	}

	~Sha1Cng()
	{
	}

	LPCTSTR GetID() { return _T("SHA1"); }
	int GetHashSize() { return 20; }
};

class Sha256Cng : public CngHash
{
public:
	Sha256Cng() : CngHash(BCRYPT_SHA256_ALGORITHM)
	{

	}

	~Sha256Cng()
	{
	}

	LPCTSTR GetID() { return _T("SHA256"); }
	int GetHashSize() { return 32; }
};

class Sha384Cng : public CngHash
{
public:
	Sha384Cng() : CngHash(BCRYPT_SHA384_ALGORITHM)
	{

	}

	~Sha384Cng()
	{
	}

	LPCTSTR GetID() { return _T("SHA384"); }
	int GetHashSize() { return 48; }
};

class Sha512Cng : public CngHash
{
public:
	Sha512Cng() : CngHash(BCRYPT_SHA512_ALGORITHM)
	{

	}

	~Sha512Cng()
	{
	}

	LPCTSTR GetID() { return _T("SHA512"); }
	int GetHashSize() { return 64; }
};

class CapiHash : public Hash
{
protected:
	HCRYPTPROV m_prov;
	HCRYPTHASH m_hash;
	ALG_ID m_algId;
public:
	CapiHash(ALG_ID algId) : Hash(), m_prov(NULL), m_hash(NULL), m_algId(algId)
	{
		Init();
	}

	virtual ~CapiHash()
	{
		Clear();
	}

	void Clear()
	{
		if (m_hash)
			CryptDestroyHash(m_hash);
		if (m_prov)
			CryptReleaseContext(m_prov, 0);
		m_hash = NULL;
		m_prov = NULL;
	}

	virtual bool IsValid() const { return (m_hash != NULL); }
	virtual bool UsesMSCrypto() const { return true; }

	virtual void Init() {
		if (CryptAcquireContext(&m_prov, NULL, g_szMsProvider, PROV_RSA_AES, CRYPT_SILENT | CRYPT_VERIFYCONTEXT))
		{
			CryptCreateHash(m_prov, m_algId, NULL, 0, &m_hash);
		}
	}

	virtual void Update(LPCBYTE pbData, size_t dwLength) {
		if (IsValid())
			CryptHashData(m_hash, pbData, (DWORD)dwLength, 0);
	}

	virtual void Final(LPBYTE pbDigest) {
		if (IsValid())
		{
			DWORD dwHashLen = (DWORD)GetHashSize();
			CryptGetHashParam(m_hash, HP_HASHVAL, pbDigest, &dwHashLen, 0);
		}
	}
};


class Md5Capi : public CapiHash
{
public:
	Md5Capi() : CapiHash(CALG_MD5)
	{

	}

	~Md5Capi()
	{
	}

	LPCTSTR GetID() { return _T("MD5"); }
	int GetHashSize() { return 16; }
};

class Sha1Capi : public CapiHash
{
public:
	Sha1Capi() : CapiHash(CALG_SHA1)
	{

	}

	~Sha1Capi()
	{
	}

	LPCTSTR GetID() { return _T("SHA1"); }
	int GetHashSize() { return 20; }
};

class Sha256Capi : public CapiHash
{
public:
	Sha256Capi() : CapiHash(CALG_SHA_256)
	{

	}

	~Sha256Capi()
	{
	}

	LPCTSTR GetID() { return _T("SHA256"); }
	int GetHashSize() { return 32; }
};

class Sha384Capi : public CapiHash
{
public:
	Sha384Capi() : CapiHash(CALG_SHA_384)
	{

	}

	~Sha384Capi()
	{
	}

	LPCTSTR GetID() { return _T("SHA384"); }
	int GetHashSize() { return 48; }
};

class Sha512Capi : public CapiHash
{
public:
	Sha512Capi() : CapiHash(CALG_SHA_512)
	{

	}

	~Sha512Capi()
	{
	}

	LPCTSTR GetID() { return _T("SHA512"); }
	int GetHashSize() { return 64; }
};

bool Hash::IsHashId(LPCTSTR szHashId)
{
	if ((_tcsicmp(szHashId, _T("SHA1")) == 0)
		|| (_tcsicmp(szHashId, _T("SHA256")) == 0)
		|| (_tcsicmp(szHashId, _T("SHA384")) == 0)
		|| (_tcsicmp(szHashId, _T("SHA512")) == 0)
		|| (_tcsicmp(szHashId, _T("MD5")) == 0)
		|| (_tcsicmp(szHashId, _T("Streebog")) == 0)
		)
	{
		return true;
	}
	else
		return false;
}

Hash* Hash::GetHash(LPCTSTR szHashId)
{
	if (!szHashId || (_tcsicmp(szHashId, _T("SHA1")) == 0))
	{
		if (g_bUseMsCrypto)
		{
			if (g_bCngAvailable)
				return new Sha1Cng();
			else
				return new Sha1Capi();
		}
#if !defined (_M_ARM64) && !defined (_M_ARM)
		else
			return new Sha1();
#endif
	}
	if (_tcsicmp(szHashId, _T("SHA256")) == 0)
	{
		if (g_bUseMsCrypto)
		{
			if (g_bCngAvailable)
				return new Sha256Cng();
			else
				return new Sha256Capi();
		}
#if !defined (_M_ARM64) && !defined (_M_ARM)
		else
			return new Sha256();
#endif
		}
	if (_tcsicmp(szHashId, _T("SHA384")) == 0)
	{
		if (g_bUseMsCrypto)
		{
			if (g_bCngAvailable)
				return new Sha384Cng();
			else
				return new Sha384Capi();
		}
#if !defined (_M_ARM64) && !defined (_M_ARM)
		else
			return new Sha384();
#endif
		}
	if (_tcsicmp(szHashId, _T("SHA512")) == 0)
	{
		if (g_bUseMsCrypto)
		{
			if (g_bCngAvailable)
				return new Sha512Cng();
			else
				return new Sha512Capi();
		}
#if !defined (_M_ARM64) && !defined (_M_ARM)
		else
			return new Sha512();
#endif
		}
	if (_tcsicmp(szHashId, _T("MD5")) == 0)
	{
		if (g_bUseMsCrypto)
		{
			if (g_bCngAvailable)
				return new Md5Cng();
			else
				return new Md5Capi();
		}
#if !defined (_M_ARM64) && !defined (_M_ARM)
		else
			return new Md5();
#endif
		}
#ifdef USE_STREEBOG
	if (_tcsicmp(szHashId, _T("Streebog")) == 0)
	{
		return new Streebog();
	}
#endif
	return NULL;
}

// ----------------------------------------------------------

class CDirContent
{
protected:
	wstring m_szPath;
	bool m_bIsDir;
public:
	CDirContent(LPCWSTR szPath, LPCWSTR szName, bool bIsDir) : m_bIsDir(bIsDir), m_szPath(szPath)
	{
		if (szPath[wcslen(szPath) - 1] == _T('/'))
			m_szPath[wcslen(szPath) - 1] = _T('\\');

		if (szPath[wcslen(szPath) - 1] != _T('\\'))
			m_szPath += _T("\\");
		m_szPath += szName;
	}

	CDirContent(const CDirContent& content) : m_bIsDir(content.m_bIsDir), m_szPath(content.m_szPath) {}

	bool IsDir() const { return m_bIsDir; }
	LPCWSTR GetPath() const { return m_szPath.c_str(); }
	operator LPCWSTR () { return m_szPath.c_str(); }
};

bool IsExcludedName(LPCTSTR szName, list<wstring>& excludeSpecList)
{
	for (list<wstring>::iterator It = excludeSpecList.begin(); It != excludeSpecList.end(); It++)
	{
		if (PathMatchSpec(szName, It->c_str()))
			return true;
	}

	return false;
}

// return the file name. If it is too long, it is shortness so that the progress line 
LPCTSTR GetShortFileName(LPCTSTR szFilePath, unsigned long long fileSize)
{
	static TCHAR szShortName[256];
	size_t l, bufferSize = ARRAYSIZE(szShortName);
	int maxPrintLen = _scprintf(" [==========] 100.00 %% (%llu/%llu)", fileSize, fileSize); // 10 steps for progress bar
	LPCTSTR ptr = &szFilePath[_tcslen(szFilePath) - 1];

	// Get file name part from the path
	while ((ptr != szFilePath) && (*ptr != _T('\\')) && (*ptr != _T('/')))
	{
		ptr--;
	}
	ptr++;

	// calculate maximum length for file name	
	bufferSize = (g_originalConsoleInfo.dwSize.X > (maxPrintLen + 1)) ? min(256, (g_originalConsoleInfo.dwSize.X - 1 - maxPrintLen)) : 9;

	l = _tcslen(ptr);
	if (l < bufferSize)
		_tcscpy(szShortName, ptr);
	else
	{
		size_t prefixLen = (bufferSize / 2 - 2);
		size_t suffixLen = bufferSize - prefixLen - 4;

		memcpy(szShortName, ptr, prefixLen * sizeof(TCHAR));
		memcpy(((unsigned char*)szShortName) + prefixLen * sizeof(TCHAR), _T("..."), 3 * sizeof(TCHAR));
		memcpy(((unsigned char*)szShortName) + (prefixLen + 3) * sizeof(TCHAR), ptr + (l - suffixLen), suffixLen * sizeof(TCHAR));
		szShortName[bufferSize - 1] = 0;
	}
	return szShortName;
}

void DisplayProgress(LPCTSTR szFileName, unsigned long long currentSize, unsigned long long fileSize, clock_t startTime, clock_t& lastBlockTime)
{
	clock_t t = clock();
	if (lastBlockTime == 0 || currentSize == fileSize || ((t - lastBlockTime) >= CLOCKS_PER_SEC))
	{
		unsigned long long maxPos = 10ull;
		unsigned long long pos = (currentSize * maxPos) / fileSize;
		double pourcentage = ((double)currentSize / (double)fileSize) * 100.0;

		lastBlockTime = t;

		_tprintf(_T("\r%s ["), szFileName);
		for (unsigned long long i = 0; i < maxPos; i++)
		{
			if (i < pos)
				_tprintf(_T("="));
			else
				_tprintf(_T(" "));
		}
		_tprintf(_T("] %.2f %% (%llu/%llu)"), pourcentage, currentSize, fileSize);

		_tprintf(_T("\r"));
	}
}

void ClearProgress()
{
	_tprintf(_T("\r"));
	for (int i = 0; i < g_originalConsoleInfo.dwSize.X - 1; i++)
	{
		_tprintf(_T(" "));
	}

	_tprintf(_T("\r"));
}

DWORD HashFile(LPCTSTR szFilePath, Hash* pHash, bool bIncludeNames, bool bStripNames, list<wstring>& excludeSpecList, bool bQuiet, bool bShowProgress, bool bSumMode, const map<wstring,ByteArray>& digestList)
{
	DWORD dwError = 0;
	FILE* f = NULL;
	int pathLen = lstrlen(szFilePath);
	map<wstring, ByteArray>::const_iterator It;
	bool bSumVerificationMode = false;

	if (pathLen <= MAX_PATH && !excludeSpecList.empty() && IsExcludedName(szFilePath, excludeSpecList))
		return 0;

	if (bSumMode)
	{
		if (!digestList.empty())
		{
			// check that the current file is specified in the checksum file
			It = digestList.find(szFilePath);
			if (It == digestList.end())
			{
				ShowError(_T("Error: file \"%s\" not found in checksum file."), szFilePath);
				return -5;
			}
			else
				bSumVerificationMode = true;
		}
		pHash = Hash::GetHash(pHash->GetID());
	}

	if (bIncludeNames)
	{
		LPCTSTR pNameToHash = NULL;
		if (pathLen > MAX_PATH)
			pNameToHash = szFilePath;
		else
		{
			g_szCanonalizedName[MAX_PATH] = 0;
			if (!PathCanonicalize(g_szCanonalizedName, szFilePath))
				lstrcpy(g_szCanonalizedName, szFilePath);

			if (bStripNames)
				pNameToHash = PathFindFileName(g_szCanonalizedName);
			else
				pNameToHash = g_szCanonalizedName;
		}

		pHash->Update((LPCBYTE)pNameToHash, _tcslen(pNameToHash) * sizeof(TCHAR));
	}

	f = _tfopen(szFilePath, _T("rb"));
	if (f)
	{
		size_t len;
		bShowProgress = !bQuiet && bShowProgress;
		unsigned long long fileSize = bShowProgress ? (unsigned long long) _filelengthi64(_fileno(f)) : 0;
		unsigned long long currentSize = 0;
		clock_t startTime = bShowProgress ? clock() : 0;
		clock_t lastBlockTime = 0;
		LPCTSTR szFileName = bShowProgress ? GetShortFileName(szFilePath, fileSize) : NULL;

		while ((len = fread(g_pbBuffer, 1, sizeof(g_pbBuffer), f)) != 0)
		{
			currentSize += (unsigned long long) len;
			pHash->Update(g_pbBuffer, len);
			if (bShowProgress)
				DisplayProgress(szFileName, currentSize, fileSize, startTime, lastBlockTime);
		}

		if (bShowProgress)
			ClearProgress();

		fclose(f);

		if (bSumMode)
		{
			pHash->Final(pbDigest);

			if (bSumVerificationMode)
			{
				if (memcmp(pbDigest, It->second.data(), pHash->GetHashSize()))
				{
					g_bMismatchFound = true;
					if (!bQuiet) ShowWarning(_T("Hash value mismatch for \"%s\"\n"), szFilePath);
					if (outputFile) _ftprintf(outputFile, _T("Hash value mismatch for \"%s\"\n"), szFilePath);
				}
			}
			else
			{
				// display hash in yellow
				SetConsoleTextAttribute(g_hConsole, FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY);

				ToHex(pbDigest, pHash->GetHashSize(), szDigestHex);

				if (!bQuiet) _tprintf(_T("%s  %s\n"), szDigestHex, szFilePath);
				if (outputFile) _ftprintf(outputFile, _T("%s  %s\n"), szDigestHex, szFilePath);

				// restore normal text color
				SetConsoleTextAttribute(g_hConsole, g_wAttributes);
			}
		}
	}
	else
	{
		_tprintf(TEXT("Failed to open file \"%s\" for reading\n"), szFilePath);
		dwError = -1;
	}

	if (bSumMode)
		delete pHash;
	return dwError;
}

DWORD HashDirectory(LPCTSTR szDirPath, Hash* pHash, bool bIncludeNames, bool bStripNames, list<wstring>& excludeSpecList, bool bQuiet, bool bShowProgress, bool bSumMode, const map<wstring, ByteArray>& digestList)
{
	wstring szDir;
	WIN32_FIND_DATA ffd;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	DWORD dwError = 0;
	list<CDirContent> dirContent;
	int pathLen = lstrlen(szDirPath);

	if (pathLen <= MAX_PATH && !excludeSpecList.empty() && IsExcludedName(szDirPath, excludeSpecList))
		return 0;

	if (bIncludeNames)
	{
		LPCTSTR pNameToHash = NULL;
		if (lstrlen(szDirPath) > MAX_PATH)
			pNameToHash = szDirPath;
		else
		{
			g_szCanonalizedName[MAX_PATH] = 0;
			if (!PathCanonicalize(g_szCanonalizedName, szDirPath))
				lstrcpy(g_szCanonalizedName, szDirPath);

			if (bStripNames)
				pNameToHash = PathFindFileName(g_szCanonalizedName);
			else
				pNameToHash = g_szCanonalizedName;
		}

		pHash->Update((LPCBYTE)pNameToHash, _tcslen(pNameToHash) * sizeof(TCHAR));
	}

	szDir += szDirPath;
	szDir += _T("\\*");

	// Find the first file in the directory.

	hFind = FindFirstFile(szDir.c_str(), &ffd);

	if (INVALID_HANDLE_VALUE == hFind)
	{
		dwError = GetLastError();
		_tprintf(TEXT("FindFirstFile failed on \"%s\" with error 0x%.8X.\n"), szDirPath, dwError);
		return dwError;
	}

	// List all the files in the directory with some info about them.

	do
	{
		if ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
		{
			// Skip "." and ".." directories
			if ((_tcscmp(ffd.cFileName, _T(".")) != 0) && (_tcscmp(ffd.cFileName, _T("..")) != 0))
				dirContent.push_back(CDirContent(szDirPath, ffd.cFileName, true));
		}
		else
		{
			dirContent.push_back(CDirContent(szDirPath, ffd.cFileName, false));
		}
	}
	while (FindNextFile(hFind, &ffd) != 0);

	dwError = GetLastError();
	if (dwError != ERROR_NO_MORE_FILES)
	{
		_tprintf(TEXT("FindNextFile failed while listing \"%s\". \n Error 0x%.8X.\n"), szDirPath, GetLastError());
		return dwError;
	}

	// Clear the error
	dwError = 0;

	FindClose(hFind);

	// Sort all entries
	dirContent.sort(compare_nocase);

	for (list<CDirContent>::iterator it = dirContent.begin(); it != dirContent.end(); it++)
	{
		if (it->IsDir())
		{
			dwError = HashDirectory(it->GetPath(), pHash, bIncludeNames, bStripNames, excludeSpecList, bQuiet, bShowProgress, bSumMode, digestList);
			if (dwError)
				break;
		}
		else
		{
			dwError = HashFile(it->GetPath(), pHash, bIncludeNames, bStripNames, excludeSpecList, bQuiet, bShowProgress, bSumMode, digestList);
			if (dwError)
				break;
		}
	}

	return dwError;
}

void ShowLogo()
{
	SetConsoleTextAttribute(g_hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	_tprintf(_T("\nDirHash by Mounir IDRASSI (mounir@idrix.fr) Copyright 2010-2020\n\nRecursively compute hash of a given directory content in lexicographical order.\nIt can also compute the hash of a single file.\n\nSupported Algorithms : MD5, SHA1, SHA256, SHA384, SHA512 and Streebog\n\n"));
	SetConsoleTextAttribute(g_hConsole, g_wAttributes);
}


void ShowUsage()
{
	ShowLogo();
	_tprintf(TEXT("Usage: \n")
		TEXT("  DirHash.exe DirectoryOrFilePath [HashAlgo] [-t ResultFileName] [-mscrypto] [-sum] [-verify checksumFileName] [-clip] [-lowercase] [-overwrite]  [-quiet] [-nowait] [-hashnames] [-exclude pattern1] [-exclude pattern2]\n")
		TEXT("  DirHash.exe -benchmark [HashAlgo] [-t ResultFileName] [-mscrypto] [-clip] [-overwrite]  [-quiet] [-nowait]\n")
		TEXT("\n")
		TEXT("  Possible values for HashAlgo (not case sensitive, default is SHA1):\n")
		TEXT("  MD5, SHA1, SHA256, SHA384, SHA512 and Streebog\n\n")
		TEXT("  ResultFileName: text file where the result will be appended\n")
		TEXT("  -benchmark: perform speed benchmark of the selected algoithm\n")
		TEXT("  -mscrypto: use Windows native implementation of hash algorithms (Always enabled on ARM).\n")
		TEXT("  -sum: output hash of every file processed in a format similar to shasum.\n")
		TEXT("  -verify: verify hash of every file against its hash value present in the given checksum file.\n")
		TEXT("  -clip: copy the result to Windows clipboard (ignored when -sum specified)\n")
		TEXT("  -lowercase: output hash value(s) in lower case instead of upper case\n")
		TEXT("  -progress: Display information about the progress of hash operation\n")
		TEXT("  -overwrite (only when -t present): output text file will be overwritten\n")
		TEXT("  -quiet: No text is displayed or written except the hash value\n")
		TEXT("  -nowait: avoid displaying the waiting prompt before exiting\n")
		TEXT("  -hashnames: file names will be included in hash computation\n")
		TEXT("  -exclude specifies a name pattern for files to exclude from hash computation.\n")
	);
}

void WaitForExit(bool bDontWait = false)
{
	if (!bDontWait)
	{
		_tprintf(_T("\n\nPress ENTER to exit the program ..."));
		getchar();
	}
}

void CopyToClipboard(LPCTSTR szDigestHex)
{
	if (OpenClipboard(NULL))
	{
		size_t cch = _tcslen(szDigestHex);

		HGLOBAL hglbCopy = GlobalAlloc(GMEM_MOVEABLE,
			(cch + 1) * sizeof(TCHAR));
		if (hglbCopy)
		{
			EmptyClipboard();

			// Lock the handle and copy the text to the buffer. 
			LPVOID lptstrCopy = GlobalLock(hglbCopy);
			memcpy(lptstrCopy, (const TCHAR*)szDigestHex,
				(cch * sizeof(TCHAR)) + 1);
			GlobalUnlock(hglbCopy);

			// Place the handle on the clipboard. 
#ifdef _UNICODE
			SetClipboardData(CF_UNICODETEXT, hglbCopy);
#else
			SetClipboardData(CF_TEXT, hglbCopy);
#endif
		}

		CloseClipboard();
	}
}

void BenchmarkAlgo(LPCTSTR hashAlgo, bool bQuiet, bool bCopyToClipboard)
{
#define BENCH_BUFFER_SIZE 50 * 1024 * 1024
#define BENCH_LOOPS 50
	unsigned char* pbData = new unsigned char[BENCH_BUFFER_SIZE];
	unsigned char pbDigest[64];

	if (pbData)
	{
		size_t i;
		clock_t t1, t2;
		Hash* pHash = Hash::GetHash(hashAlgo);

		t1 = clock();
		for (i = 0; i < BENCH_LOOPS; i++)
		{
			pHash->Update(pbData, BENCH_BUFFER_SIZE);
			pHash->Final(pbDigest);
			pHash->Init();
		}
		t2 = clock();

		double speed = ((double)BENCH_BUFFER_SIZE * (double)BENCH_LOOPS) / ((double)(t2 - t1) / (double)CLOCKS_PER_SEC);
		if (speed >= (double)(1024 * 1024 * 1024))
			StringCbPrintf((TCHAR*)pbData, BENCH_BUFFER_SIZE, _T("%s speed = %f GiB/s"), hashAlgo, (speed / (double)(1024 * 1024 * 1024)));
		else if (speed >= (double)(1024 * 1024))
			StringCbPrintf((TCHAR*)pbData, BENCH_BUFFER_SIZE, _T("%s speed = %f MiB/s"), hashAlgo, (speed / (double)(1024 * 1024)));
		else if (speed >= (double)(1024))
			StringCbPrintf((TCHAR*)pbData, BENCH_BUFFER_SIZE, _T("%s speed = %f KiB/s"), hashAlgo, (speed / (double)(1024)));
		else
			StringCbPrintf((TCHAR*)pbData, BENCH_BUFFER_SIZE, _T("%s speed = %f B/s"), hashAlgo, speed);

		// display hash in yellow
		SetConsoleTextAttribute(g_hConsole, FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY);

		ToHex(pbDigest, pHash->GetHashSize(), szDigestHex);

		if (!bQuiet)
		{
			if (outputFile)
			{
				_ftprintf(outputFile, _T("%s\n"), (TCHAR*)pbData);
			}
			_tprintf(_T("%s\n"), (TCHAR*)pbData);
		}

		if (bCopyToClipboard)
			CopyToClipboard((TCHAR*)pbData);

		// restore normal text color
		SetConsoleTextAttribute(g_hConsole, g_wAttributes);

		delete pHash;
		delete[] pbData;
	}
	else
	{
		_tprintf(_T("Failed to allocate memory for %s benchmark.\n"), hashAlgo);
	}
}

void PerformBenchmark(Hash* pHash, bool bQuiet, bool bCopyToClipboard)
{
	BenchmarkAlgo(pHash->GetID(), bQuiet, bCopyToClipboard);
}

void LoadDefaults(wstring& hashAlgoToUse, bool& bQuiet, bool& bDontWait, bool& bShowProgress, bool& bCopyToClipboard, bool& bIncludeNames, bool& bStripNames, bool& bLowerCase, bool& bUseMsCrypto)
{
	hashAlgoToUse = L"SHA1";
	bUseMsCrypto = false;
	bDontWait = false;
	bIncludeNames = false;
	bStripNames = false;
	bQuiet = false;
	bCopyToClipboard = false;
	bShowProgress = false;
	bLowerCase = false;

	// get values from DirHash.ini fille if it exists
	WCHAR szInitPath[1024];
	szInitPath[0] = 0;
	if (GetModuleFileName(NULL, szInitPath, ARRAYSIZE(szInitPath)))
	{
		wchar_t* ptr = wcsrchr (szInitPath, L'\\');
		if (ptr)
		{
			ptr += 1;
			*ptr = 0;
			StringCbCatW(szInitPath, sizeof(szInitPath), L"DirHash.ini");

			WCHAR szValue[128];
			if (GetPrivateProfileStringW(L"Defaults", L"Hash", L"SHA1", szValue, ARRAYSIZE(szValue), szInitPath) && Hash::IsHashId (szValue))
			{
				hashAlgoToUse = szValue;
			}

			if (GetPrivateProfileStringW(L"Defaults", L"Quiet", L"False", szValue, ARRAYSIZE(szValue), szInitPath))
			{
				if (_wcsicmp(szValue, L"True") == 0)
					bQuiet = true;
				else
					bQuiet = false;
			}

			if (GetPrivateProfileStringW(L"Defaults", L"NoWait", L"False", szValue, ARRAYSIZE(szValue), szInitPath))
			{
				if (_wcsicmp(szValue, L"True") == 0)
					bDontWait = true;
				else
					bDontWait = false;
			}

			if (GetPrivateProfileStringW(L"Defaults", L"ShowProgress", L"False", szValue, ARRAYSIZE(szValue), szInitPath))
			{
				if (_wcsicmp(szValue, L"True") == 0)
					bShowProgress = true;
				else
					bShowProgress = false;
			}

			if (GetPrivateProfileStringW(L"Defaults", L"hashnames", L"False", szValue, ARRAYSIZE(szValue), szInitPath))
			{
				if (_wcsicmp(szValue, L"True") == 0)
					bIncludeNames = true;
				else
					bIncludeNames = false;
			}

			if (GetPrivateProfileStringW(L"Defaults", L"stripnames", L"False", szValue, ARRAYSIZE(szValue), szInitPath))
			{
				if (_wcsicmp(szValue, L"True") == 0)
					bStripNames = true;
				else
					bStripNames = false;
			}

			if (GetPrivateProfileStringW(L"Defaults", L"clip", L"False", szValue, ARRAYSIZE(szValue), szInitPath))
			{
				if (_wcsicmp(szValue, L"True") == 0)
					bCopyToClipboard = true;
				else
					bCopyToClipboard = false;
			}

			if (GetPrivateProfileStringW(L"Defaults", L"lowercase", L"False", szValue, ARRAYSIZE(szValue), szInitPath))
			{
				if (_wcsicmp(szValue, L"True") == 0)
					bLowerCase = true;
				else
					bLowerCase = false;
			}

			if (GetPrivateProfileStringW(L"Defaults", L"MSCrypto", L"False", szValue, ARRAYSIZE(szValue), szInitPath))
			{
				if (_wcsicmp(szValue, L"True") == 0)
					bUseMsCrypto = true;
				else
					bUseMsCrypto = false;
			}
		}
	}

#if defined (_M_ARM64) || defined (_M_ARM)
	// we always use Windows native crypto on ARM platform because OpenSSL is not optimized for such platforms
	g_bUseMsCrypto = true;
#endif
}

bool ParseSumFile(const wchar_t* sumFile, map<wstring, ByteArray>& digestList)
{
	bool bRet = false;
	FILE* f = _wfopen(sumFile, L"rt");
	if (f)
	{
		bool bFailed = false;
		ByteArray buffer(4096 * 2);
		wchar_t* szLine = (wchar_t*)buffer.data();
		size_t digestLen = 0;
		
		digestList.clear();

		while (fgetws(szLine, (int)(buffer.size() / 2), f))
		{
			size_t l = wcslen(szLine);
			if (szLine[l - 1] == L'\n')
			{
				szLine[l - 1] = 0;
				l--;
			}

			if (l == 0)
				continue;

			// extract hash which is followed by two or one space characters
			wchar_t* ptr = wcschr(szLine, L' ');
			if (ptr)
			{
				*ptr = 0;
				ptr++;
				// look for begining of file path
				while (ptr != &szLine[l - 1] && *ptr == L' ')
					ptr++;
				if (ptr != &szLine[l - 1])
				{
					// hash length must be one of the supported ones (16, 20, 32, 48, 64)
					ByteArray digest;
					if (FromHex(szLine, digest))
					{
						if ((digestLen != 0 && digestLen == digest.size())
							|| (digestLen == 0 && ((digest.size() == 16) || (digest.size() == 20) || (digest.size() == 32) || (digest.size() == 48) || (digest.size() == 64)))
							)
						{
							digestLen = digest.size();
							digestList[ptr] = digest;
						}
						else
						{
							bFailed = true;
							break;
						}
					}
					else
					{
						bFailed = true;
						break;
					}
				}
				else
				{
					bFailed = true;
					break;
				}
			}
			else
			{
				bFailed = true;
				break;
			}
		}
		fclose(f);

		if (bFailed)
		{
			_tprintf(TEXT("Invalid format for checksum file \"%s\"\n"), sumFile);
			digestList.clear();
		}
		else if (digestList.size() == 0)
		{
			_tprintf(TEXT("No entries found in checksum file \"%s\"\n"), sumFile);
		}
		else
			bRet = true;
	}
	else
	{
		_tprintf(TEXT("Failed to open file \"%s\" for reading\n"), sumFile);
	}

	return bRet;
}

int _tmain(int argc, _TCHAR* argv[])
{
	size_t length_of_arg;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	DWORD dwError = 0;
	Hash* pHash = NULL;
	wstring outputFileName;
	wstring sumVerificationFileName;
	bool bDontWait = false;
	bool bIncludeNames = false;
	bool bStripNames = false;
	bool bQuiet = false;
	bool bOverwrite = false;
	bool bCopyToClipboard = false;
	bool bShowProgress = false;
	bool bSumMode = false;
	bool bVerifySumMode = false;
	list<wstring> excludeSpecList;
	OSVERSIONINFO osvi;
	bool bIsWindowsX = false;
	wstring hashAlgoToUse = L"SHA1";
	bool bBenchmarkOp = false;
	map < wstring, ByteArray> digestsList;

	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

	if (GetWindowsVersion(&osvi))
		bIsWindowsX = ((osvi.dwMajorVersion == 5) && (osvi.dwMinorVersion == 1));

	g_bCngAvailable = (osvi.dwMajorVersion >= 6);

	if (bIsWindowsX)
		g_szMsProvider = MS_ENH_RSA_AES_PROV_XP;

	g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

	// get original console attributes
	if (GetConsoleScreenBufferInfo(g_hConsole, &g_originalConsoleInfo))
		g_wAttributes = g_originalConsoleInfo.wAttributes;

	setbuf(stdout, NULL);

	SetConsoleTitle(_T("DirHash by Mounir IDRASSI (mounir@idrix.fr) Copyright 2010-2020"));

	if (argc < 2)
	{
		ShowUsage();
		WaitForExit();
		return 1;
	}

	LoadDefaults(hashAlgoToUse, bQuiet, bDontWait, bShowProgress, bCopyToClipboard, bIncludeNames, bStripNames, g_bLowerCase, g_bUseMsCrypto);

	if (_tcscmp(argv[1], _T("-benchmark")) == 0)
		bBenchmarkOp = true;

	if (argc >= 3)
	{
		for (int i = 2; i < argc; i++)
		{
			if (_tcscmp(argv[i], _T("-t")) == 0)
			{
				if ((i + 1) >= argc)
				{
					// missing file argument               
					ShowUsage();
					ShowError(_T("Error: Missing argument for switch -t\n"));
					WaitForExit(bDontWait);
					return 1;
				}

				outputFileName = argv[i + 1];

				i++;
			}
			else if (_tcscmp(argv[i], _T("-overwrite")) == 0)
			{
				bOverwrite = true;
			}
			else if (_tcscmp(argv[i], _T("-nowait")) == 0)
			{
				bDontWait = true;
			}
			else if (_tcscmp(argv[i], _T("-quiet")) == 0)
			{
				bQuiet = true;
			}
			else if (_tcscmp(argv[i], _T("-hashnames")) == 0)
			{
				if (bBenchmarkOp)
				{
					ShowUsage();
					ShowError(_T("Error: -hashnames can not be combined with -benchmark\n"));
					WaitForExit(bDontWait);
					return 1;
				}
				bIncludeNames = true;
			}
			else if (_tcscmp(argv[i], _T("-stripnames")) == 0)
			{
				if (bBenchmarkOp)
				{
					ShowUsage();
					ShowError(_T("Error: -stripnames can not be combined with -benchmark\n"));
					WaitForExit(bDontWait);
					return 1;
				}
				bStripNames = true;
			}
			else if (_tcscmp(argv[i], _T("-sum")) == 0)
			{
				if (bBenchmarkOp)
				{
					ShowUsage();
					ShowError(_T("Error: -sum can not be combined with -benchmark\n"));
					WaitForExit(bDontWait);
					return 1;
				}

				if (bVerifySumMode)
				{
					ShowUsage();
					ShowError(_T("Error: -sum can not be combined with -verify\n"));
					WaitForExit(bDontWait);
					return 1;
				}

				bSumMode = true;
			}
			else if (_tcscmp(argv[i], _T("-verify")) == 0)
			{
				if (bBenchmarkOp)
				{
					ShowUsage();
					ShowError(_T("Error: -verify can not be combined with -benchmark\n"));
					WaitForExit(bDontWait);
					return 1;
				}
				
				if (bSumMode)
				{
					ShowUsage();
					ShowError(_T("Error: -verify can not be combined with -sum\n"));
					WaitForExit(bDontWait);
					return 1;
				}

				if ((i + 1) >= argc)
				{
					// missing file argument               
					ShowUsage();
					ShowError(_T("Error: Missing argument for switch -exclude\n"));
					WaitForExit(bDontWait);
					return 1;
				}

				bVerifySumMode = true;

				sumVerificationFileName = argv[i + 1];
				i++;
			}
			else if (_tcscmp(argv[i], _T("-exclude")) == 0)
			{
				if (bBenchmarkOp)
				{
					ShowUsage();
					ShowError(_T("Error: -exclude can not be combined with -benchmark\n"));
					WaitForExit(bDontWait);
					return 1;
				}
				if ((i + 1) >= argc)
				{
					// missing file argument               
					ShowUsage();
					ShowError(_T("Error: Missing argument for switch -exclude\n"));
					WaitForExit(bDontWait);
					return 1;
				}

				excludeSpecList.push_back(argv[i + 1]);

				i++;
			}
			else if (_tcscmp(argv[i], _T("-clip")) == 0)
			{
				bCopyToClipboard = true;
			}
			else if (_tcscmp(argv[i], _T("-progress")) == 0)
			{
				if (bBenchmarkOp)
				{
					ShowUsage();
					ShowError(_T("Error: -progress can not be combined with -benchmark\n"));
					WaitForExit(bDontWait);
					return 1;
				}
				bShowProgress = true;
			}
			else if (_tcscmp(argv[i], _T("-lowercase")) == 0)
			{
				if (bBenchmarkOp)
				{
					ShowUsage();
					ShowError(_T("Error: -lowercase can not be combined with -benchmark\n"));
					WaitForExit(bDontWait);
					return 1;
				}
				g_bLowerCase = true;
			}
			else if (_tcscmp(argv[i], _T("-mscrypto")) == 0)
			{
				g_bUseMsCrypto = true;
			}
			else if (Hash::IsHashId(argv[i]))
			{
				hashAlgoToUse = argv[i];
			}
			else
			{
				if (outputFile) fclose(outputFile);
				ShowUsage();
				ShowError(_T("Error: Argument \"%s\" not recognized\n"), argv[i]);
				WaitForExit(bDontWait);
				return 1;
			}
		}
	}

	pHash = Hash::GetHash(hashAlgoToUse.c_str());
	if (!pHash || !pHash->IsValid())
	{
		if (outputFile) fclose(outputFile);
		if (pHash) delete pHash;
		ShowError(_T("Error: Failed to initialize the hash algorithm \"%s\"\n"), hashAlgoToUse.c_str());
		WaitForExit(bDontWait);
		return 1;
	}

	if (!bQuiet)
		ShowLogo();

	if (!outputFileName.empty())
	{
		outputFile = _tfopen(outputFileName.c_str(), bOverwrite ? _T("wt") : _T("a+t"));
		if (!outputFile)
		{
			if (!bQuiet)
			{
				ShowError(_T("!!!Failed to open the result file for writing!!!\n"));
			}
		}
	}

	if (bBenchmarkOp)
	{

		PerformBenchmark(pHash, bQuiet, bCopyToClipboard);

		delete pHash;

		WaitForExit(bDontWait);
		return dwError;
	}

	if (bVerifySumMode)
	{
		if (ParseSumFile(sumVerificationFileName.c_str(), digestsList))
		{
			// check that hash length used in the checksum file is the same as the one specified by the user
			int sumFileHashLen = (int)digestsList.begin()->second.size();
			if (sumFileHashLen != pHash->GetHashSize())
			{
				if (!bQuiet)
					ShowError(TEXT("Error: hash length parsed from checksum file (%d bytes) is different from used hash length (%d bytes).\n"), sumFileHashLen, pHash->GetHashSize());
				WaitForExit(bDontWait);
				return (-4);
			}
			bSumMode = true;
		}
		else
		{
			if (!bQuiet)
				ShowError(TEXT("Error: Failed to parse checksum file \"%s\". Please check that it exists and that its content is valid.\n"), sumVerificationFileName.c_str());
			WaitForExit(bDontWait);
			return (-3);
		}
	}

	// Check that the input path plus 3 is not longer than MAX_PATH.
	// Three characters are for the "\*" plus NULL appended below.

	StringCchLength(argv[1], MAX_PATH, &length_of_arg);

	if (length_of_arg > (MAX_PATH - 3))
	{
		if (outputFile) fclose(outputFile);
		delete pHash;
		if (!bQuiet)
			ShowError(TEXT("Error: Input directory/file path is too long. Maximum length is %d characters\n"), MAX_PATH);
		WaitForExit(bDontWait);
		return (-1);
	}
	else if (!PathFileExists(argv[1]))
	{
		if (outputFile) fclose(outputFile);
		delete pHash;
		if (!bQuiet)
			ShowError(TEXT("Error: The given input file doesn't exist\n"));
		WaitForExit(bDontWait);
		return (-2);
	}

	if (!bQuiet)
	{
		_tprintf(_T("Using %s to %s %s of \"%s\" ...\n"),
			pHash->GetID(),
			bVerifySumMode? _T("verify") : _T("compute"),
			bSumMode ? _T("checksum") : _T("hash"),
			bStripNames ? PathFindFileName(argv[1]) : argv[1]);
		fflush(stdout);
	}

	if (PathIsDirectory(argv[1]))
	{
		// remove any trailing backslash to harmonize directory names in case they are included
		// in hash computations
		int pathLen = lstrlen(argv[1]);
		TCHAR backslash = 0;
		if (argv[1][pathLen - 1] == '\\' || argv[1][pathLen - 1] == '/')
		{
			backslash = argv[1][pathLen - 1];
			argv[1][pathLen - 1] = 0;
		}

		dwError = HashDirectory(argv[1], pHash, bIncludeNames, bStripNames, excludeSpecList, bQuiet, bShowProgress, bSumMode, digestsList);

		// restore backslash
		if (backslash)
			argv[1][pathLen - 1] = backslash;
	}
	else
		dwError = HashFile(argv[1], pHash, bIncludeNames, bStripNames, excludeSpecList, bQuiet, bShowProgress, bSumMode, digestsList);

	if (dwError == NO_ERROR)
	{
		if (bSumMode)
		{
			if (bVerifySumMode)
			{
				if (g_bMismatchFound)
				{
					if (!bQuiet)
					{
						ShowError(_T("Verification of \"%s\" against \"%s\" failed!\n"),
							argv[1],
							sumVerificationFileName.c_str());
					}
					if (outputFile)
					{
						_ftprintf(outputFile, _T("Verification of \"%s\" against \"%s\" failed!\n"),
							argv[1],
							sumVerificationFileName.c_str());
					}
					dwError = -7;
				}
				else
				{
					if (!bQuiet)
					{
						_tprintf(_T("Verification of \"%s\" against \"%s\" succeeded.\n"),
							argv[1],
							sumVerificationFileName.c_str());
					}
					if (outputFile)
					{
						_ftprintf(outputFile, _T("Verification of \"%s\" against \"%s\" succeeded.\n"),
							argv[1],
							sumVerificationFileName.c_str());
					}
				}

			}
		}
		else
		{
			pHash->Final(pbDigest);

			if (!bQuiet)
			{
				if (outputFile)
				{
					_ftprintf(outputFile, __T("%s hash of \"%s\" (%d bytes) = "),
						pHash->GetID(),
						PathFindFileName(argv[1]),
						pHash->GetHashSize());
				}
				_tprintf(_T("%s (%d bytes) = "), pHash->GetID(), pHash->GetHashSize());
			}

			// display hash in yellow
			SetConsoleTextAttribute(g_hConsole, FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY);

			ToHex(pbDigest, pHash->GetHashSize(), szDigestHex);

			_tprintf(szDigestHex);
			if (outputFile) _ftprintf(outputFile, szDigestHex);

			if (bCopyToClipboard)
				CopyToClipboard(szDigestHex);

			// restore normal text color
			SetConsoleTextAttribute(g_hConsole, g_wAttributes);

			_tprintf(_T("\n"));
			if (outputFile) _ftprintf(outputFile, _T("\n"));
		}

	}

	delete pHash;
	if (outputFile) fclose(outputFile);

	SecureZeroMemory(g_pbBuffer, sizeof(g_pbBuffer));
	SecureZeroMemory(pbDigest, sizeof(pbDigest));
	SecureZeroMemory(szDigestHex, sizeof(szDigestHex));


	WaitForExit(bDontWait);
	return dwError;
}
