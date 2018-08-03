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
#define _WIN32_WINNT 0x0500
#endif

/* We use UNICODE */
#ifndef UNICODE
#define UNICODE
#endif

#ifndef _UNICODE
#define _UNICODE
#endif

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4995)

#include <windows.h>
#include <Shlwapi.h>
#include <stdio.h>
#include <stdarg.h>
#include <tchar.h>
#include <io.h>
#include <time.h>
#include <strsafe.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <list>
#include "Streebog.h"
using namespace std;


static BYTE g_pbBuffer[4096];
static TCHAR g_szCanonalizedName[MAX_PATH + 1];
static WORD  g_wAttributes = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED;
static HANDLE g_hConsole = NULL;
static CONSOLE_SCREEN_BUFFER_INFO g_originalConsoleInfo;

// Used for sorting directory content
bool compare_nocase (LPCWSTR first, LPCWSTR second)
{
   return _wcsicmp(first, second) < 0;
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
   static Hash* GetHash(LPCTSTR szHashId);
};

class Md5 : public Hash
{
protected:
   MD5_CTX m_ctx;
public:
   Md5() : Hash() 
   {
      MD5_Init(&m_ctx);
   }

   void Init() { MD5_Init(&m_ctx);}
   void Update(LPCBYTE pbData, size_t dwLength) { MD5_Update(&m_ctx, pbData, dwLength);}
   void Final(LPBYTE pbDigest) { MD5_Final(pbDigest, &m_ctx);}
   LPCTSTR GetID() { return _T("MD5");}
   int GetHashSize() { return 16;}
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

   void Init() { SHA1_Init(&m_ctx);}
   void Update(LPCBYTE pbData, size_t dwLength) { SHA1_Update(&m_ctx, pbData, dwLength);}
   void Final(LPBYTE pbDigest) { SHA1_Final(pbDigest, &m_ctx);}
   LPCTSTR GetID() { return _T("SHA1");}
   int GetHashSize() { return 20;}
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

   void Init() { SHA256_Init(&m_ctx);}
   void Update(LPCBYTE pbData, size_t dwLength) { SHA256_Update(&m_ctx, pbData, dwLength);}
   void Final(LPBYTE pbDigest) { SHA256_Final(pbDigest, &m_ctx);}
   LPCTSTR GetID() { return _T("SHA256");}
   int GetHashSize() { return 32;}
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

   void Init() { SHA384_Init(&m_ctx);}
   void Update(LPCBYTE pbData, size_t dwLength) { SHA384_Update(&m_ctx, pbData, dwLength);}
   void Final(LPBYTE pbDigest) { SHA384_Final(pbDigest, &m_ctx);}
   LPCTSTR GetID() { return _T("SHA384");}
   int GetHashSize() { return 48;}
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

   void Init() { SHA512_Init(&m_ctx);}
   void Update(LPCBYTE pbData, size_t dwLength) { SHA512_Update(&m_ctx, pbData, dwLength);}
   void Final(LPBYTE pbDigest) { SHA512_Final(pbDigest, &m_ctx);}
   LPCTSTR GetID() { return _T("SHA512");}
   int GetHashSize() { return 64;}
};

class Streebog : public Hash
{
protected:
   STREEBOG_CTX m_ctx;
public:
   Streebog() : Hash() 
   {
      STREEBOG_init(&m_ctx);
   }

   void Init() { STREEBOG_init(&m_ctx);}
   void Update(LPCBYTE pbData, size_t dwLength) { STREEBOG_add(&m_ctx, pbData, dwLength);}
   void Final(LPBYTE pbDigest) { STREEBOG_finalize(&m_ctx, pbDigest);}
   LPCTSTR GetID() { return _T("Streebog");}
   int GetHashSize() { return 64;}
};

Hash* Hash::GetHash(LPCTSTR szHashId)
{
   if (!szHashId || (_tcsicmp(szHashId, _T("SHA1")) == 0))
   {
      return new Sha1();
   }
   if (_tcsicmp(szHashId, _T("SHA256")) == 0)
   {
      return new Sha256();
   }
   if (_tcsicmp(szHashId, _T("SHA384")) == 0)
   {
      return new Sha384();
   }
   if (_tcsicmp(szHashId, _T("SHA512")) == 0)
   {
      return new Sha512();
   }
   if (_tcsicmp(szHashId, _T("MD5")) == 0)
   {
      return new Md5();
   }
   if (_tcsicmp(szHashId, _T("Streebog")) == 0)
   {
      return new Streebog();
   }
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

   bool IsDir() const { return m_bIsDir;}
   LPCWSTR GetPath() const { return m_szPath.c_str();}
   operator LPCWSTR () { return m_szPath.c_str();}
};

bool IsExcludedName(LPCTSTR szName, list<wstring>& excludeSpecList)
{
   for (list<wstring>::iterator It = excludeSpecList.begin(); It != excludeSpecList.end(); It++)
   {
      if (PathMatchSpec (szName, It->c_str()))
         return true;
   }

   return false;
}

// return the file name. If it is too long, it is shortness so that the progress line 
LPCTSTR GetShortFileName (LPCTSTR szFilePath, unsigned long long fileSize)
{
	static TCHAR szShortName[256];
	size_t l, bufferSize = ARRAYSIZE (szShortName);
	int maxPrintLen = _scprintf (" [==========] 100.00 %% (%ull/%ull)", fileSize, fileSize); // 10 steps for progress bar
	LPCTSTR ptr = &szFilePath [_tcslen (szFilePath) - 1];

	// Get file name part from the path
	while ((ptr != szFilePath) && (*ptr != _T('\\')) && (*ptr != _T('/')))
	{
		ptr--;
	}
	ptr++;

	// calculate maximum length for file name	
	bufferSize = (g_originalConsoleInfo.dwSize.X > (maxPrintLen+1))? min (256, (g_originalConsoleInfo.dwSize.X - 1 - maxPrintLen)) : 9;

	l = _tcslen (ptr);
	if (l < bufferSize)
		_tcscpy (szShortName, ptr);
	else
	{
		size_t prefixLen = (bufferSize / 2 - 2);
		size_t suffixLen = bufferSize - prefixLen - 4;

		memcpy (szShortName, ptr, prefixLen * sizeof (TCHAR));
		memcpy (((unsigned char*) szShortName) + prefixLen * sizeof (TCHAR), _T("..."), 3 * sizeof (TCHAR));
		memcpy (((unsigned char*) szShortName) + (prefixLen + 3)* sizeof (TCHAR), ptr + (l - suffixLen), suffixLen * sizeof (TCHAR));
		szShortName [bufferSize - 1] = 0;
	}
	return szShortName;
}

void DisplayProgress (LPCTSTR szFileName, unsigned long long currentSize, unsigned long long fileSize, clock_t startTime, clock_t &lastBlockTime)
{
	clock_t t = clock ();
	if (lastBlockTime == 0 || currentSize == fileSize || ((t - lastBlockTime) >= CLOCKS_PER_SEC))
	{
		unsigned long long maxPos = 10ull;
		unsigned long long pos = (currentSize * maxPos) / fileSize;
		double pourcentage = ((double) currentSize / (double) fileSize) * 100.0;

		lastBlockTime = t;
	
		_tprintf (_T("\r%s ["), szFileName);
		for (unsigned long long i = 0; i < maxPos; i++)
		{
			if (i < pos)
				_tprintf (_T("="));
			else
				_tprintf (_T(" "));
		}
		_tprintf (_T("] %.2f %% (%llu/%llu)"), pourcentage, currentSize, fileSize);

		_tprintf (_T("\r"));
	}
}

void ClearProgress ()
{
	_tprintf (_T("\r"));
	for (int i = 0; i < g_originalConsoleInfo.dwSize.X - 1; i++)
	{
		_tprintf (_T(" "));
	}

	_tprintf (_T("\r"));
}

DWORD HashFile(LPCTSTR szFilePath, Hash* pHash, bool bIncludeNames, bool bStripNames, list<wstring>& excludeSpecList, bool bQuiet, bool bShowProgress)
{
   DWORD dwError = 0;
   FILE* f = NULL;
   int pathLen = lstrlen(szFilePath);

   if (pathLen <= MAX_PATH && !excludeSpecList.empty() && IsExcludedName (szFilePath, excludeSpecList))
      return 0;

   if (bIncludeNames)
   {
      LPCTSTR pNameToHash = NULL;
      if (pathLen > MAX_PATH)
         pNameToHash = szFilePath;
      else
      {
         g_szCanonalizedName[MAX_PATH] = 0;
         if (!PathCanonicalize (g_szCanonalizedName, szFilePath))
            lstrcpy (g_szCanonalizedName, szFilePath);

         if (bStripNames)
             pNameToHash = PathFindFileName(g_szCanonalizedName);
         else
             pNameToHash = g_szCanonalizedName;  
      }

      pHash->Update ((LPCBYTE) pNameToHash, _tcslen (pNameToHash) * sizeof(TCHAR));
   }

   f = _tfopen(szFilePath, _T("rb"));
   if(f)
   {
      size_t len;
	  bShowProgress = !bQuiet && bShowProgress;
	  unsigned long long fileSize = bShowProgress? (unsigned long long) _filelengthi64 ( _fileno (f)) : 0;
	  unsigned long long currentSize = 0;
	  clock_t startTime = bShowProgress? clock () : 0;
	  clock_t lastBlockTime = 0;
	  LPCTSTR szFileName = bShowProgress? GetShortFileName (szFilePath, fileSize) : NULL;

      while (  (len = fread(g_pbBuffer, 1, sizeof(g_pbBuffer), f)) != 0)
	  {
		 currentSize += (unsigned long long) len;
         pHash->Update(g_pbBuffer, len);
		 if (bShowProgress)
			DisplayProgress (szFileName, currentSize, fileSize, startTime, lastBlockTime);
	  }

	  if (bShowProgress)
		ClearProgress ();

      fclose(f);
   }
   else
   {
      _tprintf(TEXT("Failed to open file \"%s\" for reading\n"), szFilePath);
      dwError = -1;
   }
   return dwError;
}

DWORD HashDirectory(LPCTSTR szDirPath, Hash* pHash, bool bIncludeNames, bool bStripNames, list<wstring>& excludeSpecList, bool bQuiet, bool bShowProgress)
{
   wstring szDir;
   WIN32_FIND_DATA ffd;
   HANDLE hFind = INVALID_HANDLE_VALUE;
   DWORD dwError=0;
   list<CDirContent> dirContent;
   int pathLen = lstrlen(szDirPath);

   if (pathLen <= MAX_PATH && !excludeSpecList.empty() && IsExcludedName (szDirPath, excludeSpecList))
      return 0;

   if (bIncludeNames)
   {
      LPCTSTR pNameToHash = NULL;
      if (lstrlen(szDirPath) > MAX_PATH)
         pNameToHash = szDirPath;
      else
      {
         g_szCanonalizedName[MAX_PATH] = 0;
         if (!PathCanonicalize (g_szCanonalizedName, szDirPath))
            lstrcpy (g_szCanonalizedName, szDirPath);

         if (bStripNames)
             pNameToHash = PathFindFileName(g_szCanonalizedName);
         else
             pNameToHash = g_szCanonalizedName;         
      }

      pHash->Update ((LPCBYTE) pNameToHash, _tcslen (pNameToHash) * sizeof(TCHAR));
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
      if (  (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
      {
         // Skip "." and ".." directories
         if ( (_tcscmp(ffd.cFileName, _T(".")) != 0) && (_tcscmp(ffd.cFileName, _T("..")) != 0))
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
         dwError = HashDirectory( it->GetPath(), pHash, bIncludeNames, bStripNames, excludeSpecList, bQuiet, bShowProgress);
         if (dwError)
            break;
      }
      else
      {
         dwError = HashFile(it->GetPath(), pHash, bIncludeNames, bStripNames, excludeSpecList, bQuiet, bShowProgress);
         if (dwError)
            break;
      }
   }
   
   return dwError;
}

void ShowLogo()
{
   SetConsoleTextAttribute (g_hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
   _tprintf(_T("\nDirHash by Mounir IDRASSI (mounir@idrix.fr) Copyright 2010-2018\n\nRecursively compute hash of a given directory content in lexicographical order.\nIt can also compute the hash of a single file.\n\nSupported Algorithms : MD5, SHA1, SHA256, SHA384, SHA512 and Streebog\nUsing OpenSSL\n\n"));
   SetConsoleTextAttribute (g_hConsole, g_wAttributes);
}

void ShowUsage()
{
   ShowLogo();
   _tprintf(TEXT("Usage: DirHash.exe DirectoryOrFilePath [HashAlgo] [-t ResultFileName] [-clip] [-overwrite]  [-quiet] [-nowait] [-hashnames] [-exclude pattern1] [-exclude pattern2]\n\n  Possible values for HashAlgo (not case sensitive, default is SHA1):\n  MD5, SHA1, SHA256, SHA384, SHA512 and Streebog\n\n  ResultFileName: text file where the result will be appended\n\n  -clip: copy the result to Windows clipboard\n\n  -progress: Display information about the progress of hash operation\n\n  -overwrite (only when -t present): output text file will be overwritten\n\n  -quiet: No text is displayed or written except the hash value\n\n  -nowait: avoid displaying the waiting prompt before exiting\n\n  -hashnames: file names will be included in hash computation\n\n  -exclude specifies a name pattern for files to exclude from hash computation.\n\n"));
}

void ShowError(LPCTSTR szMsg, ...)
{
   va_list args;
   va_start( args, szMsg );
   SetConsoleTextAttribute (g_hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
   _vtprintf (szMsg, args );
   SetConsoleTextAttribute (g_hConsole, g_wAttributes);
   va_end( args );
}

void WaitForExit(bool bDontWait = false)
{
   if (!bDontWait)
   {
      _tprintf(_T("\n\nPress ENTER to exit the program ..."));
      getchar();
   }
}

void CopyToClipboard (LPCTSTR szDigestHex)
{
	if (OpenClipboard(NULL))
	{
		size_t cch = _tcslen (szDigestHex);

		HGLOBAL hglbCopy = GlobalAlloc(GMEM_MOVEABLE, 
			(cch + 1) * sizeof(TCHAR)); 
		if (hglbCopy)
		{
			EmptyClipboard ();

			// Lock the handle and copy the text to the buffer. 
			LPVOID lptstrCopy = GlobalLock(hglbCopy); 
			memcpy(lptstrCopy, (const TCHAR*) szDigestHex, 
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

TCHAR ToHex(unsigned char b)
{
	if (b >= 0 && b <= 9)
		return _T('0') + b;
	else if (b >= 10 && b <= 15)
		return _T('A') + b - 10;
	else
		return _T('X');
}

void ToHex(LPBYTE pbData, int iLen, LPTSTR szHex)
{
	unsigned char b;
	for (int i=0; i < iLen; i++)
	{
		b = *pbData++;
		*szHex++ = ToHex(b >> 4);
		*szHex++ = ToHex(b & 0x0F);
	}
	*szHex = 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
   BYTE pbDigest[128];
   TCHAR szDigestHex[257];
   size_t length_of_arg;
   HANDLE hFind = INVALID_HANDLE_VALUE;
   DWORD dwError=0;
   Hash* pHash = NULL;
   FILE* outputFile = NULL;
   wstring outputFileName;
   bool bDontWait = false;
   bool bIncludeNames = false;
   bool bStripNames = false;
   bool bQuiet = false;
   bool bOverwrite = false;	
   bool bCopyToClipboard = false;
   bool bShowProgress = false;
   list<wstring> excludeSpecList;
   g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);   

   // get original console attributes
   if (GetConsoleScreenBufferInfo(g_hConsole, &g_originalConsoleInfo))
      g_wAttributes = g_originalConsoleInfo.wAttributes;

   setbuf (stdout, NULL);

   SetConsoleTitle(_T("DirHash by Mounir IDRASSI (mounir@idrix.fr) Copyright 2010-2018"));

   if (argc < 2)
   {
      ShowUsage();
      WaitForExit();
      return 1;
   }

   if (argc >= 3)
   {
      for (int i = 2; i < argc; i++)
      {
         if (_tcscmp(argv[i],_T("-t")) == 0)
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
         else if (_tcscmp(argv[i],_T("-overwrite")) == 0)
         {
            bOverwrite = true;
         }
         else if (_tcscmp(argv[i],_T("-nowait")) == 0)
         {
            bDontWait = true;
         }
         else if (_tcscmp(argv[i],_T("-quiet")) == 0)
         {
            bQuiet = true;
         }
         else if (_tcscmp(argv[i],_T("-hashnames")) == 0)
         {
            bIncludeNames = true;
         }
         else if (_tcscmp(argv[i],_T("-stripnames")) == 0)
         {
            bStripNames = true;
         }
         else if (_tcscmp(argv[i],_T("-exclude")) == 0)
         {
            if ((i + 1) >= argc)
            {
               // missing file argument               
               ShowUsage();
               ShowError(_T("Error: Missing argument for switch -exclude\n"));
               WaitForExit(bDontWait);
               return 1;
            }

            excludeSpecList.push_back(argv[i+1]);

            i++;
         }
         else if (_tcscmp(argv[i], _T("-clip")) == 0)
         {
            bCopyToClipboard = true;
         }
         else if (_tcscmp(argv[i], _T("-progress")) == 0)
         {
            bShowProgress = true;
         }
         else
         {
            pHash = Hash::GetHash(argv[i]);
            if (!pHash)
            {
               if (outputFile) fclose(outputFile);               
               ShowUsage();
               ShowError(_T("Error: Argument \"%s\" not recognized\n"), argv[i]);
               WaitForExit(bDontWait);
               return 1;
            }
         }
      }
   }

   if (!pHash)
      pHash = new Sha1();

   if (!bQuiet)
      ShowLogo();
  
	if (!outputFileName.empty())
	{
	 outputFile = _tfopen(outputFileName.c_str(), bOverwrite? _T("wt") : _T("a+t"));
	 if (!outputFile)
	 {
		if (!bQuiet)
		{
		   ShowError (_T("!!!Failed to open the result file for writing!!!\n"));
		}
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
      _tprintf(_T("Using %s to compute hash of \"%s\" ...\n"), 
      pHash->GetID(), 
      bStripNames? PathFindFileName(argv[1]) : argv[1]);
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
      
      dwError = HashDirectory(argv[1], pHash, bIncludeNames, bStripNames, excludeSpecList, bQuiet, bShowProgress);

      // restore backslash
      if (backslash)
         argv[1][pathLen - 1] = backslash;
   }
   else
      dwError = HashFile(argv[1], pHash, bIncludeNames, bStripNames, excludeSpecList, bQuiet, bShowProgress);

   if (dwError == NO_ERROR)
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
      SetConsoleTextAttribute (g_hConsole, FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY);

	  ToHex (pbDigest, pHash->GetHashSize(), szDigestHex);

	  _tprintf(szDigestHex);
      if (outputFile) _ftprintf(outputFile, szDigestHex);

	  if (bCopyToClipboard)
		CopyToClipboard (szDigestHex);

      // restore normal text color
      SetConsoleTextAttribute (g_hConsole, g_wAttributes);

      _tprintf(_T("\n"));
      if (outputFile) _ftprintf(outputFile, _T("\n"));
   }

   delete pHash;
   if (outputFile) fclose(outputFile);

   WaitForExit(bDontWait);
   return dwError;
}
