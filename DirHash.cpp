/*
 * An implementation of directory hashing that uses lexicographical order on name
 * for sorting. Based on OpenSSL for hash algorithms in order to support all versions
 * of Windows from 2000 to 7 without relying on the presence of any specific CSP.
 *
 * Copyright (c) 2010 Mounir IDRASSI <mounir.idrassi@idrix.fr>. All rights reserved.
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
#include <tchar.h>
#include <strsafe.h>
#include <openssl/sha.h>
#include <list>
using namespace std;


static BYTE g_pbBuffer[4096];

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
   virtual void Update(LPBYTE pbData, DWORD dwLength) = 0;
   virtual void Final(LPBYTE pbDigest) = 0;
   virtual int GetHashSize() = 0;
   virtual LPCTSTR GetID() = 0;
   static Hash* GetHash(LPCTSTR szHashId);
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
   void Update(LPBYTE pbData, DWORD dwLength) { SHA1_Update(&m_ctx, pbData, dwLength);}
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
   void Update(LPBYTE pbData, DWORD dwLength) { SHA256_Update(&m_ctx, pbData, dwLength);}
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
   void Update(LPBYTE pbData, DWORD dwLength) { SHA384_Update(&m_ctx, pbData, dwLength);}
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
   void Update(LPBYTE pbData, DWORD dwLength) { SHA512_Update(&m_ctx, pbData, dwLength);}
   void Final(LPBYTE pbDigest) { SHA512_Final(pbDigest, &m_ctx);}
   LPCTSTR GetID() { return _T("SHA512");}
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
      if (szPath[wcslen(szPath) - 1] != _T('\\') && szPath[wcslen(szPath) - 1] != _T('/'))
         m_szPath += _T("\\");
      m_szPath += szName;
   }

   CDirContent(const CDirContent& content) : m_bIsDir(content.m_bIsDir), m_szPath(content.m_szPath) {}

   bool IsDir() const { return m_bIsDir;}
   LPCWSTR GetPath() const { return m_szPath.c_str();}
   operator LPCWSTR () { return m_szPath.c_str();}
};

DWORD HashFile(LPCTSTR szFilePath, Hash* pHash)
{
   DWORD dwError = 0;
   FILE* f = _tfopen(szFilePath, _T("rb"));
   if(f)
   {
      size_t len;
      while (  (len = fread(g_pbBuffer, 1, sizeof(g_pbBuffer), f)) != 0)
         pHash->Update(g_pbBuffer, len);
      fclose(f);
   }
   else
   {
      _tprintf(TEXT("Failed to open file \"%s\" for reading\n"), szFilePath);
      dwError = -1;
   }
   return dwError;
}

DWORD HashDirectory(LPCTSTR szDirPath, Hash* pHash)
{
   wstring szDir;
   WIN32_FIND_DATA ffd;
   HANDLE hFind = INVALID_HANDLE_VALUE;
   DWORD dwError=0;
   list<CDirContent> dirContent;

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
         dwError = HashDirectory( it->GetPath(), pHash);
         if (dwError)
            break;
      }
      else
      {
         dwError = HashFile(it->GetPath(), pHash);
         if (dwError)
            break;
      }
   }
   
   return dwError;
}

void ShowUsage()
{
   _tprintf(TEXT("Usage: DirHash.exe DirectoryOrFilePath [HashAlgo] [-t ResultFileName] [-nowait]\n  Possible values for HashAlgo (not case sensitive) : \n   - SHA1\n   - SHA256\n   - SHA384\n   - SHA512\n  ResultFileName specifies a text file where the result will be appended\n"));
}

void WaitForExit(bool bDontWait = false)
{
   if (!bDontWait)
   {
      _tprintf(_T("\n\nPress ENTER to exit the program ..."));
      getchar();
   }
}


int _tmain(int argc, _TCHAR* argv[])
{
   BYTE pbDigest[128];
   size_t length_of_arg;
   HANDLE hFind = INVALID_HANDLE_VALUE;
   DWORD dwError=0;
   Hash* pHash = NULL;
   FILE* outputFile = NULL;
   bool bDontWait = false;

   SetConsoleTitle(_T("DirHash by Mounir IDRASSI (mounir@idrix.fr) Copyright 2010-2015"));

   _tprintf(_T("\nDirHash by Mounir IDRASSI (mounir@idrix.fr) Copyright 2010\nRecursively compute hash of a given directory content in lexicographical order.\nIt can also compute the hash of a single file.\n\nSupported Algorithms : SHA1, SHA256, SHA384, SHA512\nUsing OpenSSL\n\n"));

   if (argc < 2 || argc > 6)
   {
      ShowUsage();
      WaitForExit();
      return 1;
   }

   if (argc == 3)
   {
      if (_tcsicmp(argv[2], _T("-nowait")) == 0)
      {
         bDontWait = true;
         pHash = new Sha1();
      }
      else
      {
         pHash = Hash::GetHash(argv[2]);
         if (!pHash)
         {
            ShowUsage();
            WaitForExit();
            return 1;
         }
      }
   }
   else if (argc == 4)
   {
      if (_tcscmp(argv[2],_T("-t")) == 0)
	   {
	      outputFile = _tfopen(argv[3], _T("a+t"));
		   if (!outputFile)
		   {
			   _tprintf(_T("Failed to open the result file for writing!\n"));
			   WaitForExit();
			   return 1;
		   }
		   pHash = new Sha1();
	   }
	   else if (_tcscmp(argv[3],_T("-nowait")) == 0)
	   {
         bDontWait = true;
         pHash = Hash::GetHash(argv[2]);
         if (!pHash)
         {
            ShowUsage();
            WaitForExit();
            return 1;
         }         
	   }
	   else
      {
         ShowUsage();
         WaitForExit();
         return 1;
      }

   }
   else if (argc == 5)
   {
      if (_tcscmp(argv[2],_T("-t")) && _tcscmp(argv[3],_T("-t")))
      {
         ShowUsage();
         WaitForExit();
         return 1;
      }
      if (_tcscmp(argv[2],_T("-t")) == 0)
      {
         if (_tcscmp(argv[4], _T("-nowait")))
         {
            ShowUsage();
            WaitForExit();
            return 1;
         }
         bDontWait = true;
         outputFile = _tfopen(argv[3], _T("a+t"));
         pHash = new Sha1();
      }
      else
      {
         outputFile = _tfopen(argv[4], _T("a+t"));
         pHash = Hash::GetHash(argv[2]);
      }
      if (!outputFile)
      {
         _tprintf(_T("Failed to open the result file for writing!\n"));
         if (pHash) delete pHash;
         WaitForExit();
         return 1;
      }
      if (!pHash)
      {
         if (outputFile) fclose(outputFile);
         ShowUsage();
         WaitForExit();
         return 1;
      }
   }
   else if (argc == 6)
   {
      if (_tcscmp(argv[3],_T("-t")) || _tcscmp(argv[5],_T("-nowait")))
      {
         ShowUsage();
         WaitForExit();
         return 1;
      }

      outputFile = _tfopen(argv[4], _T("a+t"));
      pHash = Hash::GetHash(argv[2]);
      if (!outputFile)
      {
         _tprintf(_T("Failed to open the result file for writing!\n"));
         if (pHash) delete pHash;
         WaitForExit();
         return 1;
      }
      if (!pHash)
      {
         if (outputFile) fclose(outputFile);
         ShowUsage();
         WaitForExit();
         return 1;
      }
      bDontWait = true;
   }
   else
      pHash = new Sha1();

   // Check that the input path plus 3 is not longer than MAX_PATH.
   // Three characters are for the "\*" plus NULL appended below.

   StringCchLength(argv[1], MAX_PATH, &length_of_arg);

   if (length_of_arg > (MAX_PATH - 3))
   {
      if (outputFile) fclose(outputFile);
      delete pHash;
      _tprintf(TEXT("\nError: Directory path is too long. Maximum length is %d characters\n"), MAX_PATH);
      WaitForExit(bDontWait);
      return (-1);
   }
   else if (!PathFileExists(argv[1]))
   {
      if (outputFile) fclose(outputFile);
      delete pHash;
      _tprintf(TEXT("Error: The given path doesn't exist\n"), MAX_PATH);
      WaitForExit(bDontWait);
      return (-2);
   }

   _tprintf(_T("Using %s to compute hash of \"%s\" ...\n"), 
      pHash->GetID(), 
      PathFindFileName(argv[1]));
   fflush(stdout);

   if (PathIsDirectory(argv[1]))
      dwError = HashDirectory(argv[1], pHash);
   else
      dwError = HashFile(argv[1], pHash);

   if (dwError == NO_ERROR)
   {
      pHash->Final(pbDigest);
      if (outputFile)
      {
         _ftprintf(outputFile, __T("%s hash of \"%s\" (%d bytes) = "), 
            pHash->GetID(), 
            PathFindFileName(argv[1]), 
            pHash->GetHashSize());
      }
      _tprintf(_T("%s (%d bytes) = "), pHash->GetID(), pHash->GetHashSize());
      for (int i=0; i < pHash->GetHashSize(); i++)
      {
         _tprintf(_T("%.2X"), pbDigest[i]);
         if (outputFile) _ftprintf(outputFile, _T("%.2X"), pbDigest[i]);
      }
      _tprintf(_T("\n"));
      if (outputFile) _ftprintf(outputFile, _T("\n"));
   }

   delete pHash;
   if (outputFile) fclose(outputFile);

   WaitForExit(bDontWait);
   return dwError;
}
