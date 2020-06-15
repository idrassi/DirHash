# DirHash
Windows command line utility to compute hash of directories and files
=====================================================================

Copyright (c) 2015-2020 Mounir IDRASSI
mounir@idrix.fr

3-clause BSD license ("New BSD License")

Home page: https://idrassi.github.io/DirHash/

Usage
------------

DirHash.exe DirectoryOrFilePath [HashAlgo] [-t ResultFileName] [-progress] [-sum] [-clip] [-overwrite] [-quiet] [-nowait] [-hashnames [-stripnames]] [-exclude pattern1] [-exclude patter2] 

DirHash.exe -benchmark [HashAlgo] [-t ResultFileName] [-clip] [-overwrite] [-quiet] [-nowait]

Possible values for HashAlgo (not case sensitive):
- MD5
- SHA1
- SHA256
- SHA384
- SHA512
- Streebog

If HashAlgo is not specified, SHA-1 is used by default.

ResultFileName specifies an optional text file where the result will be appended.

if -benchmark is specified, program will perform speed benchmark of the selected hash algorithm

if -mscrypto specified, program will use Windows native implementation of hash algorithms (This is always enabled on Windows ARM platforms since OpenSSL is too slow on them).

if -sum is specified, program will output the hash of every file processed in a format similar to shasum.

if -clip is specified, the hash result is copied to Windows clipboard. This switch is ignored when -sum is specified.

if -lowercase is specified, program outputs hash value(s) in lower case instead of upper case.

If -progress is specified, information about the progress of file hash operation is displayed.

If -overwrite is specified (only when -t is present), the output text file will be overwritten instead of having hash result appended to it.

If -quiet is specified, no text is displayed or written to the output file except the hash value.

If -nowait is specified, program will exit immediately after displaying the hash result. Otherwise, it prompts user to hit a key before it exits.

If -nowait is specified, program will exit immediately after displaying the hash result. Otherwise, it prompts user to hit a key before it exits.

If -hashnames is specified, the case sensitive names of the files and directories will be included in the hash computation. Otherwise, only files content is used.

If -stripnames is specified (only when -hashnames also specified), only the the last path portion of DirectoryOrFilePath is used for hash calculation.

If -exclude is specified, it must be followed by a string indicating the file type that must be excluded from the hash computation. For example, to exclude .log files, you specify "-exclude *.log". This switch can be repeated many times in the command line to specify different file types to exclude.

