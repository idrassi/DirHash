# DirHash
Windows command line utility to compute hash of directories and files
=====================================================================

Copyright (c) 2015 Mounir IDRASSI
mounir@idrix.fr

3-clause BSD license ("New BSD License")

Home page: https://idrassi.github.io/DirHash/

Usage
------------

DirHash.exe DirectoryOrFilePath [HashAlgo] [-t ResultFileName] [-nowait] [-hashnames]

Possible values for HashAlgo (not case sensitive):
- MD5
- SHA1
- SHA256
- SHA384
- SHA512

If HashAlgo is not specified, SHA-1 is used by default.

ResultFileName specifies an optional text file where the result will be appended.

if -nowait is specified, program will exit immediately after displaying the hash result. Otherwise, it prompts user to hit a key before it exits.

if -hashnames is specified, the case sensitive names of the files and directories will be included in the hash computation. Otherwise, only files content is used.
