# DirHash
Windows command line utility to compute hash of directories and files
=====================================================================

Copyright (c) 2015 Mounir IDRASSI
mounir@idrix.fr

3-clause BSD license ("New BSD License")

Usage
------------

DirHash.exe DirectoryOrFilePath [HashAlgo] [-t ResultFileName] [-nowait]

Possible values for HashAlgo (not case sensitive):
- SHA1
- SHA256
- SHA384
- SHA512

If HashAlgo is not specified, SHA-1 is used by default.

ResultFileName specifies an optional text file where the result will be appended.

if -nowait is specified, program will exit immediately after displaying the hash result. Otherwise, it prompts user to hit a key before it exits.
