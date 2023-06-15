# DirHash
Windows command line utility to compute hash of directories and files
=====================================================================

Copyright (c) 2015-2021 Mounir IDRASSI
mounir@idrix.fr

3-clause BSD license ("New BSD License")

Home page: https://idrassi.github.io/DirHash/

Usage
------------

DirHash.exe DirectoryOrFilePath [HashAlgo] [-t ResultFileName] [-progress] [-sum] [-sumRelativePath] [-includeLastDir] [-verify FileName] [-threads] [-clip] [-lowercase] [-overwrite] [-quiet] [-nologo] [-nowait] [-skipError] [-hashnames [-stripnames]] [-exclude pattern1] [-exclude patter2] [-nofollow]

DirHash.exe -benchmark [HashAlgo | All] [-t ResultFileName] [-clip] [-overwrite] [-quiet] [-nologo] [-nowait]

Possible values for HashAlgo (not case sensitive):
- MD5
- SHA1
- SHA256
- SHA384
- SHA512
- Streebog
- Blake2s
- Blake2b
- Blake3

If HashAlgo is not specified, Blake3 is used by default.

ResultFileName specifies an optional text file where the result will be appended.

if `-benchmark` is specified, program will perform speed benchmark of the selected hash algorithm

if `-mscrypto` specified, program will use Windows native implementation of hash algorithms (This is always enabled on Windows ARM platforms since OpenSSL is too slow on them).

if `-sum` is specified, program will output the hash of every file processed in a format similar to shasum.

if `-sumRelativePath` is specified (only when -sum is specified), the file paths are stored in the output file as relative to the input directory.

if `-verify` is specified, program will verify the hash against value(s) present on the specified file. The argument to this switch must be either a checksum file or a result file.

if `-includeLastDir` (only when -sum or -verify is specified), the last directory name of the input directory is included in the SUM file entries and used in the verification process. This switch implies `-sumRelativePath`.

if `-threads` is specified (only when -sum or -verify specified), multithreading will be used to accelerate hashing of files.

if `-clip` is specified, the hash result is copied to Windows clipboard. This switch is ignored when -sum is specified.

if `-lowercase` is specified, program outputs hash value(s) in lower case instead of upper case.

If `-progress` is specified, information about the progress of file hash operation is displayed.

If `-overwrite` is specified (only when -t is present), the output text file will be overwritten instead of having hash result appended to it.

If `-quiet` is specified, no text is displayed or written to the output file except the hash value.

If `-nowait` is specified, program will exit immediately after displaying the hash result. Otherwise, it prompts user to hit a key before it exits.

If `-hashnames` is specified, the case sensitive names of the files and directories will be included in the hash computation. Otherwise, only files content is used.

If `-stripnames` is specified (only when -hashnames also specified), only the the last path portion of DirectoryOrFilePath is used for hash calculation.

If `-exclude` is specified, it must be followed by a string indicating the file type that must be excluded from the hash computation. For example, to exclude .log files, you specify "-exclude *.log". This switch can be repeated many times in the command line to specify different file types to exclude.

If `-skipError` is specified, ignore any encountered errors and continue processing.

If `-nologo` is specified, don't display the copyright message and version number on startup.

if `-nofollow` is specified, don't follow symbolic links, junction points or mount points, thus excluding them from hash computation.

DirHash can also be configured using a configuration file called DirHash.ini and which must be on the same folder as DirHash.exe.
When `Sum=True` is specified in DirHash.ini, it will have an effect only if `-verify` is not specified in the command line.
An example of DirHash.ini is shown below:

```
[Defaults]
Hash=Blake3
Sum=True
SumRelativePath=True
Threads=True
Quiet=False
Nologo=True
NoWait=True
ShowProgress=False
clip=True
hashnames=False
stripnames=False
lowercase=False
MSCrypto=False
NoFollow=False
```

