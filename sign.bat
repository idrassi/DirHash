PATH=%PATH%;%WSDK81%\bin\x86

rem sign using SHA-256
signtool sign /v /sha1 88c1ff4b7469ea3915bd8e7635a7567d34f43202 /ac GlobalSign_SHA256_EV_CodeSigning_CA.cer /fd sha256 /tr http://timestamp.digicert.com /td SHA256 "Release\DirHash.exe" "x64\Release\DirHash.exe" "ARM64\Release\DirHash.exe" 

pause
