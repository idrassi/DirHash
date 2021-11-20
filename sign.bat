PATH=%PATH%;%WSDK81%\bin\x86

rem sign using SHA-256
signtool sign /v /sha1 2B174F12D921AF2FF576D867BE91E97E4ADC7D07 /ac GlobalSign_SHA256_EV_CodeSigning_CA.cer /fd sha256 /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "Release\DirHash.exe" "x64\Release\DirHash.exe" "ARM64\Release\DirHash.exe" 

pause
