PATH=%PATH%;%WSDK81%\bin\x86

rem sign using SHA-256
signtool sign /v /sha1 04141E4EA6D9343CEC994F6C099DC09BDD8937C9 /ac GlobalSign_SHA256_EV_CodeSigning_CA.cer /fd sha256 /tr http://timestamp.globalsign.com/?signature=sha2 /td SHA256 "Release\DirHash.exe" "x64\Release\DirHash.exe" "ARM64\Release\DirHash.exe" 

pause
