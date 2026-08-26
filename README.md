# Hash-Based-Stream
A test of a Hash Based Stream encryption implemented as a command line.
A cryptanalysis of this is appreciated.
Use in Alpine Linux, gcc and OpenSSL-Dev is needed.
```ash
gcc -O2 -std=c11 -Wall -Wextra -o Code Code.c -lssl -lcrypto
```
Change Code to whatever you named your file.
# SECURITY NOTICE
This is a custom cryptographic construction.
It has NOT been formally audited or peer-reviewed.
Do NOT use in production systems or for protecting sensitive data.
Use established, audited libraries (libsodium, Tink, etc.) instead.
