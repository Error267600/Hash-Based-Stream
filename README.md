# Hash-Based-Stream
A test of a Hash Based Stream encryption implemented as a command line.
A cryptanalysis of this is appreciated.
Use in Alpine Linux, gcc and OpenSSL-Dev is needed.
```ash
gcc -O2 -std=c11 -Wall -Wextra -o Main Main.c -lssl -lcrypto
```
Build with above command and run.
# Supported OS
Any os that can emulate Alpine and/or run gcc with OpenSSL should work.  
If you are on iOS, I suggest ish shell on App Store.
# SECURITY NOTICE
This is a custom cryptographic construction.
It has NOT been formally audited or peer-reviewed.
Do NOT use in production systems or for protecting sensitive data.
Use established, audited libraries (libsodium, Tink, etc.) instead.
