# Hash-Based-Stream
A test of a Hash Based Stream encryption. Do NOT use in practice, this have not been through testing.
A cryptanalysis of this is appreciated.
Use in Alpine Linux, gcc and OpenSSL-Dev is needed.
```ash
gcc -O2 -std=c11 -Wall -Wextra -o Code Code.c -lssl -lcrypto
```
Change Code to whatever you name your file.
