## EncryptedDllLoader

Program which can encrypt DLLs, and load them encrypted. It can be used to hide the DLL code.

It has 4 options:

- encrypt DLL - produces encrypted DLL from *myfile.txt* and names it *myfile.txt.enc*

- decrypt DLL - decrypts *myfile.txt.enc* to *myfile.txt.enc.dec*

- test encryption - tries to encrypt *myfile.txt* and then decrypt it (without saving new file), then compares result with original file

- load encrypted DLL - loads *myfile.txt.enc* into memory, decrypts memory, then loads DLL from memory using [this](https://github.com/fancycode/MemoryModule)


It uses hardcoded key for encryption/decryption, but this behavior can be easily changed (and it should be changed).

Encryption is done using vigenere cipher - not very strong encryption algorithm, but it does the job.

