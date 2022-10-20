# xor_packer
Python (pefile) XOR Packer for x64 PE files, using section injection.

# What
Takes an x64 binary and encrypts it's code section to evade detection.

# How
- Encrypts the code (.text) section with a single byte XOR key
- Makes it writable (for later decryption)
- Adds a new unpacker section that contains code to decrypt the code section, and jump to it
- Moves the PE entry point to the new section (so the unpacker runs first)
- Modifies PE structures and deals with section / file alignment so everything works

# Why
For educational purposes™️.

This is useful for understanding the basics of how malware hides it's code from static analyzers and makes a researcher's life harder.

It is also useful for understanding how the PE file format deals with section headers and maps their data to memory.
