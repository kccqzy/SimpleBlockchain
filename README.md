# Simple Blockchain

This project was my attempt at implementing a simple blockchain from scratch.
(Well, not totally not scratch because I didn't implement the low-level
cryptography primitives and low-level network connection handling stuff, but I
did write the code to use those cryptography primitives in a blockchain
setting and the blockchain network protocol on top.) It was inspired by a
blockchain problem at HackMIT 2018 and grew out of the California CTF 2019.
The roots of this problem from a CTF can still be found within the commit
history (this repo was extracted from a subdirectory from the CTF repo).
Although the challenge wasn't particularly well-received by the contestants
due to a few issues, some of which within my control, the process of writing
this blockchain did teach me a lot about the blockchain. I had always thought
I completely understood how blockchains worked, until I sat down to write the
code and realized there were gaps in my understanding. For example, exactly
how should we ascertain a transaction is valid? How do we deal with
transactions that attempt to double spend? These questions have seemingly
simple answers, until you realize there's much more nuance behind.

Currently the blockchain can be run, but there are known bugs that prevent a
smooth experience. They will be fixed if I have time. Also, a feature I'd like
to implement is support for multiple distinct blockchains.

To run, we require a Python 3.7 installation on a UNIX-like system. Python 3.7
is needed because we make use of new features like `asyncio.run` or
`contextlib.AsyncExitStack`. A UNIX-like system is needed because we need to
`fork()`.
