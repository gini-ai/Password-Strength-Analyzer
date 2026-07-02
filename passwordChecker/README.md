# Secure Password Strength Analyzer & Repo Logger

A Python-based cybersecurity tool designed to evaluate password complexity metrics and safely manage user credential histories using modern cryptographic principles.

## Features
- **Entropy Analysis:** Evaluates length, letter casing, numbers, symbols, and string patterns.
- **CSPRNG Generation:** Yields mathematically sound password recommendations using Python's `secrets` module.
- **Cryptographic Hashing:** Implements isolated salting accompanied by SHA-256 compression layers to store records without revealing structural data.
- **Anti-Reuse Policy:** Validates real-time submissions against structural SQLite logs.

## Setup & Execution
Run the following script directly via a console window:
```bash
python main.py