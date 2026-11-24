# Password Strength Analyzer

A Python command-line project that evaluates password characteristics, gives improvement suggestions, generates stronger alternatives, and checks password reuse using a local SQLite history.

> **Project scope:** Educational security tool. It is not a password manager or a production authentication system.

## Features

- Checks password length and character variety (lowercase, uppercase, digits, and symbols)
- Flags a small built-in list of common passwords
- Detects repeated characters and simple ascending/descending sequences
- Estimates character-pool entropy as an educational indicator
- Produces a score out of 9 with a strength label
- Suggests a generated password when the result is weak or reused
- Tracks password history per username in SQLite
- Uses hidden terminal input for password entry

## Built with

- Python
- SQLite
- Python standard library

## Run locally

1. Clone this repository.
2. Open a terminal in the project directory.
3. Run:

```bash
python3 password_strength_analyzer.py
```

No third-party packages are required.

## How it works

1. Enter a username for local history tracking.
2. Enter a password (terminal input is hidden).
3. The analyzer checks length, character classes, common-password membership, repeated characters, and simple sequences.
4. It displays a score, estimated entropy, and suggestions.
5. You can optionally save a password hash to the local SQLite history to check for reuse later.

The database file `password_history.db` is created automatically beside the script.

## Important security notes

- This project currently uses unsalted SHA-256 for its local password-history comparison. This is **not suitable for securely storing real passwords**. Production systems should use a password-hashing scheme designed for passwords, such as Argon2id or bcrypt, with appropriate parameters and salts.
- The built-in common-password list is intentionally small and is not comprehensive.
- The entropy figure is a simplified estimate based on the character classes present; it is not a guarantee of real-world password strength.
- Password generation currently uses Python's `random` module, which is not intended for cryptographic password generation.

## Learning objectives

This project demonstrates introductory password-security concepts, pattern checks, basic entropy estimation, local persistence with SQLite, and password-reuse detection.

## Responsible use

Use this project for learning and testing with passwords you control. Avoid entering real or reused account passwords into experimental tools.
