# Password Strength Analyzer

A Python command-line learning project that evaluates password characteristics, provides improvement suggestions, generates a password suggestion, and checks password reuse using a local SQLite history.

> **Project scope:** This is an educational tool, not a password manager or production authentication system. Do not enter real or reused account passwords.

## Purpose

The project explores introductory password-security concepts, simple pattern checks, character-pool entropy estimation and local persistence with SQLite.

## Features

- Checks password length and the presence of lowercase letters, uppercase letters, digits and symbols.
- Flags entries found in a small built-in common-password list.
- Detects repeated characters and simple ascending or descending character sequences.
- Estimates entropy from the character pool represented in the password.
- Calculates a project-defined score out of 9 and displays a strength label.
- Provides suggestions for improving the entered password.
- Optionally stores a password hash in a local SQLite database and checks later entries for reuse by username.
- Uses hidden terminal input for password entry.
- Generates a password suggestion when the score is weak/moderate or the password is reused.

## Requirements

- Python 3.7 or later
- No third-party packages. The project uses Python standard-library modules, including `sqlite3`.

## Installation

```bash
git clone https://github.com/manojga56565/Password-Strength-Analyzer.git
cd Password-Strength-Analyzer
python -m pip install -r requirements.txt
```

## Usage

```bash
python password_strength_analyzer.py
```

Enter a username, then enter a test password when prompted. Choose whether to save its hash to the local history. The database file `password_history.db` is created beside the script.

## Sample output

The following is an illustrative excerpt. Exact values depend on the entered password and local history.

```text
PASSWORD STRENGTH REPORT
Length          : 14
Uppercase       : Yes
Lowercase       : Yes
Digits          : Yes
Symbols         : Yes
Common password : No
Repeated chars  : No
Sequential chars: No
Entropy (bits)  : <estimated value>
[####################] 9/9
Rating          : Very Strong
Reuse check     : OK - not found in your password history
```

## Limitations and security notes

- Password-history entries currently use unsalted SHA-256. This is not suitable for securely storing real passwords. Production systems should use a password-hashing algorithm designed for passwords, such as Argon2id or bcrypt, with appropriate parameters and salts.
- The built-in common-password list is small and is not comprehensive.
- The entropy figure is a simplified character-pool estimate, not a guarantee of real-world password strength.
- Password suggestions currently use Python's `random` module, which is not intended for cryptographic password generation.
- Password history is stored locally in an SQLite database and is not encrypted by this application.

## What I learned

- Checking password length, character classes and simple patterns.
- Implementing a basic entropy estimate.
- Using SQLite for local persistence and parameterized queries.
- Comparing password-history hashes to identify reuse.
- Documenting the security limitations of a learning tool.

## Responsible use

Use only test passwords that you control. Avoid entering real or reused account passwords into experimental tools.
