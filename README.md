# Password Strength Analyzer

A command-line tool that evaluates password strength based on length,
complexity, and uniqueness, suggests stronger alternatives, and prevents
reuse of previously used passwords via a local SQLite database.

## Features
- Checks length, uppercase/lowercase, digits, symbols
- Detects common passwords, repeated characters, sequential characters
- Estimates entropy (bits) as a strength measure
- Scores password out of 9 and rates it (Very Weak → Very Strong)
- Suggests a randomly generated strong password when needed
- Tracks password history per username in `password_history.db`
  (SQLite) and warns if a password has been reused
- Passwords are stored as SHA-256 hashes, never in plain text

## Requirements
- Python 3.7+
- No external packages needed (uses only the standard library)

## How to Run
```bash
python3 password_strength_analyzer.py
```

Follow the prompts:
1. Enter a username (used to track your password history)
2. Enter a password to analyze (input is hidden)
3. Review the strength report and suggestions
4. Optionally save the password to history to prevent future reuse

Type `quit` at any prompt to exit.

## Notes
- SHA-256 hashing (without salt) is used here for simplicity/education.
  In a real production system, use a proper password hashing algorithm
  such as bcrypt or Argon2 with per-user salts.
- The common-password list included is a small sample; expand
  `COMMON_PASSWORDS` in the script for stronger detection.
- The SQLite database file `password_history.db` is created
  automatically in the same folder as the script on first run.

## Learning Outcome
This project demonstrates password security fundamentals and basic
cryptography concepts: entropy calculation, hashing, pattern detection
(repeats/sequences), and secure password generation.
