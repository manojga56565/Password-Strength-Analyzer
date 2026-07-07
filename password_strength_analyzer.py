#!/usr/bin/env python3
"""
Password Strength Analyzer
---------------------------
Evaluates the strength of user-entered passwords based on length,
complexity, and uniqueness. Suggests stronger alternatives, and
prevents reuse of old passwords using a local SQLite database.

Author: Manohar Salakula
Project: Password Strength Analyzer (Task 1)
"""

import re
import math
import random
import string
import sqlite3
import hashlib
import getpass
import os
from datetime import datetime

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "password_history.db")

# Common weak passwords list (small sample; extend as needed)
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345",
    "qwerty", "abc123", "password1", "111111", "123123",
    "admin", "letmein", "welcome", "monkey", "iloveyou",
    "dragon", "master", "sunshine", "princess", "football"
}


# -----------------------------
# Database setup
# -----------------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def hash_password(password: str) -> str:
    """Return a SHA-256 hash of the password (salting omitted for
    simplicity in this educational tool; use bcrypt/argon2 in production)."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def is_password_reused(username: str, password: str) -> bool:
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(
        "SELECT password_hash FROM password_history WHERE username = ?",
        (username,)
    )
    rows = cur.fetchall()
    conn.close()
    hashed = hash_password(password)
    return any(hashed == row[0] for row in rows)


def store_password(username: str, password: str):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO password_history (username, password_hash, created_at) VALUES (?, ?, ?)",
        (username, hash_password(password), datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


# -----------------------------
# Strength analysis
# -----------------------------
def calculate_entropy(password: str) -> float:
    """Estimate password entropy in bits based on character pool size."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def analyze_password(password: str) -> dict:
    result = {
        "length": len(password),
        "has_lower": bool(re.search(r"[a-z]", password)),
        "has_upper": bool(re.search(r"[A-Z]", password)),
        "has_digit": bool(re.search(r"[0-9]", password)),
        "has_symbol": bool(re.search(r"[^a-zA-Z0-9]", password)),
        "is_common": password.lower() in COMMON_PASSWORDS,
        "has_repeats": bool(re.search(r"(.)\1{2,}", password)),
        "has_sequence": has_sequential_chars(password),
        "entropy": calculate_entropy(password),
    }

    score = 0
    if result["length"] >= 8:
        score += 1
    if result["length"] >= 12:
        score += 1
    if result["has_lower"]:
        score += 1
    if result["has_upper"]:
        score += 1
    if result["has_digit"]:
        score += 1
    if result["has_symbol"]:
        score += 1
    if not result["is_common"]:
        score += 1
    if not result["has_repeats"]:
        score += 1
    if not result["has_sequence"]:
        score += 1

    result["score"] = score
    result["max_score"] = 9

    if result["is_common"] or result["length"] < 6:
        result["rating"] = "Very Weak"
    elif score <= 3:
        result["rating"] = "Weak"
    elif score <= 5:
        result["rating"] = "Moderate"
    elif score <= 7:
        result["rating"] = "Strong"
    else:
        result["rating"] = "Very Strong"

    return result


def has_sequential_chars(password: str, run_length: int = 3) -> bool:
    """Detect ascending/descending sequences like 'abc' or '321'."""
    lower = password.lower()
    for i in range(len(lower) - run_length + 1):
        chunk = lower[i:i + run_length]
        if all(ord(chunk[j + 1]) - ord(chunk[j]) == 1 for j in range(len(chunk) - 1)):
            return True
        if all(ord(chunk[j]) - ord(chunk[j + 1]) == 1 for j in range(len(chunk) - 1)):
            return True
    return False


# -----------------------------
# Suggestions
# -----------------------------
def suggest_strong_password(length: int = 14) -> str:
    """Generate a strong random password suggestion."""
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+"

    all_chars = lower + upper + digits + symbols
    password = [
        random.choice(lower),
        random.choice(upper),
        random.choice(digits),
        random.choice(symbols),
    ]
    password += [random.choice(all_chars) for _ in range(length - len(password))]
    random.shuffle(password)
    return "".join(password)


def get_feedback(analysis: dict) -> list:
    tips = []
    if analysis["length"] < 12:
        tips.append("Use at least 12 characters for better security.")
    if not analysis["has_upper"]:
        tips.append("Add uppercase letters (A-Z).")
    if not analysis["has_lower"]:
        tips.append("Add lowercase letters (a-z).")
    if not analysis["has_digit"]:
        tips.append("Add numbers (0-9).")
    if not analysis["has_symbol"]:
        tips.append("Add special symbols (!@#$%, etc.).")
    if analysis["is_common"]:
        tips.append("Avoid commonly used passwords.")
    if analysis["has_repeats"]:
        tips.append("Avoid repeating the same character 3+ times in a row.")
    if analysis["has_sequence"]:
        tips.append("Avoid sequential characters like 'abc' or '321'.")
    return tips


# -----------------------------
# Display helpers
# -----------------------------
def print_bar(score: int, max_score: int):
    filled = int((score / max_score) * 20)
    bar = "#" * filled + "-" * (20 - filled)
    print(f"[{bar}] {score}/{max_score}")


def print_report(analysis: dict, reused: bool):
    print("\n" + "=" * 45)
    print("        PASSWORD STRENGTH REPORT")
    print("=" * 45)
    print(f"Length          : {analysis['length']}")
    print(f"Uppercase       : {'Yes' if analysis['has_upper'] else 'No'}")
    print(f"Lowercase       : {'Yes' if analysis['has_lower'] else 'No'}")
    print(f"Digits          : {'Yes' if analysis['has_digit'] else 'No'}")
    print(f"Symbols         : {'Yes' if analysis['has_symbol'] else 'No'}")
    print(f"Common password : {'Yes (bad)' if analysis['is_common'] else 'No'}")
    print(f"Repeated chars  : {'Yes (bad)' if analysis['has_repeats'] else 'No'}")
    print(f"Sequential chars: {'Yes (bad)' if analysis['has_sequence'] else 'No'}")
    print(f"Entropy (bits)  : {analysis['entropy']:.1f}")
    print("-" * 45)
    print_bar(analysis["score"], analysis["max_score"])
    print(f"Rating          : {analysis['rating']}")
    if reused:
        print("Reuse check     : WARNING - matches a previously used password!")
    else:
        print("Reuse check     : OK - not found in your password history")
    print("=" * 45)

    tips = get_feedback(analysis)
    if tips:
        print("\nSuggestions to improve:")
        for tip in tips:
            print(f"  - {tip}")

    if analysis["rating"] in ("Weak", "Very Weak", "Moderate") or reused:
        print(f"\nTry a stronger alternative: {suggest_strong_password()}")


# -----------------------------
# Main program
# -----------------------------
def main():
    init_db()
    print("=" * 45)
    print("   PASSWORD STRENGTH ANALYZER")
    print("=" * 45)
    print("Type 'quit' at any prompt to exit.\n")

    while True:
        username = input("Enter username (for reuse tracking): ").strip()
        if username.lower() == "quit":
            break
        if not username:
            print("Username cannot be empty.\n")
            continue

        password = getpass.getpass("Enter password to analyze: ")
        if password.lower() == "quit":
            break
        if not password:
            print("Password cannot be empty.\n")
            continue

        analysis = analyze_password(password)
        reused = is_password_reused(username, password)
        print_report(analysis, reused)

        if not reused:
            save = input("\nSave this password to your history? (y/n): ").strip().lower()
            if save == "y":
                store_password(username, password)
                print("Saved to password history.")

        again = input("\nAnalyze another password? (y/n): ").strip().lower()
        print()
        if again != "y":
            break

    print("Goodbye!")


if __name__ == "__main__":
    main()
