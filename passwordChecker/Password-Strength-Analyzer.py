import string
import re
import secrets
import hashlib
import sqlite3
from getpass import getpass


# ==========================================
# 1. DATABASE & CRYPTOGRAPHY FUNCTIONS
# ==========================================

def init_db():
    """Initializes a local SQLite database to store password history securely."""
    conn = sqlite3.connect("password_history.db")
    cursor = conn.cursor()
    # Stores user_id, a unique salt, and the salted password hash
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_repo (
            user_id TEXT,
            salt TEXT,
            password_hash TEXT
        )
    ''')
    conn.commit()
    conn.close()


def hash_password(password, salt):
    """
    Applies Salting and Hashing using SHA-256.
    Combines the password with a unique salt so identical passwords
    produce completely different hashes.
    """
    salted_password = password + salt
    return hashlib.sha256(salted_password.encode()).hexdigest()


def is_password_reused(user_id, new_password):
    """Checks the database to see if the user has used this password before."""
    conn = sqlite3.connect("password_history.db")
    cursor = conn.cursor()

    cursor.execute("SELECT salt, password_hash FROM password_repo WHERE user_id = ?", (user_id,))
    records = cursor.fetchall()

    for salt, stored_hash in records:
        # Hash the incoming password with the historical salt to check for a match
        if hash_password(new_password, salt) == stored_hash:
            conn.close()
            return True

    conn.close()
    return False


def save_password(user_id, password):
    """Generates a secure cryptographically random salt and saves the record."""
    conn = sqlite3.connect("password_history.db")
    cursor = conn.cursor()

    # Generate a cryptographically secure 16-byte random salt
    salt = secrets.token_hex(16)
    p_hash = hash_password(password, salt)

    cursor.execute("INSERT INTO password_repo VALUES (?, ?, ?)", (user_id, salt, p_hash))
    conn.commit()
    conn.close()


# ==========================================
# 2. CORE EVALUATOR MECHANISM
# ==========================================

def analyze_password_strength(password):
    """
    Evaluates password entropy based on length, complexity,
    and common structural vulnerabilities.
    """
    score = 0
    feedback = []

    # Criteria 1: Length Check
    length = len(password)
    if length >= 12:
        score += 2
    elif length >= 8:
        score += 1
    else:
        feedback.append("• Password is too short (Minimum recommended length is 8-12 characters).")

    # Criteria 2: Complexity Checks via Regular Expressions
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("• Missing lowercase letters (a-z).")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("• Missing uppercase letters (A-Z).")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("• Missing numbers (0-9).")

    if re.search(r"[{}]".format(re.escape(string.punctuation)), password):
        score += 1
    else:
        feedback.append("• Missing special characters (e.g., !, @, #, $, %).")

    # Criteria 3: Basic Common Weak Patterns Check
    common_sequences = ["123", "abc", "qwerty", "password"]
    if any(seq in password.lower() for seq in common_sequences):
        score = max(0, score - 2)  # Penalize score heavily for lazy sequences
        feedback.append("• Contains weak sequential/common patterns (like '123' or 'qwerty').")

    # Mapping scores to readable tiers
    # Max possible base points is 7, adjusting scale out of 5
    final_rating = "Very Weak"
    if score >= 6:
        final_rating = "Excellent / Very Strong"
    elif score >= 4:
        final_rating = "Strong"
    elif score >= 3:
        final_rating = "Moderate"
    elif score >= 2:
        final_rating = "Weak"

    return final_rating, feedback


# ==========================================
# 3. SECURE PASS GENERATOR (CSPRNG)
# ==========================================

def generate_strong_alternative():
    """Uses the secrets module (CSPRNG) to build an unguessable 16-character password."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        # Guarantee entropy by picking characters randomly
        password = ''.join(secrets.choice(alphabet) for _ in range(16))
        # Ensure it passes our own strongest check before returning
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and sum(c.isdigit() for c in password) >= 2):
            return password


# ==========================================
# 4. USER INTERFACE (CLI EXECUTION)
# ==========================================

def main():
    init_db()
    print("==================================================")
    print("      CYBERSECURITY: PASSWORD STRENGTH ANALYZER   ")
    print("==================================================")

    user_id = input("Enter your Username: ").strip().lower()
    if not user_id:
        print("Username cannot be empty. Exiting.")
        return

    # getpass hides user terminal inputs to prevent "shoulder surfing"
    user_pass = getpass("Enter password to evaluate: ")

    if not user_pass:
        print("Password cannot be empty.")
        return

    # Check Database for History Reuse (Cybersecurity Constraint)
    if is_password_reused(user_id, user_pass):
        print("\n[!] SECURITY ALERT: You cannot reuse this password! It matches your past history.")
        print("Generating a completely unique, secure suggestion for you...")
        print(f"Suggested Password: {generate_strong_alternative()}")
        return

    # Evaluate the active strength
    rating, improvements = analyze_password_strength(user_pass)

    print("\n--- Evaluation Results ---")
    print(f"Overall Metric: {rating}")

    if improvements:
        print("\nVulnerabilities identified:")
        for point in improvements:
            print(point)

    # If the password is weak, automatically supply an alternative
    if rating in ["Very Weak", "Weak", "Moderate"]:
        print("\n[Recommendation] Switch to a randomly generated high-entropy option:")
        print(f"👉 Suggested Alternative: {generate_strong_alternative()}")
    else:
        # Commit securely to the database only if it's a solid, safe password
        save_password(user_id, user_pass)
        print("\n[✓] Password meets safety rules and has been securely hashed into database records.")


if __name__ == "__main__":
    main()