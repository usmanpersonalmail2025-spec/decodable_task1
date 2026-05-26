# DecodeLabs Project 1 - Password Strength Checker
# Batch 2026

import re
import hmac

def constant_time_compare(a, b):
    """Prevent timing attacks"""
    return hmac.compare_digest(a.encode(), b.encode())

def check_password(password):
    """Pure string-handling and conditional logic"""
    
    # GATEKEEPER RULE: Validate before processing
    if not password or password.isspace():
        return "INVALID", ["Password cannot be empty"]
    
    length = len(password)
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    
    # CONDITIONAL LOGIC for strength rating
    if length >= 12 and has_upper and has_lower and has_digit and has_special:
        return "STRONG", []
    
    elif length >= 8 and has_upper and has_lower and (has_digit or has_special):
        return "MODERATE", ["Use 12+ chars and special characters for STRONG"]
    
    else:
        issues = []
        if length < 8:
            issues.append("Minimum 8 characters required")
        if not has_upper:
            issues.append("Add uppercase letters (A-Z)")
        if not has_lower:
            issues.append("Add lowercase letters (a-z)")
        if not has_digit:
            issues.append("Add numbers (0-9)")
        if not has_special:
            issues.append("Add special characters (!@#$ etc.)")
        return "WEAK", issues

def main():
    print("\n" + "=" * 40)
    print("PASSWORD STRENGTH CHECKER")
    print("DecodeLabs - Project 1")
    print("=" * 40)
    
    pwd = input("\nEnter password: ")
    confirm = input("Confirm password: ")
    
    # Gatekeeper
    if not pwd:
        print("\nError: Password cannot be empty")
        return
    
    # Constant-time comparison
    if not constant_time_compare(pwd, confirm):
        print("\nError: Passwords do not match")
        return
    
    # Check strength
    strength, feedback = check_password(pwd)
    
    # Output
    print("\n" + "=" * 40)
    print(f"Strength: {strength}")
    print("=" * 40)
    
    for item in feedback:
        print(f"• {item}")
    
    if not feedback and strength == "STRONG":
        print("✓ Password meets all security criteria")
    
    print()

if __name__ == "__main__":
    main()