#!/usr/bin/env python3
"""password_hash - Password hashing with salt, PBKDF2, and bcrypt-style rounds."""
import sys, hashlib, os, hmac, struct

def generate_salt(length=16):
    return os.urandom(length)

def pbkdf2_hash(password, salt=None, iterations=100000, dklen=32):
    if salt is None:
        salt = generate_salt()
    if isinstance(password, str):
        password = password.encode()
    dk = hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen)
    return salt, dk

def verify_pbkdf2(password, salt, expected_hash, iterations=100000, dklen=32):
    _, dk = pbkdf2_hash(password, salt, iterations, dklen)
    return hmac.compare_digest(dk, expected_hash)

def simple_hash(password, salt=None, rounds=10):
    if salt is None:
        salt = generate_salt(8)
    if isinstance(password, str):
        password = password.encode()
    h = hashlib.sha256(salt + password).digest()
    for _ in range(rounds):
        h = hashlib.sha256(h + salt).digest()
    return salt, h

def password_strength(password):
    score = 0
    if len(password) >= 8: score += 1
    if len(password) >= 12: score += 1
    if any(c.isupper() for c in password): score += 1
    if any(c.islower() for c in password): score += 1
    if any(c.isdigit() for c in password): score += 1
    if any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/" for c in password): score += 1
    labels = {0:"very weak",1:"weak",2:"weak",3:"fair",4:"good",5:"strong",6:"very strong"}
    return score, labels.get(score, "very strong")

def test():
    salt, h = pbkdf2_hash("mypassword")
    assert len(salt) == 16
    assert len(h) == 32
    assert verify_pbkdf2("mypassword", salt, h)
    assert not verify_pbkdf2("wrongpassword", salt, h)
    salt2, h2 = simple_hash("test123")
    assert len(h2) == 32
    s, label = password_strength("Ab1!xyzw")
    assert s >= 4
    s2, label2 = password_strength("abc")
    assert s2 <= 2
    print("OK: password_hash")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        test()
    else:
        print("Usage: password_hash.py test")
