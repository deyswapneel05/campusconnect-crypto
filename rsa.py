#!/usr/bin/env python3
"""
rsa.py — CampusConnect Part 2, Task 1: RSA implementation

Usage:
    python3 rsa.py                      # runs both built-in test cases
    python3 rsa.py <p> <q> <e> <m>       # runs one custom case with your own values

Validity constraints enforced:
    - p and q must be distinct primes (script refuses to run if p == q,
      or if either p or q is not prime).
    - The plaintext message m must satisfy 0 <= m < n.
    - The private exponent d is computed as the UNIQUE value in the
      range 0 <= d < phi(n) that satisfies d * e mod phi(n) == 1 — i.e.
      the smallest non-negative modular inverse, not merely "any"
      integer solution to d*e = 1 + k*phi(n).
    - e must satisfy 1 < e < phi(n) and gcd(e, phi(n)) == 1.
"""

import sys


def is_prime(n: int) -> bool:
    """Simple deterministic primality test (trial division), fine for
    the small numbers used in this assignment."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int):
    """Returns (g, x, y) such that a*x + b*y = g = gcd(a, b)."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    x, y = y1, x1 - (a // b) * y1
    return g, x, y


def modinv(e: int, phi_n: int) -> int:
    """Returns the unique smallest non-negative d such that
    d * e mod phi_n == 1. Raises ValueError if e has no inverse
    mod phi_n (i.e., gcd(e, phi_n) != 1)."""
    g, x, _ = extended_gcd(e, phi_n)
    if g != 1:
        raise ValueError(f"e={e} has no modular inverse mod phi(n)={phi_n} "
                          f"(gcd(e, phi(n)) = {g}, not 1)")
    # x may be negative; reduce to the smallest non-negative representative
    d = x % phi_n
    return d


def select_valid_e(phi_n: int, preferred_e: int | None = None) -> int:
    """Validates a caller-supplied e, or, if none supplied, selects the
    smallest valid e > 2 that is coprime to phi(n)."""
    if preferred_e is not None:
        e = preferred_e
        if not (1 < e < phi_n):
            raise ValueError(f"e={e} does not satisfy 1 < e < phi(n)={phi_n}")
        if gcd(e, phi_n) != 1:
            raise ValueError(f"e={e} is not coprime to phi(n)={phi_n} "
                             f"(gcd = {gcd(e, phi_n)})")
        return e
    # auto-select the smallest valid candidate
    for candidate in range(3, phi_n):
        if gcd(candidate, phi_n) == 1:
            return candidate
    raise ValueError("No valid e found for this phi(n)")


def rsa_run(p: int, q: int, m: int, e: int | None = None, label: str = ""):
    print(f"--- RSA test case {label} ---")
    print(f"Input: p = {p}, q = {q}, m = {m}" + (f", e = {e}" if e is not None else ""))

    # --- validity constraint: p, q must be distinct primes ---
    if not is_prime(p):
        raise ValueError(f"p = {p} is not prime; refusing to run.")
    if not is_prime(q):
        raise ValueError(f"q = {q} is not prime; refusing to run.")
    if p == q:
        raise ValueError(f"p and q must be distinct primes, but p == q == {p}; refusing to run.")

    n = p * q
    phi_n = (p - 1) * (q - 1)
    print(f"n = p * q = {p} * {q} = {n}")
    print(f"phi(n) = (p-1)(q-1) = {p-1} * {q-1} = {phi_n}")

    # --- validity constraint: 0 <= m < n ---
    if not (0 <= m < n):
        raise ValueError(f"m = {m} does not satisfy 0 <= m < n = {n}; refusing to run.")

    e = select_valid_e(phi_n, preferred_e=e)
    d = modinv(e, phi_n)
    # sanity-check: confirm d is truly the modular inverse (smallest non-negative)
    assert 0 <= d < phi_n and (d * e) % phi_n == 1, "computed d failed self-check"
    print(f"e = {e}  (public exponent: 1 < e < phi(n), gcd(e, phi(n)) = {gcd(e, phi_n)})")
    print(f"d = {d}  (private exponent: unique value in [0, phi(n)) with d*e mod phi(n) = 1)")

    c = pow(m, e, n)
    print(f"Encrypt:  c = m^e mod n = {m}^{e} mod {n} = {c}")

    recovered_m = pow(c, d, n)
    print(f"Decrypt:  m = c^d mod n = {c}^{d} mod {n} = {recovered_m}")

    ok = (recovered_m == m)
    print(f"Round-trip check: recovered m == original m? {ok}")
    print()
    return ok


def main():
    args = sys.argv[1:]
    if args:
        if len(args) != 4:
            print("Usage: python3 rsa.py <p> <q> <e> <m>")
            sys.exit(1)
        p, q, e, m = (int(x) for x in args)
        ok = rsa_run(p, q, m, e=e, label="(custom, from command line)")
        sys.exit(0 if ok else 1)

    # --- Test case (a): worked example from the assignment ---
    ok_a = rsa_run(p=3, q=11, m=4, e=3, label="(a) worked example p=3, q=11, e=3, m=4")

    # --- Test case (b): additional pair of primes and message of our choosing ---
    # Classic textbook-scale RSA numbers: p=61, q=53, e=17, m=65
    ok_b = rsa_run(p=61, q=53, m=65, e=17, label="(b) additional case p=61, q=53, e=17, m=65")

    if ok_a and ok_b:
        print("All RSA test cases passed: decrypted message equals original m in every case.")
    else:
        print("FAILURE: at least one RSA test case did not round-trip correctly.")
        sys.exit(1)


if __name__ == "__main__":
    main()
