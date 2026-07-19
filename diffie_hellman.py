#!/usr/bin/env python3
"""
diffie_hellman.py — CampusConnect Part 2, Task 2: Diffie-Hellman key exchange

Usage:
    python3 diffie_hellman.py                       # runs both built-in test cases
    python3 diffie_hellman.py <p> <alpha> <a> <b>     # runs one custom case

Validity constraints enforced:
    - alpha must be a primitive root modulo p.
    - Each private key a and b must satisfy 1 < a, b < p - 1.
"""

import sys


def is_prime(n: int) -> bool:
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


def prime_factors(n: int) -> set:
    """Distinct prime factors of n (trial division; fine for assignment-scale numbers)."""
    factors = set()
    d = 2
    temp = n
    while d * d <= temp:
        while temp % d == 0:
            factors.add(d)
            temp //= d
        d += 1
    if temp > 1:
        factors.add(temp)
    return factors


def is_primitive_root(alpha: int, p: int) -> bool:
    """alpha is a primitive root mod p (p prime) iff for every distinct
    prime factor q of (p-1), alpha^((p-1)/q) mod p != 1."""
    if not is_prime(p):
        raise ValueError(f"p = {p} is not prime; primitive-root check requires prime p.")
    phi = p - 1
    for q in prime_factors(phi):
        if pow(alpha, phi // q, p) == 1:
            return False
    return True


def dh_run(p: int, alpha: int, a: int, b: int, label: str = ""):
    print(f"--- Diffie-Hellman test case {label} ---")
    print(f"Input: p = {p}, alpha = {alpha}, a (Alice's private key) = {a}, "
          f"b (Bob's private key) = {b}")

    # --- validity constraint: alpha must be a primitive root mod p ---
    if not is_primitive_root(alpha, p):
        raise ValueError(f"alpha = {alpha} is not a primitive root modulo p = {p}; refusing to run.")

    # --- validity constraint: 1 < a, b < p - 1 ---
    if not (1 < a < p - 1):
        raise ValueError(f"a = {a} does not satisfy 1 < a < p-1 = {p-1}; refusing to run.")
    if not (1 < b < p - 1):
        raise ValueError(f"b = {b} does not satisfy 1 < b < p-1 = {p-1}; refusing to run.")

    # Alice computes her public value and sends it to Bob
    A = pow(alpha, a, p)
    # Bob computes his public value and sends it to Alice
    B = pow(alpha, b, p)
    print(f"Alice computes A = alpha^a mod p = {alpha}^{a} mod {p} = {A}  (sent to Bob)")
    print(f"Bob computes   B = alpha^b mod p = {alpha}^{b} mod {p} = {B}  (sent to Alice)")

    # Each side independently derives the shared secret
    K_alice = pow(B, a, p)   # Alice: K = B^a mod p
    K_bob = pow(A, b, p)     # Bob:   K = A^b mod p
    print(f"Alice computes K = B^a mod p = {B}^{a} mod {p} = {K_alice}")
    print(f"Bob computes   K = A^b mod p = {A}^{b} mod {p} = {K_bob}")

    match = (K_alice == K_bob)
    print(f"Shared secrets match? {match}")
    print()
    return match


def main():
    args = sys.argv[1:]
    if args:
        if len(args) != 4:
            print("Usage: python3 diffie_hellman.py <p> <alpha> <a> <b>")
            sys.exit(1)
        p, alpha, a, b = (int(x) for x in args)
        ok = dh_run(p, alpha, a, b, label="(custom, from command line)")
        sys.exit(0 if ok else 1)

    # --- Worked example from the assignment ---
    ok_a = dh_run(p=29, alpha=2, a=5, b=12, label="(worked example) p=29, alpha=2, a=5, b=12")

    # --- Additional set of values ---
    # p=23 is prime, alpha=5 is a primitive root of 23, private keys satisfy 1 < a,b < 22
    ok_b = dh_run(p=23, alpha=5, a=6, b=15, label="(additional) p=23, alpha=5, a=6, b=15")

    if ok_a and ok_b:
        print("All Diffie-Hellman test cases passed: both computed values of K match in every case.")
    else:
        print("FAILURE: at least one Diffie-Hellman test case did not produce matching K values.")
        sys.exit(1)


if __name__ == "__main__":
    main()
