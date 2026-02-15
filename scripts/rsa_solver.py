#!/usr/bin/env python3
"""
RSA Small Public Exponent Attack Solver

Exploits RSA when e is small (typically e=3) and the plaintext message m
is small enough that m^e < n, meaning the modular reduction never applies.

Usage:
    python3 rsa_solver.py
    python3 rsa_solver.py --n <modulus> --e <exponent> --c <ciphertext>

Supports:
    - Direct cube root attack (m^e < n)
    - Hastad's broadcast attack (same m encrypted under multiple moduli)
"""

import argparse
import sys

try:
    import gmpy2
except ImportError:
    print("Error: gmpy2 is required. Install with: pip install gmpy2")
    sys.exit(1)


def integer_root_attack(n: int, e: int, c: int) -> bytes | None:
    """
    Direct integer root attack.

    If m^e < n, then c = m^e (no modular reduction), and m = c^(1/e).
    """
    m, is_exact = gmpy2.iroot(c, e)

    if is_exact:
        m_int = int(m)
        try:
            plaintext = m_int.to_bytes((m_int.bit_length() + 7) // 8, "big")
            return plaintext
        except OverflowError:
            return None
    return None


def hastad_broadcast_attack(
    pairs: list[tuple[int, int]], e: int
) -> bytes | None:
    """
    Hastad's broadcast attack using the Chinese Remainder Theorem.

    Given e pairs of (n_i, c_i) where the same message m was encrypted
    with the same small exponent e under different moduli, reconstruct
    m^e using CRT and then compute the integer e-th root.

    Args:
        pairs: List of (modulus, ciphertext) tuples.
        e: The public exponent (must equal len(pairs)).
    """
    if len(pairs) < e:
        print(f"Error: Need at least {e} pairs for Hastad's attack, got {len(pairs)}")
        return None

    pairs = pairs[:e]
    moduli = [p[0] for p in pairs]
    ciphertexts = [p[1] for p in pairs]

    # Compute product of all moduli
    N = 1
    for n in moduli:
        N *= n

    # Chinese Remainder Theorem
    result = 0
    for i in range(e):
        Ni = N // moduli[i]
        # Modular inverse of Ni mod moduli[i]
        yi = int(gmpy2.invert(Ni, moduli[i]))
        result += ciphertexts[i] * Ni * yi

    result = result % N

    # Now result = m^e (over the integers, reconstructed via CRT)
    m, is_exact = gmpy2.iroot(result, e)

    if is_exact:
        m_int = int(m)
        try:
            plaintext = m_int.to_bytes((m_int.bit_length() + 7) // 8, "big")
            return plaintext
        except OverflowError:
            return None
    return None


def solve_challenge() -> None:
    """Solve the CTF challenge with the provided values."""
    # Challenge parameters
    n = int(
        "6528060431134312098979986223024489565526932471806448564536469573046"
        "2093884132866862783900959153839493828194832026289924937797725669992"
        "1394812830511547181882839043654414361801527073771468092147856988826"
        "8839827028564639193248324096339581689662962043645269409315691045637"
        "1"
    )
    e = 3
    c = 108972958430310775283815601557015300139058292082239249540391578556530581803254020

    print(f"Modulus (n):     {n}")
    print(f"Exponent (e):    {e}")
    print(f"Ciphertext (c):  {c}")
    print()

    # Check if c < n (necessary condition for direct root attack)
    if c < n:
        print("[*] c < n: Direct integer root attack is viable")
    else:
        print("[!] c >= n: Direct root may not work, trying anyway...")

    print("[*] Computing integer cube root of ciphertext...")

    result = integer_root_attack(n, e, c)

    if result:
        try:
            flag = result.decode("ascii")
            print(f"[+] Decrypted flag: {flag}")
        except UnicodeDecodeError:
            print(f"[+] Decrypted (hex): {result.hex()}")
    else:
        print("[-] Direct root attack failed (m^e > n)")
        print("[-] Try Hastad's broadcast attack with multiple ciphertexts")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="RSA small exponent attack solver"
    )
    parser.add_argument("--n", type=int, help="RSA modulus")
    parser.add_argument("--e", type=int, default=3, help="Public exponent (default: 3)")
    parser.add_argument("--c", type=int, help="Ciphertext")
    parser.add_argument(
        "--challenge",
        action="store_true",
        help="Solve the CTF challenge with built-in values",
    )

    args = parser.parse_args()

    if args.challenge or (args.n is None and args.c is None):
        solve_challenge()
    elif args.n and args.c:
        print(f"[*] Attempting integer root attack with e={args.e}")
        result = integer_root_attack(args.n, args.e, args.c)
        if result:
            try:
                print(f"[+] Decrypted: {result.decode('ascii')}")
            except UnicodeDecodeError:
                print(f"[+] Decrypted (hex): {result.hex()}")
        else:
            print("[-] Attack failed. The message may be too large for direct root.")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
