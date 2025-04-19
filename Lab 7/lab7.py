#!/usr/bin/env python3
"""
RSA Lab 7 - Small Prime Factor Attack

This script demonstrates how to decrypt an RSA ciphertext when one of the prime factors
is small enough to be easily factored (weak RSA key). It uses the process of:

1. Identifying the prime factors (p and q) of the modulus n
2. Computing the private exponent d
3. Decrypting the ciphertext

This lab illustrates an important security principle: RSA keys must use large, random
prime numbers of similar bit length to be secure.

Author: [Your Name]
Date: April 2025
"""

import argparse
import binascii
import json
import math
import time
from typing import Tuple, Dict, Optional, List


class RSAToolkit:
    """
    A toolkit for RSA cryptography operations, especially for analyzing and exploiting
    weak RSA keys.
    """

    @staticmethod
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        """
        Extended Euclidean Algorithm to find gcd(a, b) and coefficients x, y
        such that ax + by = gcd(a, b).

        Args:
            a: First integer
            b: Second integer

        Returns:
            Tuple of (gcd, x, y) where ax + by = gcd
        """
        if a == 0:
            return b, 0, 1

        # Initialize variables
        last_remainder, remainder = abs(a), abs(b)
        x, last_x, y, last_y = 0, 1, 1, 0

        # Compute extended GCD iteratively
        while remainder:
            quotient, remainder = divmod(last_remainder, remainder)
            x, last_x = last_x - quotient * x, x
            y, last_y = last_y - quotient * y, y
            last_remainder = remainder

        # Adjust signs based on input
        return (
            last_remainder,
            last_x * (-1 if a < 0 else 1),
            last_y * (-1 if b < 0 else 1)
        )

    @staticmethod
    def mod_inverse(a: int, m: int) -> int:
        """
        Calculate the modular multiplicative inverse of a modulo m.

        Args:
            a: Integer to find inverse for
            m: Modulus

        Returns:
            Modular multiplicative inverse

        Raises:
            ValueError: If a and m are not coprime (inverse doesn't exist)
        """
        gcd, x, y = RSAToolkit.extended_gcd(a, m)

        # Inverse exists only if gcd is 1
        if gcd != 1:
            raise ValueError(f"Modular inverse does not exist (gcd={gcd})")

        # Ensure the result is in the range [0, m-1]
        return x % m

    @staticmethod
    def compute_private_key(p: int, q: int, e: int) -> int:
        """
        Compute the RSA private exponent d from prime factors and public exponent.

        Args:
            p: First prime factor
            q: Second prime factor
            e: Public exponent

        Returns:
            Private exponent d

        Raises:
            ValueError: If e is not coprime with (p-1)(q-1)
        """
        # Calculate Euler's totient function φ(n) = (p-1)(q-1)
        phi_n = (p - 1) * (q - 1)

        try:
            # Calculate d as the modular inverse of e modulo φ(n)
            d = RSAToolkit.mod_inverse(e, phi_n)
            return d
        except ValueError as err:
            raise ValueError(f"Failed to compute private exponent: {err}")

    @staticmethod
    def decrypt_rsa(ciphertext: int, d: int, n: int) -> int:
        """
        Decrypt an RSA ciphertext using the private key.

        Args:
            ciphertext: The encrypted message as an integer
            d: Private exponent
            n: Modulus (product of p and q)

        Returns:
            Decrypted message as an integer
        """
        # m = c^d mod n
        return pow(ciphertext, d, n)

    @staticmethod
    def int_to_string(value: int) -> str:
        """
        Convert an integer to its string representation.

        Args:
            value: Integer to convert

        Returns:
            String representation of the integer

        Raises:
            ValueError: If the integer cannot be converted to a valid string
        """
        try:
            # Ensure the hex representation has an even number of digits
            hex_string = format(value, "x")
            if len(hex_string) % 2 != 0:
                hex_string = '0' + hex_string

            return binascii.unhexlify(hex_string.encode("utf-8")).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as e:
            raise ValueError(f"Failed to convert integer to string: {str(e)}")

    @staticmethod
    def trial_division(n: int, limit: int = 1_000_000) -> Optional[int]:
        """
        Find a small prime factor of n using trial division.

        Args:
            n: Number to factor
            limit: Maximum value to test for primality

        Returns:
            A small prime factor if found, None otherwise
        """
        # Check if n is even
        if n % 2 == 0:
            return 2

        # Check odd numbers up to the limit
        for i in range(3, min(limit, int(math.sqrt(n)) + 1), 2):
            if n % i == 0:
                return i

        return None

    @staticmethod
    def is_prime(n: int, k: int = 10) -> bool:
        """
        Check if a number is prime using Miller-Rabin primality test.

        Args:
            n: Number to check for primality
            k: Number of test rounds (higher values increase accuracy)

        Returns:
            True if the number is probably prime, False otherwise
        """
        import random

        # Handle small cases
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False

        # Express n as 2^r * d + 1
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        # Witness loop
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True


def main():
    """Main function to demonstrate RSA decryption with small prime attack."""
    parser = argparse.ArgumentParser(
        description="RSA Small Prime Factor Attack"
    )
    parser.add_argument('--n', type=str,
                        help='RSA modulus (product of p and q)')
    parser.add_argument('--e', type=int, default=65537,
                        help='Public exponent (default: 65537)')
    parser.add_argument('--p', type=str,
                        help='First prime factor (if known)')
    parser.add_argument('--ciphertext', type=str,
                        help='Ciphertext to decrypt (as a decimal integer)')
    parser.add_argument('--find-small-prime', action='store_true',
                        help='Attempt to find a small prime factor')
    parser.add_argument('--limit', type=int, default=1000000,
                        help='Limit for small prime search (default: 1,000,000)')
    parser.add_argument('--save', type=str,
                        help='Save calculation results to file')
    parser.add_argument('--verbose', action='store_true',
                        help='Show detailed calculation steps')
    args = parser.parse_args()

    try:
        # Default values
        n = 79832181757332818552764610761349592984614744432279135328398999801627880283610900361281249973175805069916210179560506497075132524902086881120372213626641879468491936860976686933630869673826972619938321951599146744807653301076026577949579618331502776303983485566046485431039541708467141408260220098592761245010678592347501894176269580510459729633673468068467144199744563731826362102608811033400887813754780282628099443490170016087838606998017490456601315802448567772411623826281747245660954245413781519794295336197555688543537992197142258053220453757666537840276416475602759374950715283890232230741542737319569819793988431443
        e = 65537
        c = 877047627503964563527859854056241853286548710266261291942543955818132370489959838496983429954434494528178229313135354793125902041844995518092695073588272773865176510386504459109444540504995243455296652458363596632448945407597570368304177404561607143991631472612686460090955582314803404185085391881900665937993904325795901688452399415391744151647251408176477627720933717024380735888111455809609800839992904182591275652616244755461341372866557636825262065485442416189938154309976219500988259186981644426083447522183242945513870008042818029602927271842718324310884266107435333212981162347887454715321088536179467180247805306
        p = 3133337  # A small prime factor - in a real scenario this may be found by factorization

        # Update values from command line args
        if args.n:
            n = int(args.n)
        if args.e:
            e = args.e
        if args.ciphertext:
            c = int(args.ciphertext)
        if args.p:
            p = int(args.p)

        # Try to find a small prime factor if requested
        if args.find_small_prime and not args.p:
            print(f"Searching for small prime factors up to {args.limit}...")
            start_time = time.time()
            p = RSAToolkit.trial_division(n, args.limit)
            elapsed = time.time() - start_time

            if p:
                print(f"Found small prime factor p = {p} in {elapsed:.2f} seconds")
            else:
                print(f"No small prime factors found up to {args.limit} in {elapsed:.2f} seconds")
                print("Consider using an online factorization service like factordb.com")
                return 1

        # Compute the second prime factor q
        q = n // p

        # Verify that p*q equals n
        if p * q != n:
            raise ValueError(f"Invalid prime factors: p*q ({p * q}) does not equal n ({n})")

        # Check if the factors are actually prime
        if args.verbose:
            print("Verifying primality of factors...")
            p_prime = RSAToolkit.is_prime(p)
            q_prime = RSAToolkit.is_prime(q)
            print(f"p is {'probably prime' if p_prime else 'composite'}")
            print(f"q is {'probably prime' if q_prime else 'composite'}")

            if not (p_prime and q_prime):
                print("Warning: One or both factors may not be prime. Results may be incorrect.")

        if args.verbose:
            print("\nRSA Parameters:")
            print(f"n = {n}")
            print(f"e = {e}")
            print(f"p = {p}")
            print(f"q = {q}")
            print(f"Bits in n: {n.bit_length()}")
            print(f"Bits in p: {p.bit_length()}")
            print(f"Bits in q: {q.bit_length()}")

        # Calculate Euler's totient function φ(n) = (p-1)(q-1)
        phi_n = (p - 1) * (q - 1)

        if args.verbose:
            print(f"φ(n) = (p-1)(q-1) = {phi_n}")

        # Compute the private exponent d
        d = RSAToolkit.compute_private_key(p, q, e)

        if args.verbose:
            print(f"d = {d}")

        # Decrypt the ciphertext
        start_time = time.time()
        decrypted_int = RSAToolkit.decrypt_rsa(c, d, n)
        elapsed = time.time() - start_time

        if args.verbose:
            print(f"Decryption time: {elapsed:.4f} seconds")

        # Convert to plaintext
        try:
            plaintext = RSAToolkit.int_to_string(decrypted_int)

            print("\nResults:")
            print(f"Decrypted plaintext: {plaintext}")

            # Generate and print the flag
            flag = f"ZD{{{plaintext}}}"
            print(f"Flag: {flag}")

            # Save results if requested
            if args.save:
                result = {
                    'n': str(n),
                    'e': e,
                    'd': str(d),
                    'p': str(p),
                    'q': str(q),
                    'phi_n': str(phi_n),
                    'ciphertext': str(c),
                    'plaintext': plaintext,
                    'flag': flag
                }

                with open(args.save, 'w') as f:
                    json.dump(result, f, indent=2)

                print(f"Results saved to {args.save}")

        except ValueError as e:
            print(f"Error converting to plaintext: {str(e)}")
            print(f"Raw decrypted value (decimal): {decrypted_int}")
            print(f"Raw decrypted value (hex): {hex(decrypted_int)}")

    except Exception as e:
        print(f"Error: {str(e)}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())