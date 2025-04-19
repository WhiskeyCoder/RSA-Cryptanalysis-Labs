#!/usr/bin/env python3
"""
RSA Lab 6 - Computing Private Key from Prime Factors

This script demonstrates how to compute an RSA private key when you have:
1. The prime factors (p and q)
2. The public exponent (e)
3. A ciphertext to decrypt

It calculates the private exponent d as the modular inverse of e modulo φ(n),
where φ(n) = (p-1)(q-1), then uses d to decrypt the ciphertext.

Author: [Your Name]
Date: April 2025
"""

import argparse
import binascii
import json
from typing import Tuple, Dict, Union


class RSAKeyCalculator:
    """
    Class to calculate RSA key components given prime factors and decrypt messages.
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

        # Track the state of the recursion
        last_remainder, remainder = abs(a), abs(b)
        x, last_x, y, last_y = 0, 1, 1, 0

        while remainder:
            # Division with remainder
            quotient, remainder = divmod(last_remainder, remainder)

            # Update coefficients
            x, last_x = last_x - quotient * x, x
            y, last_y = last_y - quotient * y, y

            # Update remainders
            last_remainder = remainder

        # Adjust sign based on input
        return (
            last_remainder,
            last_x * (-1 if a < 0 else 1),
            last_y * (-1 if b < 0 else 1)
        )

    @staticmethod
    def modular_inverse(a: int, m: int) -> int:
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
        gcd, x, y = RSAKeyCalculator.extended_gcd(a, m)

        # Inverse exists only if gcd is 1
        if gcd != 1:
            raise ValueError(f"Modular inverse does not exist (gcd={gcd})")

        # Ensure the result is in the range [0, m-1]
        return x % m

    @staticmethod
    def compute_private_exponent(p: int, q: int, e: int) -> int:
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
            d = RSAKeyCalculator.modular_inverse(e, phi_n)
            return d
        except ValueError as err:
            raise ValueError(f"Failed to compute private exponent: {err}")

    @staticmethod
    def decrypt(ciphertext: int, d: int, n: int) -> int:
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


def main():
    """Main function to demonstrate RSA private key calculation and decryption."""
    parser = argparse.ArgumentParser(
        description="RSA Private Key Calculation and Decryption"
    )
    parser.add_argument('--p', type=str,
                        help='First prime factor (as a decimal integer)')
    parser.add_argument('--q', type=str,
                        help='Second prime factor (as a decimal integer)')
    parser.add_argument('--e', type=int, default=65537,
                        help='Public exponent (default: 65537)')
    parser.add_argument('--ciphertext', type=str,
                        help='Ciphertext to decrypt (as a decimal integer)')
    parser.add_argument('--input-file', type=str,
                        help='JSON file containing p, q, e, and ciphertext')
    parser.add_argument('--save', type=str,
                        help='Save calculation results to file')
    parser.add_argument('--verbose', action='store_true',
                        help='Show detailed calculation steps')
    args = parser.parse_args()

    try:
        # Load parameters from file or command line
        p, q, e, ciphertext = None, None, args.e, None

        if args.input_file:
            with open(args.input_file, 'r') as f:
                params = json.load(f)
                p = int(params.get('p', '0'))
                q = int(params.get('q', '0'))
                e = int(params.get('e', str(args.e)))
                ciphertext = int(params.get('ciphertext', '0'))
        else:
            if args.p:
                p = int(args.p)
            if args.q:
                q = int(args.q)
            if args.ciphertext:
                ciphertext = int(args.ciphertext)

        # Prompt for missing parameters
        if p is None:
            p = int(input("Enter first prime factor p: "))
        if q is None:
            q = int(input("Enter second prime factor q: "))
        if ciphertext is None:
            ciphertext = int(input("Enter ciphertext to decrypt: "))

        # Default values for testing if needed
        if not args.input_file and not any([args.p, args.q, args.ciphertext]):
            print("Using default test values:")
            p = 163598797232837275790583032413921422452851861145478369331976309880028992955089558380171554447759405365296693377570783300198791468861355639873166150884714034914366548252757855530548966926710596087588892893653952147784119788340592861717511574050564549916735627066568966135368285851889401719649796310308064172229
            q = 151928351783926490385254692544226090032004315756120674902384041799040568083955129227360764179393042678005292005933989750269377019057534023167675372696224003953154715102625798599561576746593076228704448522848509650863715575134525964992439285085243915010868628145127710442853766119688772555932018349278733467937
            ciphertext = 4413233431418367729487001191499320110908628864393005850336194538378846901872012263024060279733910394528568658924541767014298273106072428208428621362441660742168169457839232452898840402021800460905562638079257404470183053387353849960252811956727755974787563684430128654542847575219444418360279725423441999278619584162289488016498634231451443666882615379215688913514242136494373656647328276909398980200846880640231426382657437148137610018777974884800967755913109702229247523206388812041488414941125272083962209616158810973532091497979384180936871075352614021504627549173686729322478688708849605857667792183339692021980
            print(f"p: {p}")
            print(f"q: {q}")
            print(f"e: {e}")
            print(f"ciphertext: {ciphertext}")

        # Calculate the modulus n = p*q
        n = p * q

        if args.verbose:
            print("\nCalculation Steps:")
            print(f"1. Modulus n = p * q = {n}")

        # Calculate Euler's totient function φ(n) = (p-1)(q-1)
        phi_n = (p - 1) * (q - 1)

        if args.verbose:
            print(f"2. Euler's totient φ(n) = (p-1)(q-1) = {phi_n}")

        # Compute the private exponent d
        d = RSAKeyCalculator.compute_private_exponent(p, q, e)

        if args.verbose:
            print(f"3. Private exponent d (modular inverse of e mod φ(n)) = {d}")

        # Decrypt the ciphertext
        decrypted_int = RSAKeyCalculator.decrypt(ciphertext, d, n)

        if args.verbose:
            print(f"4. Decrypted message (as integer) = {decrypted_int}")

        # Convert to plaintext
        try:
            plaintext = int_to_string(decrypted_int)

            print("\nResults:")
            print(f"Modulus (n): {n}")
            print(f"Public exponent (e): {e}")
            print(f"Private exponent (d): {d}")
            print(f"Decrypted plaintext: {plaintext}")

            # Generate and print the flag
            flag = f"ZD{{{plaintext}}}"
            print(f"Flag: {flag}")

            # Save results if requested
            if args.save:
                result = {
                    'n': n,
                    'e': e,
                    'd': d,
                    'p': p,
                    'q': q,
                    'phi_n': phi_n,
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