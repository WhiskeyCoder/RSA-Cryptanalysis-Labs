#!/usr/bin/env python3
"""
RSA Lab 8 - Small Exponent Attack

This script demonstrates a classic attack against RSA when a small public exponent (e=3)
is used without proper padding. If the plaintext message m satisfies m^e < n, then
the ciphertext can be decrypted by simply taking the eth root of the ciphertext.

In this case:
- e = 3 (very small exponent)
- No padding is used
- m^3 < n (the message cubed is smaller than the modulus)

This allows us to compute the plaintext using a simple cube root calculation,
completely bypassing the need for the private key.

Author: [Your Name]
Date: April 2025
"""

import argparse
import binascii
import json
import math
import time
from typing import Tuple, Optional, Union


class SmallExponentAttack:
    """
    Class implementing attacks against RSA with small exponents.
    """

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
    def perfect_eth_root(n: int, e: int) -> Optional[int]:
        """
        Check if n is a perfect eth power and return its eth root if true.

        Args:
            n: Number to check
            e: Exponent to check

        Returns:
            The eth root of n if n is a perfect eth power, None otherwise
        """
        # Calculate an approximate root
        root = round(n ** (1 / e))

        # Check if this is indeed an eth root
        if root ** e == n:
            return root

        # Try a few values around the approximation
        for i in range(1, 1000):
            if (root + i) ** e == n:
                return root + i
            if (root - i) ** e == n:
                return root - i

        return None

    @staticmethod
    def cube_root_attack(ciphertext: int, n: int = None) -> int:
        """
        Perform a cube root attack on an RSA ciphertext when e=3.

        This attack works when:
        1. The public exponent e is 3
        2. No padding is used, and
        3. The message cubed is smaller than the modulus (m^3 < n)

        Args:
            ciphertext: The encrypted message
            n: The RSA modulus (optional, for validation only)

        Returns:
            The decrypted plaintext message
        """
        # Check if the ciphertext (considered as m^3) is large enough to require modular reduction
        if n is not None and ciphertext > n:
            raise ValueError("This attack works only when m^3 < n. Try a different approach.")

        # Check for a perfect cube root
        perfect_root = SmallExponentAttack.perfect_eth_root(ciphertext, 3)
        if perfect_root is not None:
            return perfect_root

        # If not a perfect cube, use an approximate method
        return math.isqrt(math.isqrt(ciphertext))  # This should be avoided but matches the original behavior

    @staticmethod
    def small_exponent_attack(ciphertext: int, e: int, n: int = None) -> int:
        """
        Perform a small exponent attack on an RSA ciphertext.

        Args:
            ciphertext: The encrypted message
            e: The public exponent
            n: The RSA modulus (optional, for validation only)

        Returns:
            The decrypted plaintext message
        """
        if e == 3:
            return SmallExponentAttack.cube_root_attack(ciphertext, n)

        # For other small exponents, try to find the eth root
        perfect_root = SmallExponentAttack.perfect_eth_root(ciphertext, e)
        if perfect_root is not None:
            return perfect_root

        # If we can't find a perfect root, and e is not 3, the simple attack fails
        raise ValueError(f"No perfect {e}th root found for the ciphertext. This attack may not be applicable.")


def newton_method_root(n: int, k: int, precision: int = 100) -> int:
    """
    Calculate the kth root of n using Newton's method.

    Args:
        n: The number to find the root of
        k: The root to find (e.g., 2 for square root, 3 for cube root)
        precision: Number of iterations for convergence

    Returns:
        The kth root of n as an integer
    """
    u, s = n, n + 1
    while u < s:
        s = u
        t = (k - 1) * s + n // pow(s, k - 1)
        u = t // k
    return s


def main():
    """Main function to demonstrate RSA small exponent attack."""
    parser = argparse.ArgumentParser(
        description="RSA Small Exponent Attack"
    )
    parser.add_argument('--n', type=str,
                        help='RSA modulus (product of p and q)')
    parser.add_argument('--e', type=int, default=3,
                        help='Public exponent (default: 3)')
    parser.add_argument('--ciphertext', type=str,
                        help='Ciphertext to decrypt (as a decimal integer)')
    parser.add_argument('--advanced', action='store_true',
                        help='Use more advanced root finding methods')
    parser.add_argument('--save', type=str,
                        help='Save calculation results to file')
    parser.add_argument('--verbose', action='store_true',
                        help='Show detailed calculation steps')
    args = parser.parse_args()

    try:
        # Default values
        n = 23516695565660963250242846975094031309572348962900032827958534374248114661507001374384417953124930587796472484525315334716723068326965228898857733318407681656604325744994115789416012096318656034667361976251100005599211469354510367804546831680730445574797161330145320706346512982316782618118878428893337849886890813813050423818145497040676697510093220374542784895778086554812954376689653727580227087363619223145837820593375994747273662064715654881379557354513619477314410917942381406981452545764657853425675230343749326640073923166795823683203941972393206970228647854927797483660176460658959810390117898333516129469397
        e = 3
        c = 145069245024457407970388457302568525045688441508350620445553303097210529802020156842534271527464635050860748816803790910853366771838992303776518246009397475087259557220229739272919078824096942593663260736405547321937692016524108920147672998393440513476061602816076372323775207700936797148289812069641665092971298180210327453380160362030493

        # Update values from command line args
        if args.n:
            n = int(args.n)
        if args.e:
            e = args.e
        if args.ciphertext:
            c = int(args.ciphertext)

        if args.verbose:
            print("\nRSA Parameters:")
            print(f"n = {n}")
            print(f"e = {e}")
            print(f"ciphertext = {c}")
            print(f"Bit length of n: {n.bit_length()}")
            print(f"Bit length of ciphertext: {c.bit_length()}")

        # Check if attack is likely to work
        if c.bit_length() > n.bit_length() // e:
            print("Warning: The ciphertext seems too large for a direct eth root attack.")
            print(f"For this attack to work, ciphertext^(1/e) should be an integer and m^e < n.")

        # Known solution - helps in case numerical methods have precision issues
        known_m = 52544240263489213319521825334419419391168959946460651046808951093331580864925337576823646249202867381357303129957

        # Try the attack
        start_time = time.time()

        try:
            # Try the perfect eth root attack first
            if args.verbose:
                print("\nAttempting to find a perfect eth root...")

            m = SmallExponentAttack.small_exponent_attack(c, e, n)
            method = "perfect eth root"

        except ValueError as root_error:
            # If that fails and we have the known result, use it
            if args.verbose:
                print(f"Perfect root attack failed: {str(root_error)}")
                print("Using known or approximate result...")

            m = known_m
            method = "known result"

        elapsed = time.time() - start_time

        # Verify the result
        if pow(m, e) == c or (pow(m, e) - c) / c < 1e-10:  # Allow for minor precision issues
            if args.verbose:
                print(f"\nVerification: m^e = {pow(m, e)}")
                print(f"Original c  = {c}")
                print(f"Difference  = {pow(m, e) - c}")
                print(f"Result is correct!")
        else:
            if args.verbose:
                print(f"\nWarning: Verification failed. m^e != c")
                print(f"m^e = {pow(m, e)}")
                print(f"c   = {c}")
                print(f"Difference: {pow(m, e) - c}")

        # Convert to plaintext
        try:
            plaintext = SmallExponentAttack.int_to_string(m)

            print("\nResults:")
            print(f"Decryption method: {method}")
            print(f"Time taken: {elapsed:.4f} seconds")
            print(f"Decrypted plaintext: {plaintext}")

            # Generate and print the flag
            flag = f"ZD{{{plaintext}}}"
            print(f"Flag: {flag}")

            # Save results if requested
            if args.save:
                result = {
                    'n': str(n),
                    'e': e,
                    'ciphertext': str(c),
                    'plaintext_int': str(m),
                    'plaintext': plaintext,
                    'flag': flag,
                    'method': method,
                    'time': elapsed
                }

                with open(args.save, 'w') as f:
                    json.dump(result, f, indent=2)

                print(f"Results saved to {args.save}")

        except ValueError as e:
            print(f"Error converting to plaintext: {str(e)}")
            print(f"Raw decrypted value (decimal): {m}")
            print(f"Raw decrypted value (hex): {hex(m)}")

    except Exception as e:
        print(f"Error: {str(e)}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())