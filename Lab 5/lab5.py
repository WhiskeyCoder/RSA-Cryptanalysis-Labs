#!/usr/bin/env python3
"""
RSA Lab 5 - Decryption using Chinese Remainder Theorem (CRT)

This script demonstrates efficient RSA decryption using the Chinese Remainder Theorem.
Instead of computing m = c^d mod n directly (which is computationally expensive),
the CRT approach uses the following steps:
1. Compute m1 = c^dp mod p
2. Compute m2 = c^dq mod q
3. Compute h = qinv * (m1 - m2) mod p
4. Compute m = m2 + h * q

This is significantly faster than standard RSA decryption, especially for large keys.

Author: [Your Name]
Date: April 2025
"""

import argparse
import binascii
import json
from typing import Dict, Union, Optional


class RSACRTDecryptor:
    """
    RSA decryptor utilizing the Chinese Remainder Theorem (CRT) for efficiency.
    """

    def __init__(
            self,
            p: int,
            q: int,
            dp: int,
            dq: int,
            qinv: int,
            pinv: Optional[int] = None
    ):
        """
        Initialize the RSA CRT decryptor with the private key components.

        Args:
            p: First prime factor of n
            q: Second prime factor of n
            dp: d mod (p-1), where d is the private exponent
            dq: d mod (q-1)
            qinv: q^(-1) mod p (multiplicative inverse of q modulo p)
            pinv: p^(-1) mod q (optional, not used in standard CRT implementation)
        """
        self.p = p
        self.q = q
        self.dp = dp
        self.dq = dq
        self.qinv = qinv
        self.pinv = pinv

        # Compute n (modulus) for validation
        self.n = p * q

    def decrypt(self, ciphertext: int) -> int:
        """
        Decrypt a ciphertext using the Chinese Remainder Theorem.

        Args:
            ciphertext: The encrypted message as an integer

        Returns:
            Decrypted message as an integer
        """
        # Compute m1 = c^dp mod p
        m1 = pow(ciphertext, self.dp, self.p)

        # Compute m2 = c^dq mod q
        m2 = pow(ciphertext, self.dq, self.q)

        # Make sure m1 >= m2 before subtraction to avoid negative numbers
        # Compute h = qinv * (m1 - m2) mod p
        h = (self.qinv * ((m1 - m2) % self.p)) % self.p

        # Compute the message m = m2 + h * q
        m = m2 + h * self.q

        return m

    def verify_decryption(self, ciphertext: int, plaintext: int, e: int) -> bool:
        """
        Verify that decryption works correctly by re-encrypting the plaintext.

        Args:
            ciphertext: The original encrypted message
            plaintext: The decrypted message
            e: The public exponent

        Returns:
            True if verification succeeds, False otherwise
        """
        # Re-encrypt the plaintext: c' = m^e mod n
        reencrypted = pow(plaintext, e, self.n)

        # Check if the re-encrypted value matches the original ciphertext
        return reencrypted == ciphertext


def int_to_string(value: int) -> str:
    """
    Convert an integer to its string representation.

    Args:
        value: Integer to convert

    Returns:
        String representation of the integer
    """
    try:
        # Ensure the hex representation has an even number of digits
        hex_string = format(value, "x")
        if len(hex_string) % 2 != 0:
            hex_string = '0' + hex_string

        return binascii.unhexlify(hex_string.encode("utf-8")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as e:
        raise ValueError(f"Failed to convert integer to string: {str(e)}")


def load_key_params_from_file(filename: str) -> Dict[str, int]:
    """
    Load RSA key parameters from a file.

    Args:
        filename: Path to the key file

    Returns:
        Dictionary of key parameters
    """
    params = {}

    try:
        with open(filename, 'r') as f:
            content = f.read()

        # Parse parameters from file content
        for line in content.splitlines():
            line = line.strip()
            if not line or '=' not in line:
                continue

            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip()

            # Convert value to integer
            if key in ['p', 'q', 'dp', 'dq', 'pinv', 'qinv', 'ciphertext']:
                params[key] = int(value)

        return params

    except FileNotFoundError:
        raise FileNotFoundError(f"Key file not found: {filename}")
    except ValueError as e:
        raise ValueError(f"Invalid value in key file: {str(e)}")


def main():
    """Main function to demonstrate RSA decryption using CRT."""
    parser = argparse.ArgumentParser(
        description="RSA Decryption using Chinese Remainder Theorem (CRT)"
    )
    parser.add_argument('--key', type=str, default="key.txt",
                        help='Path to the key parameters file')
    parser.add_argument('--ciphertext', type=str,
                        help='Ciphertext to decrypt (as a decimal integer)')
    parser.add_argument('--verify', action='store_true',
                        help='Verify decryption by re-encrypting the result')
    parser.add_argument('--save', type=str,
                        help='Save decryption result to file')
    args = parser.parse_args()

    try:
        # Load key parameters
        params = load_key_params_from_file(args.key)

        # Create the CRT decryptor
        decryptor = RSACRTDecryptor(
            p=params.get('p'),
            q=params.get('q'),
            dp=params.get('dp'),
            dq=params.get('dq'),
            qinv=params.get('qinv'),
            pinv=params.get('pinv')
        )

        # Get ciphertext from command line, file, or prompt
        ciphertext = None

        if args.ciphertext:
            ciphertext = int(args.ciphertext)
        elif 'ciphertext' in params:
            ciphertext = params['ciphertext']
            print(f"Using ciphertext from key file: {ciphertext}")
        else:
            ciphertext_input = input("Enter the ciphertext (as a decimal integer): ")
            ciphertext = int(ciphertext_input)

        # Decrypt the ciphertext
        print("Decrypting using Chinese Remainder Theorem...")
        decrypted_int = decryptor.decrypt(ciphertext)

        # Convert to plaintext
        try:
            plaintext = int_to_string(decrypted_int)
            print(f"\nDecrypted plaintext: {plaintext}")

            # Generate and print the flag
            flag = f"ZD{{{plaintext}}}"
            print(f"Flag: {flag}")

            # Verify decryption if requested
            if args.verify:
                # For verification, we need the public exponent e
                e = int(input("Enter public exponent e for verification: "))

                if decryptor.verify_decryption(ciphertext, decrypted_int, e):
                    print("✅ Verification successful: Decryption is correct!")
                else:
                    print("❌ Verification failed: Decryption might be incorrect!")

            # Save results if requested
            if args.save:
                result = {
                    'plaintext': plaintext,
                    'flag': flag,
                    'plaintext_int': decrypted_int
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