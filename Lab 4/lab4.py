#!/usr/bin/env python3
"""
RSA Lab 4 - Ciphertext Decryption

This script demonstrates RSA decryption using a private key file. It takes a ciphertext
as input and produces the plaintext using the private key parameters.

Author: [Your Name]
Date: April 2025
"""

import argparse
import binascii
import os
from typing import Union, Optional
from Crypto.PublicKey import RSA


class RSADecryptor:
    """
    A class for RSA decryption operations using a private key.
    """

    def __init__(self, key_path: str):
        """
        Initialize the RSA decryptor with a private key.

        Args:
            key_path: Path to the RSA private key file

        Raises:
            FileNotFoundError: If the key file doesn't exist
            ValueError: If the key file is invalid or not an RSA key
        """
        self.key_path = key_path
        self.key = self._load_key(key_path)

        # Extract key parameters
        self.n = self.key.n
        self.e = self.key.e
        self.d = self.key.d
        self.p = getattr(self.key, 'p', None)
        self.q = getattr(self.key, 'q', None)

    def _load_key(self, key_path: str) -> RSA.RsaKey:
        """
        Load an RSA key from a file.

        Args:
            key_path: Path to the RSA key file

        Returns:
            RSA key object

        Raises:
            FileNotFoundError: If the key file doesn't exist
            ValueError: If the key file is invalid
        """
        if not os.path.exists(key_path):
            raise FileNotFoundError(f"Key file not found: {key_path}")

        try:
            with open(key_path, 'r') as key_file:
                key_data = key_file.read()

            return RSA.import_key(key_data)
        except Exception as e:
            raise ValueError(f"Failed to load RSA key: {str(e)}")

    def print_key_info(self) -> None:
        """Print the RSA key parameters."""
        print(f"RSA Key Parameters from {self.key_path}:")
        print(f"n = {self.n}")
        print(f"e = {self.e}")
        print(f"d = {self.d}")

        if self.p and self.q:
            print(f"p = {self.p}")
            print(f"q = {self.q}")

    def decrypt(self, ciphertext: Union[int, str]) -> int:
        """
        Decrypt the ciphertext using the private key.

        Args:
            ciphertext: The encrypted message as an integer or string

        Returns:
            Decrypted message as an integer
        """
        # Convert ciphertext to int if it's a string
        if isinstance(ciphertext, str):
            ciphertext = int(ciphertext.strip())

        # Perform decryption
        return pow(ciphertext, self.d, self.n)

    @staticmethod
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


def main():
    """Main function to demonstrate RSA decryption."""
    parser = argparse.ArgumentParser(description="RSA Decryption Tool")
    parser.add_argument('--key', type=str, default="mykey3",
                        help='Path to the RSA private key file')
    parser.add_argument('--ciphertext', type=str,
                        help='Ciphertext to decrypt (as a decimal integer)')
    parser.add_argument('--format', choices=['raw', 'flag'], default='flag',
                        help='Output format (raw or as ZD{} flag)')
    parser.add_argument('--info', action='store_true',
                        help='Print key information')
    args = parser.parse_args()

    try:
        # Initialize the RSA decryptor with the provided key
        decryptor = RSADecryptor(args.key)

        # Print key information if requested
        if args.info:
            decryptor.print_key_info()
            print()

        # Get ciphertext from command line or prompt
        ciphertext = args.ciphertext
        if not ciphertext:
            ciphertext = input("Enter the ciphertext (as a decimal integer): ")

        # Decrypt the ciphertext
        decrypted_int = decryptor.decrypt(ciphertext)

        # Convert to plaintext
        try:
            plaintext = decryptor.int_to_string(decrypted_int)

            # Display result based on format
            if args.format == 'flag':
                if not plaintext.startswith('ZD{'):
                    plaintext = f"ZD{{{plaintext}}}"
                print(f"Decrypted flag: {plaintext}")
            else:
                print(f"Decrypted plaintext: {plaintext}")

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