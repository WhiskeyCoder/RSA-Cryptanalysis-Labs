#!/usr/bin/env python3
"""
RSA Encryption/Decryption Lab Implementation

This script demonstrates the fundamental operations of RSA cryptography including:
- String/Integer conversion utilities
- Key generation validation
- Encryption and decryption operations

Author: Whiskey
"""

import binascii
import argparse
from typing import Tuple, Union


class RSA:
    """
    RSA cryptosystem implementation providing encryption, decryption, and utility functions.
    """

    @staticmethod
    def string_to_int(message: Union[str, bytes]) -> int:
        """
        Convert a string or bytes to an integer representation.

        Args:
            message: Input string or bytes to convert

        Returns:
            Integer representation of the input
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        return int(binascii.hexlify(message), 16)

    @staticmethod
    def int_to_string(value: int) -> str:
        """
        Convert an integer back to its string representation.

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
            raise ValueError(f"Failed to convert integer to string: {e}")

    @staticmethod
    def verify_keys(n: int, e: int, d: int, p: int, q: int) -> bool:
        """
        Verify that the RSA keys are valid and consistent.

        Args:
            n: Modulus (product of p and q)
            e: Public exponent
            d: Private exponent
            p: First prime factor
            q: Second prime factor

        Returns:
            True if keys are valid, False otherwise
        """
        # Check if n = p*q
        if n != p * q:
            print(f"Warning: n ({n}) is not equal to p*q ({p * q})")
            return False

        # Check if ed ≡ 1 (mod φ(n))
        phi_n = (p - 1) * (q - 1)
        if (e * d) % phi_n != 1:
            print(f"Warning: e*d ({e * d}) is not congruent to 1 modulo φ(n) ({phi_n})")
            return False

        return True

    @staticmethod
    def encrypt(message: Union[str, bytes, int], e: int, n: int) -> int:
        """
        Encrypt a message using RSA public key (e, n).

        Args:
            message: The message to encrypt (string, bytes, or integer)
            e: Public exponent
            n: Modulus

        Returns:
            Encrypted message as an integer
        """
        if isinstance(message, (str, bytes)):
            m = RSA.string_to_int(message)
        else:
            m = message

        if m >= n:
            raise ValueError("Message too large for the given modulus")

        return pow(m, e, n)

    @staticmethod
    def decrypt(ciphertext: int, d: int, n: int, as_string: bool = True) -> Union[str, int]:
        """
        Decrypt a ciphertext using RSA private key (d, n).

        Args:
            ciphertext: The encrypted message as an integer
            d: Private exponent
            n: Modulus
            as_string: Whether to return the result as a string (True) or integer (False)

        Returns:
            Decrypted message as string or integer
        """
        m = pow(ciphertext, d, n)
        return RSA.int_to_string(m) if as_string else m

    @staticmethod
    def generate_flag(ciphertext: int) -> str:
        """
        Generate a flag in the required format.

        Args:
            ciphertext: The encrypted message

        Returns:
            Formatted flag string
        """
        return f"ZD{{{ciphertext}}}"


def main():
    """Main function to demonstrate RSA encryption and decryption."""
    parser = argparse.ArgumentParser(description="RSA Encryption/Decryption Lab")
    parser.add_argument('--message', type=str, default="RSA isn't really that hard",
                        help='Message to encrypt/decrypt')
    parser.add_argument('--mode', choices=['encrypt', 'decrypt', 'verify'], default='encrypt',
                        help='Operation mode')
    parser.add_argument('--generate-flag', action='store_true',
                        help='Generate a flag from the encrypted message')
    args = parser.parse_args()

    # RSA parameters from the lab
    n = 23516695565660963250242846975094031309572348962900032827958534374248114661507001374384417953124930587796472484525315334716723068326965228898857733318407681656604325744994115789416012096318656034667361976251100005599211469354510367804546831680730445574797161330145320706346512982316782618118878428893337849886890813813050423818145497040676697510093220374542784895778086554812954376689653727580227087363619223145837820593375994747273662064715654881379557354513619477314410917942381406981452545764657853425675230343749326640073923166795823683203941972393206970228647854927797483660176460658959810390117898333516129469397
    e = 65537
    d = 9587600726595591453426898215169101767863399178169979967502694355028996988583633210586039386751682566723132708455252764519220038491664005843242439790264046968625524201298469258242007220372280857992847470031480553726983707671745159488070659256258857978134570602562717609180653377092666963295822401721181836384326336158085408894694549470434424808812412260714422693522311366681659987060925945689943522825747715934700712908720597323076354591388316712970722935035250113120539406041972135508540472211484760814740089404942374666334486855389174327639061106567747152104666795257954039030591097174242386069752606041990644663125
    p = 170436857437540785902894247445629309884819493988198726337160363787266132388801445377172350883259146330710518633323153950488107255453274647690833952071079266615535462115718628529996080297946386916054952930963525522668498855400580516951309863503734146131687670337990358661269686138903141878297721385390421204703
    q = 137978932017559751745702136624874154954496829862527332457067512249687998333117572719846957168595861866495967632464915097378576596911015571165340454225721218087595428364080801400548238088288742249145662369868461078198744980520572785232341389134600070345564258064842348774203427257497319140459851255774165194699

    # Input message
    message = args.message

    # Verify RSA keys consistency
    if args.mode == 'verify' or args.mode == 'encrypt':
        if RSA.verify_keys(n, e, d, p, q):
            print("✅ RSA keys are valid and consistent.")
        else:
            print("❌ RSA keys are inconsistent!")

    # Perform the requested operation
    if args.mode == 'encrypt':
        try:
            ciphertext = RSA.encrypt(message, e, n)
            print(f"\nOriginal message: {message}")
            print(f"Encrypted ciphertext: {ciphertext}")

            if args.generate_flag:
                flag = RSA.generate_flag(ciphertext)
                print(f"\nFlag: {flag}")

        except Exception as ex:
            print(f"Encryption error: {ex}")

    elif args.mode == 'decrypt':
        try:
            # For demo purposes, first encrypt then decrypt
            ciphertext = RSA.encrypt(message, e, n)
            decrypted = RSA.decrypt(ciphertext, d, n)

            print(f"\nOriginal message: {message}")
            print(f"Encrypted ciphertext: {ciphertext}")
            print(f"Decrypted message: {decrypted}")

            # Verify the decryption is correct
            if decrypted == message:
                print("✅ Decryption successful!")
            else:
                print("❌ Decryption failed!")

        except Exception as ex:
            print(f"Decryption error: {ex}")


if __name__ == "__main__":
    main()