# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2020 Johannes Holland
# All rights reserved.

"""Utility widgets."""

from enum import IntEnum, auto
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import Certificate

# +=========================================================+
# | Encoding:  |  String | Hex | Hexdump | PEM | DER | Info |
# +============+=========+=====+=========+=====+=====+======+
# | Bytearray  | y       | y   | y       | -   | -   | -    |
# | Bytes      | y       | y   | y       | -   | -   | -    |
# | String     | y       | y   | y       | -   | -   | -    |
# | EC Pub Key | -       | -   | -       | y   | y   | y    |
# | Cert       | -       | -   | -       | y   | y   | y    |
# +============+=========+=====+=========+=====+=====+======+
# TODO UInt64 and Bitfield (byte-like)


class Encoding(IntEnum):
    """Encoding Options."""

    String = auto()
    Hex = auto()
    Hexdump = auto()
    PEM = auto()
    DER = auto()
    Info = auto()
    UInt64 = auto()
    Bitfield = auto()

    def __str__(self):
        return {
            Encoding.String: "String",
            Encoding.Hex: "Hex",
            Encoding.Hexdump: "Hexdump",
            Encoding.PEM: "PEM",
            Encoding.DER: "DER (Hex)",
            Encoding.Info: "Info",
            Encoding.UInt64: "Integer",
            Encoding.Bitfield: "Bitfield",
        }[self]


class ValueType(IntEnum):
    """Value Types which are to be encoded."""

    Bytearray = auto()
    Bytes = auto()
    String = auto()
    Path = auto()
    ECPublicKey = auto()
    RSAPublicKey = auto()
    Cert = auto()

    @staticmethod
    def from_value(value):
        """Autodetect the ValueType."""
        # cast value to bytes if it is not already
        if isinstance(value, bytearray):
            return ValueType.Bytearray
        if isinstance(value, bytes):
            return ValueType.Bytes
        if isinstance(value, str):
            return ValueType.String
        if isinstance(value, Path):
            return ValueType.Path
        if isinstance(value, EllipticCurvePublicKey):
            return ValueType.ECPublicKey
        if isinstance(value, RSAPublicKey):
            return ValueType.RSAPublicKey
        if isinstance(value, Certificate):
            return ValueType.Cert

        raise ValueError(f"Could not find ValueType for value {value}")


class Encoder:
    """Utility class for encoding values."""

    @staticmethod
    def _bytes_to_string(value):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError as error:
            return (
                f"Error: cannot decode byte {bytes([value[error.start]])} at index {error.start}. "
                f"Hint: Use Encoding '{str(Encoding.Hex)}'"
            )

    @staticmethod
    def _bytes_to_hex(value):
        return " ".join("{:02x}".format(b) for b in value)

    @staticmethod
    def _bytes_to_hexdump(value, line_len=16):
        """Get hexdump from bytearray."""
        char_map = "".join([(len(repr(chr(b))) == 3) and chr(b) or "." for b in range(256)])
        lines = []

        # for each line
        for offset in range(0, len(value), line_len):
            line_text = value[offset : offset + line_len]
            line_hex = " ".join(["%02x" % b for b in line_text])
            # replace non-printable chars with '.'
            printable = "".join(["%s" % ((b <= 127 and char_map[b]) or ".") for b in line_text])
            lines.append("%04x  %-*s  |%s|\n" % (offset, line_len * 3, line_hex, printable))
        return "".join(lines)

    @staticmethod
    def _int_to_hex(value):
        value_hex = f"{value:x}"

        # pad to even number of digits
        if len(value_hex) % 2 != 0:
            value_hex = f"0{value_hex}"

        # group two each
        return " ".join(f"{a}{b}" for (a, b) in zip(value_hex[::2], value_hex[1::2]))

    @staticmethod
    def _bytes_like_to_bytes(value):
        """Cast bytes-like value (bytearray, bytes, string) to bytes."""
        if isinstance(value, bytearray):
            return bytes(value)
        if isinstance(value, str):
            return value.encode("utf-8")
        if isinstance(value, Path):
            return str(value).encode("utf-8")
        if isinstance(value, bytes):
            return value

        raise ValueError(f"Could not convert byte-like value to bytes: {value}")

    @staticmethod
    def _encode_bytes_like(value, encoding):
        """Encode bytes-like value (bytearray, bytes, string)."""
        value = Encoder._bytes_like_to_bytes(value)

        # encode
        return {
            Encoding.String: Encoder._bytes_to_string,
            Encoding.Hex: Encoder._bytes_to_hex,
            Encoding.Hexdump: Encoder._bytes_to_hexdump,
        }[encoding](value)

    @staticmethod
    def _encode_ec_public_key(value, encoding):
        """Encode an EllipticCurvePublicKey."""
        return {
            Encoding.PEM: Encoder._bytes_to_string(
                value.public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
                )
            ),
            Encoding.DER: Encoder._bytes_to_hex(
                value.public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                )
            ),
            Encoding.Info: f"""
EC Public Key
    Curve:    {value.curve.name}
    Key Size: {value.key_size}
    X:        {Encoder._int_to_hex(value.public_numbers().x)}
    Y:        {Encoder._int_to_hex(value.public_numbers().y)}
""".strip(),
        }[encoding]

    @staticmethod
    def _encode_rsa_public_key(value, encoding):
        """Encode an RSAPublicKey."""
        return {
            Encoding.PEM: Encoder._bytes_to_string(
                value.public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
                )
            ),
            Encoding.DER: Encoder._bytes_to_hex(
                value.public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                )
            ),
            Encoding.Info: f"""
RSA Public Key
    Key Size:   {value.key_size}
    Modulus n:  {Encoder._int_to_hex(value.public_numbers().n)}
    Exponent e: {Encoder._int_to_hex(value.public_numbers().e)}
""".strip(),
        }[encoding]

    @staticmethod
    def _encode_cert(value, encoding):
        """Encode a Certificate."""
        oid_name = (
            value.signature_algorithm_oid._name  # [TODO refactor]  pylint: disable=protected-access
        )

        return {
            Encoding.PEM: Encoder._bytes_to_string(value.public_bytes(serialization.Encoding.PEM)),
            Encoding.DER: Encoder._bytes_to_hex(value.public_bytes(serialization.Encoding.DER)),
            Encoding.Info: f"""
X.509 Certificate
    Issuer:             {", ".join(e.rfc4514_string() for e in value.issuer.rdns)}
    Subject:            {", ".join(e.rfc4514_string() for e in value.issuer.rdns)}
    Serial No.:         {Encoder._int_to_hex(value.serial_number)}
    Not valid before:   {value.not_valid_before}
    Not valid afer:     {value.not_valid_after}
    Version:            {value.version}
    Signature Hash Alg: {value.signature_hash_algorithm.name}
    Signature Alg OID:  {value.signature_algorithm_oid.dotted_string} ({oid_name})
    Public Key:         {value.public_key}
    Signature:          {" ".join("{:02x}".format(b) for b in value.signature)}
    Fingerprint:        {" ".join("{:02x}".format(b) for b in value.fingerprint(hashes.SHA256()))}
    Extensions:         {value.extensions}  # TODO
            """.strip(),
        }[encoding]

    @staticmethod
    def encode(value, encoding):
        """Encode a value according to the given encoding option."""
        if not value:
            return ""

        value_type = ValueType.from_value(value)

        return {
            ValueType.Bytearray: Encoder._encode_bytes_like,
            ValueType.Bytes: Encoder._encode_bytes_like,
            ValueType.String: Encoder._encode_bytes_like,
            ValueType.Path: Encoder._encode_bytes_like,
            ValueType.ECPublicKey: Encoder._encode_ec_public_key,
            ValueType.RSAPublicKey: Encoder._encode_rsa_public_key,
            ValueType.Cert: Encoder._encode_cert,
        }[value_type](value, encoding)
