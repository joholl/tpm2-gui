# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2020 Johannes Holland
# All rights reserved.

"""Interface to make TPM info dict structure more accessible via dot notation."""

import json
from enum import Enum
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicNumbers,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from tpm2_pytss.binding import UINT8_ARRAY
from tpm2_pytss.exceptions import TPM2Error


def hexdump(byte_array, line_len=16):
    """Get hexdump from bytearray."""
    char_map = "".join([(len(repr(chr(b))) == 3) and chr(b) or "." for b in range(256)])
    lines = []

    # for each line
    for offset in range(0, len(byte_array), line_len):
        line_text = byte_array[offset : offset + line_len]
        line_hex = " ".join(["%02x" % b for b in line_text])
        # replace non-printable chars with '.'
        printable = "".join(["%s" % ((b <= 127 and char_map[b]) or ".") for b in line_text])
        lines.append("%04x  %-*s  |%s|\n" % (offset, line_len * 3, line_hex, printable))
    return "".join(lines)


class ObjectType(Enum):
    """TPM FAPI object types."""

    none = 0
    key = 1
    nv = 2
    ext_pub_key = 3
    hierarchy = 4
    duplicate = 5
    policy = 6  # not a real FAPI object


class FAPIObject:
    """A FAPI object represented by a path. Valid, as long as the FAPI Context is valid."""

    def __init__(self, path, fapi_ctx, user_dir, system_dir):
        self._fapi_ctx = fapi_ctx
        self._user_dir = user_dir
        self._system_dir = system_dir

        self.path = path

    @property
    def json_path(self):
        """Return the path to the keystore json file (or None if does not exist)."""
        # strip leading '/' from path
        path = self.path.lstrip("/")

        # first look at system keystore, then the user keystore...
        for keystore in [self._system_dir, self._user_dir]:
            # look for object.json
            json_file = Path(keystore) / path / "object.json"
            if json_file.is_file():
                return json_file
            # look for <leaf name>.json (policies)
            json_file = Path(keystore) / f"{path}.json"
            if json_file.is_file():
                return json_file

        return None

    @property
    def internals(self):
        """Return the internal keystore data. Use with caution."""
        if self.json_path is None:
            return None

        json_data = json.loads(self.json_path.read_bytes())
        return ObjectInternals(json_data)

    @property
    def object_type(self):
        """Return the object type of a TPM FAPI object (can be )."""
        if self.json_path is None:
            return ObjectType.none

        # policies are not real FAPI objects, but we treat it as one
        if "/policy/" in str(self.json_path):
            return ObjectType.policy

        return ObjectType(self.internals.objectType)

    @property
    def object_type_info(self):
        """Return the object type of a TPM FAPI object (can be )."""
        return {
            ObjectType.none: "",
            ObjectType.key: "Protected Key",
            ObjectType.nv: "Protected Memory",
            ObjectType.ext_pub_key: "External Public Key",
            ObjectType.hierarchy: self.description,
            ObjectType.duplicate: "Duplicate Object",
            ObjectType.policy: "Policy",
        }[self.object_type]

    @property
    def attributes(self):
        if self.internals and self.internals.public and self.internals.public.publicArea and self.internals.public.publicArea.objectAttributes:
            obj_attrs_dict = self.internals.public.publicArea.objectAttributes
            obj_attrs_list = [k for k in dir(obj_attrs_dict) if getattr(obj_attrs_dict, k)]
            return ', '.join(obj_attrs_list)

    # TODO handle object types and setter exceptions
    @property
    def description(self):
        """Get description from TPM object."""
        try:
            return self._fapi_ctx.GetDescription(self.path)
        except TPM2Error as tpm_error:
            if tpm_error.rc in (0x60020, 0x00060024):  # TODO Could not open (2x)
                return None
            raise tpm_error

    @description.setter
    def description(self, value):
        """Set description of TPM object."""
        self._fapi_ctx.SetDescription(self.path, value)

    @property
    def appdata(self):
        """Get application data of TPM object."""

        try:
            appdata = self._fapi_ctx.GetAppData(self.path)
            if not appdata:
                return ""
            return hexdump(appdata)
        except TPM2Error as tpm_error:
            if tpm_error.rc in (
                0x60020,
                0x00060024,
                0x6001D,
            ):  # TODO Could not open (2x), Object has no app data
                return None
            raise tpm_error

    @appdata.setter
    def appdata(self, value):
        """Set application data of TPM object."""
        value = bytearray(value, "utf-8")
        app_data_size = len(value)
        app_data = UINT8_ARRAY(nelements=app_data_size)
        for i, byte in enumerate(value):
            app_data[i] = byte

        self._fapi_ctx.SetAppData(self.path, app_data.cast(), app_data_size)

    @property
    def certificate(self):
        """Get certifiacte from TPM object path."""
        try:
            return self._fapi_ctx.GetCertificate(self.path)
        except TPM2Error as tpm_error:
            if tpm_error.rc in (0x60020, 0x00060024):  # TODO Could not open (2x)
                return None
            raise tpm_error

    @certificate.setter
    def certificate(self, value):
        """Set certificate of TPM object."""
        self._fapi_ctx.SetCertificate(self.path, value)

    @property
    def public_private_policy(self):
        """Get public and private portion as well as policy from TPM object path."""

        try:
            public, private, policy = self._fapi_ctx.GetTpmBlobs(self.path)
        except TPM2Error as tpm_error:
            if tpm_error.rc in (
                0x6001D,
                0x60020,
                0x60024,
            ):  # TODO bad path, Could not open (2x)
                return (None, None, None)
            raise tpm_error

        return (public, private, policy)

    @property
    def public(self):
        """Get public key portion from TPM object."""
        public, _, _ = self.public_private_policy
        if public is None:
            return None

        public_key_x = int.from_bytes(public[-64 - 2 : -32 - 2], "big")  # TODO other curves and RSA
        public_key_y = int.from_bytes(public[-32:], "big")
        public_key = EllipticCurvePublicNumbers(
            x=public_key_x, y=public_key_y, curve=ec.SECP256R1()
        ).public_key()
        public_bytes = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        return public_bytes.decode("utf-8").strip()

    @property
    def private(self):
        """Get private key portion from TPM object."""
        _, private, _ = self.public_private_policy
        if private is None:
            return None
        return hexdump(private)  # TODO PEM?

    @property
    def policy(self):
        """Get policy of from TPM object."""
        _, _, policy = self.public_private_policy
        if policy is None or not policy:
            return None
        return json.dumps(policy, indent=3)

    @property
    def nv(self):  # pylint: disable=invalid-name
        """Get the conents of the NV memory from a given NV index."""
        try:
            data = self._fapi_ctx.NvRead(self.path)
            return hexdump(data[0])
        except TPM2Error as tpm_error:
            if tpm_error.rc in (0x6001D, 0x60020, 0x60024, 0x14A):  # TODO
                return None
            raise tpm_error

    def encrypt(self, plaintext):
        """Encrypt plaintext using TPM object specified via its path."""
        if plaintext:
            data_size = len(plaintext)
            data = UINT8_ARRAY(nelements=data_size)
            for i, byte in enumerate(plaintext):
                data[i] = byte

            # try:
            ret = self._fapi_ctx.Encrypt(self.path, data.cast(), data_size)
            # except TPM2Error as tpm_error:
            #     raise tpm_error
            print(ret)

        return ""

    def decrypt(self, ciphertext):
        """Decrypt ciphertext using TPM object specified via its path."""
        print('decrypt "' + str(ciphertext) + '" with ' + str(self.path))
        return ciphertext.lower()

    def sign(self, message):
        """Sign message using TPM object specified via its path."""
        if message:
            # message has to be hashed: use SHA256
            digest = hashes.Hash(hashes.SHA256())
            digest.update(message)
            digest = digest.finalize()

            data_size = len(digest)
            data = UINT8_ARRAY(nelements=data_size)
            for i, byte in enumerate(digest):
                data[i] = byte

            # try:
            padding = None
            ret = self._fapi_ctx.Sign(
                self.path, padding, data.cast(), data_size
            )  # TODO returns sign., pub key, cert
            # except TPM2Error as tpm_error:
            #     raise tpm_error
            return hexdump(ret[0])

        return ""

    def verify(self, signature):
        """Verify signature using TPM object specified via its path."""
        print('verify "' + str(signature) + '" with ' + str(self.path))
        return signature.lower()


class ObjectInternals():
    """Takes a dict and makes values accessible via dot notation."""

    def __init__(self, data):
        self.data = data

    def __getattr__(self, attr):
        value = self.data[attr]
        if isinstance(value, dict):
            return ObjectInternals(value)
        return value

    def attrs_recursive(self, parent=""):
        """Return a generator to all attributes."""
        attrs_rec = []
        sep = "." if parent else ""

        for attr in dir(self):
            child = getattr(self, attr)
            if isinstance(child, ObjectInternals):
                attrs_rec.extend(child.attrs_recursive(parent=f"{parent}{sep}{attr}"))
            else:
                attrs_rec.append(f"{parent}{sep}{attr}")

    def __dir__(self):
        return self.data.keys()
