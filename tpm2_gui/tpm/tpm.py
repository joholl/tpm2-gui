# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2020 Johannes Holland
# All rights reserved.

"""Interface for interacting with the TSS Feature API and the Truste Platform Module."""

import contextlib
import json
import tempfile
from enum import Enum
from pathlib import Path
from typing import Any, NamedTuple

from tpm2_pytss.binding import (
    ESYS_TR_NONE,
    CHAR_PTR_PTR,
    SIZE_T_PTR,
    UINT8_PTR,
    UINT8_PTR_PTR,
    ByteArray,
)
from tpm2_pytss.tcti import TCTI
from tpm2_pytss.esys import ESYS
from tpm2_pytss.exceptions import TPM2Error
from tpm2_pytss.fapi import DEFAULT_FAPI_CONFIG_PATH, FAPI, export
from tpm2_pytss.util.simulator import Simulator


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
    def object_type(self):
        """Return the object type of a TPM FAPI object (can be )."""
        json_file = self.json_path
        if json_file is None:
            return ObjectType.none

        # policies are not real FAPI objects, but we treat it as one
        if "/policy/" in str(json_file):
            return ObjectType.policy

        json_data = json.loads(json_file.read_bytes())
        return ObjectType(json_data["objectType"])

    @property
    def object_type_info(self):
        """Return the object type of a TPM FAPI object (can be )."""
        return {
            ObjectType.none: "",
            ObjectType.key: "Protected Key",
            ObjectType.nv: "Protected Memory",
            ObjectType.ext_pub_key: "External Public Key",
            ObjectType.hierarchy: "Hierarchy",
            ObjectType.duplicate: "Duplicate Object",
            ObjectType.policy: "Policy",
        }[self.object_type]

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
        app_data = UINT8_PTR(value=48 + len(value))
        self._fapi_ctx.SetAppData(self.path, app_data, 1)

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
        return hexdump(public)  # TODO PEM?

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
        if policy is None:
            return None
        if not policy:
            return ""
        return json.dumps(policy, indent=3)

    @property
    def nv(self):
        """Get the conents of the NV memory from a given NV index."""
        try:
            data = self._fapi_ctx.NvRead(self.path)
        except TPM2Error as tpm_error:
            if tpm_error.rc in (0x6001D, 0x60020, 0x60024, 0x14A):  # TODO
                return None
            raise tpm_error

        print(data)
        return ""


class TPM:  # pylint: disable=too-many-public-methods
    """Interface for interacting with the TSS Feature API and the Truste Platform Module."""

    def __init__(self):
        self.ctx_stack = contextlib.ExitStack()

        self._simulator = None

        self._config_path = DEFAULT_FAPI_CONFIG_PATH.resolve()
        self._config = None
        self._config_overlay = {}

        self._user_dir = None
        self._log_dir = None
        self._system_dir = None

        self._fapi = None
        self._fapi_ctx = None

        self.reload()

        self.provision()  # TODO joho

        # self.dummy_populate()  # TODO

    def __del__(self):
        self.ctx_stack.pop_all()  # TODO is this right?

    @property
    def config(self):
        """Get the JSON configuration loaded from the file."""
        return self._config

    @property
    def config_path(self):
        """Get the path from which the configuration was loaded."""
        return self._config_path

    @config_path.setter
    def config_path(self, value):
        """Set the configuration path (and reload FAPI)."""
        config_old = self._config_path
        self._config_path = value
        try:
            self.reload()
        except json.decoder.JSONDecodeError:  # dialog
            # rollback
            self._config_path = config_old
            self.reload()

    @property
    def config_overlay(self):
        """Get the configuration overlay."""
        return self._config_overlay

    @config_overlay.setter
    def config_overlay(self, value):
        """Set the configuration overlay to enforce a set of custom settings."""
        self._config_overlay = value
        self.reload()

    @property
    def config_with_overlay(self):
        """Get the loaded JSON configuration including the custom overlay."""
        return {**self._config, **self._config_overlay}

    @property
    def is_keystore_provisioned(self):
        """Determine if the TPM FAPI keystore is provisioned."""
        system_dir = Path(self.config_with_overlay["system_dir"])
        profile_name = self.config_with_overlay["profile_name"]
        return (system_dir / profile_name).is_dir()

    @property
    def is_tpm_provisioned(self):
        """Determine if the TPM is provisioned."""
        return False  # TODO

    @property
    def is_consistent(self):
        """If FAPI keystore and TPM state is consistent."""
        return False  # TODO

    def _load_config(self):
        # Parse config file into a dict
        default_fapi_config_contents = self._config_path.read_text()
        self._config = json.loads(default_fapi_config_contents)

        # Add needed key value pairs if they do not exist in config file
        additional_kvps = {"tcti_retry": 1}
        self._config = {**self._config, **additional_kvps}

    def _load_fapi(self):
        # Apply the configuration overlay
        config_with_overlay = {**self._config, **self._config_overlay}

        # Create a named tuple (with an export function needed by the fapi constructor) from the dict
        tpm_configuration = NamedTuple("tpm_configuration", [(e, Any) for e in config_with_overlay])
        tpm_configuration.export = export
        config_tuples = tpm_configuration(  # pylint: disable=not-callable
            *config_with_overlay.values()
        )

        # Create the FAPI object
        self._fapi = FAPI(config_tuples)

        # Enter the context, create TCTI connection
        self._fapi_ctx = self.ctx_stack.enter_context(self._fapi)

    def reload(self, use_simulator=True, use_tmp_keystore=True):
        """Load or reload FAPI including configuration and simulator. Does not provision."""
        self.ctx_stack.pop_all()  # TODO is this right?
        self._config_overlay = {}

        if use_simulator:
            # Create TPM simulator
            self._simulator = self.ctx_stack.enter_context(
                Simulator()
            )  # TODO support swtpm as well

            # Add to the configuration overlay
            simulator_config = {
                "tcti": f"mssim:port={self._simulator.port}",
                "tcti_retry": 3,
                "ek_cert_less": "yes",
            }
            self._config_overlay = {**self._config_overlay, **simulator_config}

        if use_tmp_keystore:
            # Create temporary directories to separate this example's state
            user_dir = self.ctx_stack.enter_context(tempfile.TemporaryDirectory())
            system_dir = self.ctx_stack.enter_context(tempfile.TemporaryDirectory())
            log_dir = self.ctx_stack.enter_context(tempfile.TemporaryDirectory())

            # Add to the configuration overlay
            tmp_keystore_config = {
                "user_dir": user_dir,
                "system_dir": system_dir,
                "log_dir": log_dir,
            }
            self._config_overlay = {**self._config_overlay, **tmp_keystore_config}

        self._load_config()

        self._user_dir = self.config_with_overlay["user_dir"]
        self._system_dir = self.config_with_overlay["system_dir"]
        self._log_dir = self.config_with_overlay["log_dir"]

        self._load_fapi()

    def provision(self):
        """Provision the FAPI keystore and the TPM."""
        self._fapi_ctx.Provision(None, None, None)

    def keystore_clear(self):
        """Clear (delete) keystore."""
        pass  # TODO

    def tpm_clear(self):
        print()
        print()
        print()
        print()

        tcti_name = self.config_with_overlay["tcti"].split(":")[0]
        tcti_config = "".join(self.config_with_overlay["tcti"].split(":")[1:])
        print(f"{tcti_name}, {tcti_config}")
        esys = ESYS()
        tcti = TCTI.load(tcti_name)

        # Create a context stack
        ctx_stack = contextlib.ExitStack().__enter__()
        # Enter the contexts
        tcti_ctx = ctx_stack.enter_context(tcti(config=tcti_config, retry=1))
        esys_ctx = ctx_stack.enter_context(esys(tcti_ctx))

        ret = esys_ctx.ClearControl(
            None, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, TPMI_YES_NO_PTR(False)
        )
        ret = esys_ctx.Clear(ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE)

    def dummy_populate(self):
        """Populate the FAPI with dummy objects."""
        #         privkey = """-----BEGIN EC PRIVATE KEY-----
        # MHcCAQEEIC9A2PknCL7BFLjNDbxlPu3I5rvJGoEIQkujhSNiTblZoAoGCCqGSM49
        # AwEHoUQDQgAExgnxXp0Kj+Zuav7zbzX0COwCS/qZURF8qRef+cnkbNKCYBsZnfI3
        # Cvm6l0F4bVE8QibJg+QntesC8hLc17ASJA==
        # -----END EC PRIVATE KEY----"""
        pubkey = r"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUymzBzI3LcxRpqJkiP0Ks7qp1UZH
93mYpmfUJBjK6anQawTyy8k87MteUdP5IPy47gzsO7sFcbWCoVZ8LvoQUw==
-----END PUBLIC KEY-----"""
        self._fapi_ctx.Import("/ext/myExtPubKey", pubkey)

        public_key_pem = r"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoGL6IrCSAznmIIzBessI
mW7tPOUy78uWTIaub32KnYHn78KXprrZ3ykp6WDrOQeMjv4AA+14mJbg77apVYXy
EnkFdOMa1hszSJnp6cJvx7ILngLvFUxzbVki/ehvgS3nRk67Njal+nMTe8hpe3UK
QeV/Ij+F0r6Yz91W+4LPmncAiUesRZLetI2BZsKwHYRMznmpIYpoua1NtS8QpEXR
MmsUue19eS/XRAPmmCfnb5BX2Tn06iCpk6wO+RfMo9etcX5cLSAuIYEQYCvV2/0X
TfEw607vttBN0Y54LrVOKno1vRXd5sxyRlfB0WL42F4VG5TfcJo5u1Xq7k9m9K57
8wIDAQAB
-----END PUBLIC KEY-----"""
        policy = {
            "description": "Description pol_signed",
            "policy": [
                {
                    "type": "POLICYSIGNED",
                    "publicKeyHint": "Test key hint",
                    "keyPEM": public_key_pem,
                    "keyPEMhashAlg": "SHA1",
                }
            ],
        }
        self._fapi_ctx.Import("/policy/myPolicy", str(policy))  # policy

        # TODO create some objects for debugging
        self._fapi_ctx.CreateKey("HS/SRK/mySigKey", "noDa, sign", "", "")  # signature
        self._fapi_ctx.CreateKey("HS/SRK/myDecKey", "noDa, decrypt", "", "")  # decrypt
        self._fapi_ctx.CreateKey(
            "HS/SRK/myRestrictedSignKey",
            "noDa, sign, restricted",
            "/policy/myPolicy",
            "",
        )  # restricted

        # ret = self._fapi_ctx.CreateSeal("HS/SRK/mySeal", "noDa", 12, "", "", "Hello World!")

        self._fapi_ctx.CreateNv("/nv/Owner/myNV", "noDa", 10, "", "")  # NV
        self._fapi_ctx.NvWrite()  # TODO
        # u8 = UINT8_PTR.frompointer(None)
        print()

        buf = ByteArray(3)  # 'cast', 'frompointer', 'this'
        buf[0] = 0
        buf[1] = 1
        buf[2] = 3
        # print(dir(buf))

        # with UINT8_PTR(value=1) as data:
        #     ret = self._fapi_ctx.NvWrite("/nv/Owner/myNV", data, 10)

        cert = """-----BEGIN CERTIFICATE-----
MIIDBjCCAe4CCQDcvXBOEVM0UTANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJE
RTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0
cyBQdHkgTHRkMB4XDTE5MDIyODEwNDkyM1oXDTM1MDgyNzEwNDkyM1owRTELMAkG
A1UEBhMCREUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0
IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AKBi+iKwkgM55iCMwXrLCJlu7TzlMu/LlkyGrm99ip2B5+/Cl6a62d8pKelg6zkH
jI7+AAPteJiW4O+2qVWF8hJ5BXTjGtYbM0iZ6enCb8eyC54C7xVMc21ZIv3ob4Et
50ZOuzY2pfpzE3vIaXt1CkHlfyI/hdK+mM/dVvuCz5p3AIlHrEWS3rSNgWbCsB2E
TM55qSGKaLmtTbUvEKRF0TJrFLntfXkv10QD5pgn52+QV9k59OogqZOsDvkXzKPX
rXF+XC0gLiGBEGAr1dv9F03xMOtO77bQTdGOeC61Tip6Nb0V3ebMckZXwdFi+Nhe
FRuU33CaObtV6u5PZvSue/MCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAcamUPe8I
nMOHcv9x5lVN1joihVRmKc0QqNLFc6XpJY8+U5rGkZvOcDe9Da8L97wDNXpKmU/q
pprj3rT8l3v0Z5xs8Vdr8lxS6T5NhqQV0UCsn1x14gZJcE48y9/LazYi6Zcar+BX
Am4vewAV3HmQ8X2EctsRhXe4wlAq4slIfEWaaofa8ai7BzO9KwpMLsGPWoNetkB9
19+SFt0lFFOj/6vDw5pCpSd1nQlo1ug69mJYSX/wcGkV4t4LfGhV8jRPDsGs6I5n
ETHSN5KV1XCPYJmRCjFY7sIt1x4zN7JJRO9DVw+YheIlduVfkBiF+GlQgLlFTjrJ
VrpSGMIFSu301A==
-----END CERTIFICATE-----"""
        self._fapi_ctx.SetCertificate("HS/SRK/mySigKey", cert)  # Cert

    def get_path_tree(self):
        """Get paths of TPM FAPI objects in a tree structure, e.g. {'': {'P_ECCP256SHA256': {'HN': {}, ...}}}"""
        try:
            search_path = ""
            info = self._fapi_ctx.List(search_path)
        except TPM2Error as tpm_error:
            if tpm_error.rc == 0x60034:  # TODO import rc already provisioned?
                return {"": {}}  # empty tree

            raise tpm_error

        tree = dict()
        for path in info.split(":"):
            subtree = tree

            while path is not None:
                parent = path.split("/", 1)[0]
                try:
                    path = path.split("/", 1)[1]
                except IndexError:
                    path = None

                # add element to tree
                if parent not in subtree:
                    subtree[parent] = dict()

                subtree = subtree[parent]
        return tree

    def fapi_object(self, path):  # pylint: disable=invalid-name
        """Return a FAPIObject from a path."""
        return FAPIObject(  # TODO return error if path is not in list?
            path, fapi_ctx=self._fapi_ctx, user_dir=self._user_dir, system_dir=self._system_dir
        )

    def get_pcr(self, index):
        """Get single Platform Configuration Register value from index."""
        # TODO fetch multiple pcrs at once

        try:
            pcr_value, pcr_log = self._fapi_ctx.PcrRead(index)

        except TPM2Error:
            pcr_value = None
            pcr_log = None

        return (pcr_value, pcr_log)

    def get_policy(self, path):
        """Get policy from TPM object path."""
        try:
            with CHAR_PTR_PTR() as json_policy:
                policy = self._fapi_ctx.ExportPolicy(path, json_policy)
                if policy is not None:
                    policy = json.dumps(policy, indent=3)
                else:
                    policy = None
        except TPM2Error:
            policy = None
        return policy

    def encrypt(self, path, plaintext):
        """Encrypt plaintext using TPM object specified via its path."""
        if plaintext:
            self.get_path_tree()  # TODO rm
            print('encrypt "' + str(plaintext) + '" with ' + str(path))

            # try:
            #     with UINT8_PTR_PTR() as keyPath:
            #         with UINT8_PTR() as plaintext:
            #             print(dir(plaintext))

            #             bla = ByteArray(4)
            #             s = b"Test"
            #             for i in range(0, 4):
            #                 bla[i] = s[i]
            #             print("#" + str(type(plaintext.frompointer(bla))))
            #             plaintext = plaintext.frompointer(bla)

            #             with SIZE_T_PTR() as plaintextSize:
            #                 with UINT8_PTR_PTR() as cipherText:
            #                     with SIZE_T_PTR() as cipherTextSize:
            #                         ret = self._fapi_ctx.Encrypt(
            #                           path,
            #                           plaintext,
            #                           plaintextSize,
            #                           cipherText,
            #                           cipherTextSize
            #                         )
            #                         print("----", ret)
            # except TPM2Error:
            #     pass # TODO

            return plaintext.upper()

        return ""

    def decrypt(self, path, ciphertext):
        """Decrypt ciphertext using TPM object specified via its path."""
        self.get_path_tree()  # TODO rm
        print('decrypt "' + str(ciphertext) + '" with ' + str(path))
        return ciphertext.lower()

    def sign(self, path, message):
        """Sign message using TPM object specified via its path."""
        self.get_path_tree()  # TODO rm
        print('sign "' + str(message) + '" with ' + str(path))
        return message.upper()

    def verify(self, path, signature):
        """Verify signature using TPM object specified via its path."""
        self.get_path_tree()  # TODO rm
        print('verify "' + str(signature) + '" with ' + str(path))
        return signature.lower()

    # def auth_policy(self, policy_path, key_path):
    #     """TODO"""
    #     print("---- AuthorizePolicy")  # TODO rm
    #     try:
    #         with UINT8_PTR(value=0) as policy_ref:
    #             ret = self._fapi_ctx.AuthorizePolicy(policy_path, key_path, policy_ref, 0)
    #             print(ret)
    #     except TPM2Error:
    #         # print("A----")  # TODO rm
    #         pass
    #     return None

    def pcr_extend(self, indices):
        """Extend TPM Platform Configuration Register."""
        for idx in indices:
            try:
                data = UINT8_PTR(value=1)
                self._fapi_ctx.PcrExtend(idx, data, 1, '{ "some": "data" }')  # TODO
            except TPM2Error:
                pass
            # return policy

    #     TSS2_RC Fapi_Quote(
    # FAPI_CONTEXT   *context,
    # uint32_t       *pcrList,
    # size_t          pcr_list_size,
    # char     const *keyPath,
    # char     const *quoteType,
    # uint8_t  const *qualifying_data,
    # size_t          qualifyingDataSize,
    # char          **quoteInfo,
    # uint8_t       **signature,
    # size_t         *signatureSize,
    # char          **pcrLog,
    # char          **certificate);
