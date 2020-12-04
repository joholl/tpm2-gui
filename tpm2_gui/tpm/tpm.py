# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2020 Johannes Holland
# All rights reserved.

"""Interface for interacting with the TSS Feature API and the Truste Platform Module."""

import contextlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, NamedTuple

from tpm2_pytss.binding import (
    CHAR_PTR_PTR,
    ESYS_TR_NONE,
    ESYS_TR_PASSWORD,
    ESYS_TR_RH_PLATFORM,
    TPMI_YES_NO_PTR,
    UINT8_ARRAY,
)
from tpm2_pytss.esys import ESYS
from tpm2_pytss.exceptions import TPM2Error
from tpm2_pytss.fapi import DEFAULT_FAPI_CONFIG_PATH, FAPI, export
from tpm2_pytss.tcti import TCTI
from tpm2_pytss.util.simulator import Simulator

from .info import TPMInfo
from .object import FAPIObject


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

        self._using_fapi = True
        self._fapi_ctx = None
        self._esys_ctx = None

        # suppress FAPI errors (TODO migrate to pytss func once supported)
        os.environ["TSS2_LOG"] = "fapi+NONE"

        self.reload()

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

    def _load_config(self):
        # Parse config file into a dict
        default_fapi_config_contents = self._config_path.read_text()
        self._config = json.loads(default_fapi_config_contents)

        # Add needed key value pairs if they do not exist in config file
        additional_kvps = {"tcti_retry": 1}
        self._config = {**self._config, **additional_kvps}

    def _load_fapi(self):
        # Create a named tuple (with an export function needed by the fapi constructor) from the dict
        tpm_configuration = NamedTuple(
            "tpm_configuration", [(e, Any) for e in self.config_with_overlay]
        )
        tpm_configuration.export = export
        config_tuples = tpm_configuration(  # pylint: disable=not-callable
            *self.config_with_overlay.values()
        )

        # Create FAPI, enter the context (creates TCTI connection)
        self._fapi_ctx = self.ctx_stack.enter_context(FAPI(config_tuples))

    def _load_esys(self):
        tcti_name = self.config_with_overlay["tcti"].split(":")[0]
        tcti_config = "".join(self.config_with_overlay["tcti"].split(":")[1:])
        esys = ESYS()
        tcti = TCTI.load(tcti_name)

        # Create a context stack
        self.ctx_stack = (
            contextlib.ExitStack().__enter__()
        )  # TODO this is not right! use existing one!
        # Enter the contexts
        tcti_ctx = self.ctx_stack.enter_context(
            tcti(config=tcti_config, retry=1)  # pylint: disable=not-callable
        )
        self._esys_ctx = self.ctx_stack.enter_context(esys(tcti_ctx))
        # Call Startup and clear the TPM
        self._esys_ctx.Startup(self._esys_ctx.TPM2_SU_CLEAR)
        # Set the timeout to blocking
        self._esys_ctx.SetTimeout(self._esys_ctx.TSS2_TCTI_TIMEOUT_BLOCK)

    def reload(self, use_simulator=True, use_tmp_keystore=True):
        """Load or reload FAPI including configuration and simulator. Does not provision."""
        self.ctx_stack.close()
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

        if self._using_fapi:
            self._load_fapi()
        else:
            self._load_esys()

    def _switch_to_fapi(self):
        self._using_fapi = True
        self.reload()

    def _switch_to_esys(self):
        self._using_fapi = False
        self.reload()

    def provision(self):
        """Provision the FAPI keystore and the TPM."""
        self._fapi_ctx.Provision(None, None, None)

    def tpm_clear(self):
        """Clear TPM."""
        self._switch_to_esys()

        # authValue = TPM2B_AUTH(size=0, buffer=[])
        # self.esys_ctx.TR_SetAuth(ESYS_TR_RH_OWNER, authValue)
        self._esys_ctx.ClearControl(
            ESYS_TR_RH_PLATFORM,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            TPMI_YES_NO_PTR(False),
        )

        self._esys_ctx.Clear(ESYS_TR_RH_PLATFORM, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE)

        self._switch_to_fapi()

    def dummy_populate(self):
        """Populate the FAPI with dummy objects."""
        #         privkey = """-----BEGIN EC PRIVATE KEY-----
        # MHcCAQEEIC9A2PknCL7BFLjNDbxlPu3I5rvJGoEIQkujhSNiTblZoAoGCCqGSM49
        # AwEHoUQDQgAExgnxXp0Kj+Zuav7zbzX0COwCS/qZURF8qRef+cnkbNKCYBsZnfI3
        # Cvm6l0F4bVE8QibJg+QntesC8hLc17ASJA==
        # -----END EC PRIVATE KEY----"""
        pubkey = r"""-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0
FPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/
3j+skZ6UtW+5u09lHNsj6tQ51s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQAB
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

        self._fapi_ctx.CreateNv("/nv/Owner/myNV", "system", 11, "", "")  # NV

        data_size = 11
        data = UINT8_ARRAY(nelements=data_size)
        for i, byte in enumerate("Hello World"):
            data[i] = ord(byte)
        self._fapi_ctx.NvWrite("/nv/Owner/myNV", data.cast(), data_size)  # TODO
        # b = UINT8_PTR.frompointer(None)

        self._fapi_ctx.CreateNv("/nv/Owner/myCounter", "counter", 0, "", "")  # NV
        self._fapi_ctx.NvIncrement("/nv/Owner/myCounter")
        self._fapi_ctx.NvIncrement("/nv/Owner/myCounter")

        self._fapi_ctx.CreateNv("/nv/Owner/myBitmask", "bitfield", 0, "", "")  # NV
        self._fapi_ctx.NvSetBits("/nv/Owner/myBitmask", 0xDEADBEEF01234567)

        self._fapi_ctx.CreateNv("/nv/Owner/myExtend", "pcr", 11, "", "")  # NV
        self._fapi_ctx.NvExtend("/nv/Owner/myExtend", data.cast(), data_size, None)

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

    @property
    def info(self):
        """Return FAPI info."""
        info = self._fapi_ctx.GetInfo()
        return TPMInfo(info)

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

    def pcr_extend(self, indices, value):
        """Extend TPM Platform Configuration Register with byte array."""
        for idx in indices:
            data_size = len(value)
            data = UINT8_ARRAY(nelements=data_size)
            for i, byte in enumerate(value):
                data[i] = byte
            self._fapi_ctx.PcrExtend(
                idx, data.cast(), data_size, '{ "some": "data" }'
            )  # TODO pcr log
