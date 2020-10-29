import contextlib
import json
import tempfile

from tpm2_pytss.binding import (
    CHAR_PTR_PTR,
    SIZE_T_PTR,
    UINT8_PTR,
    UINT8_PTR_PTR,
    ByteArray,
)
from tpm2_pytss.exceptions import TPM2Error
from tpm2_pytss.fapi import FAPI, FAPIDefaultConfig
from tpm2_pytss.util.simulator import Simulator


def hexdump(byte_array, line_len=16):
    char_map = "".join([(len(repr(chr(b))) == 3) and chr(b) or "." for b in range(256)])
    lines = []

    # for each line
    for offset in range(0, len(byte_array), line_len):
        text = byte_array[offset : offset + line_len]
        hex = " ".join(["%02x" % b for b in text])
        # replace non-printable chars with '.'
        printable = "".join(["%s" % ((b <= 127 and char_map[b]) or ".") for b in text])
        lines.append("%04x  %-*s  |%s|\n" % (offset, line_len * 3, hex, printable))
    return "".join(lines)


class TPM:
    def __init__(self):
        self.ctx_stack = contextlib.ExitStack()

        # Create TPM simulator
        self.simulator = self.ctx_stack.enter_context(Simulator())

        # Create temporary directories to separate this example's state
        self.user_dir = self.ctx_stack.enter_context(tempfile.TemporaryDirectory())
        self.log_dir = self.ctx_stack.enter_context(tempfile.TemporaryDirectory())
        self.system_dir = self.ctx_stack.enter_context(tempfile.TemporaryDirectory())

        # Create the FAPI object
        fapi = FAPI(
            FAPIDefaultConfig._replace(
                user_dir=self.user_dir,
                system_dir=self.system_dir,
                log_dir=self.log_dir,
                tcti="mssim:port=%d" % (self.simulator.port,),
                tcti_retry=100,
                ek_cert_less=1,
            )
        )

        # Enter the context, create TCTI connection
        self.fapi_ctx = self.ctx_stack.enter_context(fapi)

        # Fapi_Provision
        self.fapi_ctx.Provision(None, None, None)

        #         privkey = """-----BEGIN EC PRIVATE KEY-----
        # MHcCAQEEIC9A2PknCL7BFLjNDbxlPu3I5rvJGoEIQkujhSNiTblZoAoGCCqGSM49
        # AwEHoUQDQgAExgnxXp0Kj+Zuav7zbzX0COwCS/qZURF8qRef+cnkbNKCYBsZnfI3
        # Cvm6l0F4bVE8QibJg+QntesC8hLc17ASJA==
        # -----END EC PRIVATE KEY----"""
        pubkey = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUymzBzI3LcxRpqJkiP0Ks7qp1UZH
93mYpmfUJBjK6anQawTyy8k87MteUdP5IPy47gzsO7sFcbWCoVZ8LvoQUw==
-----END PUBLIC KEY-----"""
        ret = self.fapi_ctx.Import("/ext/myExtPubKey", pubkey)

        policy = """{
    "description":"Description pol_signed",
    "policy":[
        {
            "type": "POLICYSIGNED",
            "publicKeyHint": "Test key hint",
            "keyPEM": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoGL6IrCSAznmIIzBessI\nmW7tPOUy78uWTIaub32KnYHn78KXprrZ3ykp6WDrOQeMjv4AA+14mJbg77apVYXy\nEnkFdOMa1hszSJnp6cJvx7ILngLvFUxzbVki\/ehvgS3nRk67Njal+nMTe8hpe3UK\nQeV\/Ij+F0r6Yz91W+4LPmncAiUesRZLetI2BZsKwHYRMznmpIYpoua1NtS8QpEXR\nMmsUue19eS\/XRAPmmCfnb5BX2Tn06iCpk6wO+RfMo9etcX5cLSAuIYEQYCvV2\/0X\nTfEw607vttBN0Y54LrVOKno1vRXd5sxyRlfB0WL42F4VG5TfcJo5u1Xq7k9m9K57\n8wIDAQAB\n-----END PUBLIC KEY-----\n",
            "keyPEMhashAlg": "SHA1"
        }
    ]
}"""

        ret = self.fapi_ctx.Import("/policy/myPolicy", policy)  # policy

        # TODO create some objects for debugging
        ret = self.fapi_ctx.CreateKey(
            "HS/SRK/mySigKey", "noDa, sign", "", ""
        )  # signature
        ret = self.fapi_ctx.CreateKey(
            "HS/SRK/myDecKey", "noDa, decrypt", "", ""
        )  # decrypt
        ret = self.fapi_ctx.CreateKey(
            "HS/SRK/myRestrictedSignKey",
            "noDa, sign, restricted",
            "/policy/myPolicy",
            "",
        )  # restricted

        # ret = self.fapi_ctx.CreateSeal("HS/SRK/mySeal", "noDa", 12, "", "", "Hello World!")

        ret = self.fapi_ctx.CreateNv("/nv/Owner/myNV", "noDa", 10, "", "")  # NV
        # u8 = UINT8_PTR.frompointer(None)
        print()

        buf = ByteArray(3)  # 'cast', 'frompointer', 'this'
        buf[0] = 0
        buf[1] = 1
        buf[2] = 3
        # print(dir(buf))

        # with UINT8_PTR(value=1) as data:
        #     ret = self.fapi_ctx.NvWrite("/nv/Owner/myNV", data, 10)

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
        ret = self.fapi_ctx.SetCertificate("HS/SRK/mySigKey", cert)  # Cert

    def __del__(self):
        self.ctx_stack.pop_all()  # TODO is this right?

    def get_path_tree(self):
        with CHAR_PTR_PTR() as info:
            info = self.fapi_ctx.List("", info)

        tree = dict()
        for path in info.split(":"):
            subtree = tree

            while path != None:
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

    def get_description(self, path):
        try:
            with CHAR_PTR_PTR() as description:
                description = self.fapi_ctx.GetDescription(path, description)
        except TPM2Error:
            description = None
        return description

    def set_description(self, path, description):
        self.fapi_ctx.SetDescription(path, description)

    def get_appdata(self, path):
        try:
            with UINT8_PTR_PTR() as appData:
                with SIZE_T_PTR() as appDataSize:
                    appdata = self.fapi_ctx.GetAppData(path, appData, appDataSize)
                    appdata = hexdump(appdata)
        except TPM2Error:
            appdata = None
        return appdata

    def set_appdata(self, path, appdata):
        with UINT8_PTR() as appData:
            # TODO appData = "This is the App Data"
            appDataSize = len(appdata)  # TODO
            self.fapi_ctx.SetAppData(path, appData, appDataSize)

    def get_certificate(self, path):
        # if path == "/P_ECCP256SHA256":
        #     with UINT8_PTR_PTR() as certificates:
        #         with SIZE_T_PTR() as certificatesSize:
        #             ret = self.fapi_ctx.GetPlatformCertificates(certificates, certificatesSize)
        #             print(ret)
        try:
            with CHAR_PTR_PTR() as x509certData:
                cert = self.fapi_ctx.GetCertificate(path, x509certData)
        except TPM2Error:
            cert = None
        return cert

    def set_certificate(self, path, cert):
        self.fapi_ctx.SetCertificate(path, cert)

    def get_pcr(self, index):
        # TODO fetch multiple pcrs at once
        try:
            with UINT8_PTR_PTR() as pcrValue:
                with SIZE_T_PTR() as pcrValueSize:
                    with CHAR_PTR_PTR() as pcrLog:
                        pcrValue, pcrLog = self.fapi_ctx.PcrRead(
                            index, pcrValue, pcrValueSize, pcrLog
                        )

        except TPM2Error:
            pcrValue = None
            pcrLog = None

        return (pcrValue, pcrLog)

    def get_public_private_policy(self, path):
        try:
            with UINT8_PTR_PTR() as tpm2bPublic:
                with SIZE_T_PTR() as tpm2bPublicSize:
                    with UINT8_PTR_PTR() as tpm2bPrivate:
                        with SIZE_T_PTR() as tpm2bPrivateSize:
                            with CHAR_PTR_PTR() as policy:
                                public, private, policy = self.fapi_ctx.GetTpmBlobs(
                                    path,
                                    tpm2bPublic,
                                    tpm2bPublicSize,
                                    tpm2bPrivate,
                                    tpm2bPrivateSize,
                                    policy,
                                )
                                public = hexdump(public)
                                private = hexdump(private)
                                if policy is not None:
                                    policy = json.dumps(policy, indent=3)
                                else:
                                    policy = None
        except TPM2Error:
            public = None
            private = None
            policy = None

        # TODO rm
        self.get_nvdata(path)

        return (public, private, policy)

    def get_policy(self, path):
        try:
            with CHAR_PTR_PTR() as jsonPolicy:
                policy = self.fapi_ctx.ExportPolicy(path, jsonPolicy)
                if policy is not None:
                    policy = json.dumps(policy, indent=3)
                else:
                    policy = None
        except TPM2Error:
            policy = None
        return policy

    def get_nvdata(self, path):
        # print("V----")  # TODO rm
        try:
            with UINT8_PTR_PTR() as data:
                with SIZE_T_PTR() as size:
                    with CHAR_PTR_PTR() as logData:
                        ret = self.fapi_ctx.NvRead(path, data, size, logData)
                        print(ret)
        except TPM2Error:
            # print("A----")  # TODO rm
            pass
        return None

    def encrypt(self, path, plaintext):
        if plaintext:
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
            #                         ret = self.fapi_ctx.Encrypt(path, plaintext, plaintextSize, cipherText, cipherTextSize)
            #                         print("----", ret)
            # except TPM2Error:
            #     pass # TODO

            return plaintext.upper()

        return ""

    def decrypt(self, path, ciphertext):
        return ciphertext.lower()

    def sign(self, path, message):
        return message.upper()

    def verify(self, path, signature):
        return signature.lower()

    def auth_policy(self, policy_path, key_path):
        print("---- AuthorizePolicy")  # TODO rm
        try:
            with UINT8_PTR(value=0) as policy_ref:
                ret = self.fapi_ctx.AuthorizePolicy(
                    policy_path, key_path, policy_ref, 0
                )
                print(ret)
        except TPM2Error:
            # print("A----")  # TODO rm
            pass
        return None

    def pcr_extend(self, indices):
        for idx in indices:
            try:
                with UINT8_PTR(value=1) as data:
                    ret = self.fapi_ctx.PcrExtend(
                        idx, data, 1, '{ "some": "data" }'
                    )  # TODO
            except TPM2Error:
                pass
            # return policy

    def quote(self, path, indices):
        try:
            # with pcrList(size=len(indices), buffer=indices) as pcrList:
            with UINT32_PTR(len(indices)) as pcrListSize:
                with UINT8_PTR(value=1) as qualifyingData:
                    with UINT8_PTR(value=1) as signature:
                        ret = self.fapi_ctx.Quote(
                            indices,
                            pcrListSize.ptr(),
                            path,
                            "TPM-Quote",
                            qualifyingData,
                            1,
                            "",
                            signature,
                            1,
                            "",
                            "",
                        )
                        print(ret)
        except TPM2Error:
            # print("A----")  # TODO rm
            pass
        return None

    #     TSS2_RC Fapi_Quote(
    # FAPI_CONTEXT   *context,
    # uint32_t       *pcrList,
    # size_t          pcrListSize,
    # char     const *keyPath,
    # char     const *quoteType,
    # uint8_t  const *qualifyingData,
    # size_t          qualifyingDataSize,
    # char          **quoteInfo,
    # uint8_t       **signature,
    # size_t         *signatureSize,
    # char          **pcrLog,
    # char          **certificate);
