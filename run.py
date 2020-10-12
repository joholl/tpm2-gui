# for TPM communication
import random
import tempfile
import contextlib
from tpm2_pytss.fapi import FAPI, FAPIDefaultConfig
from tpm2_pytss.binding import *
from tpm2_pytss.exceptions import TPM2Error
from tpm2_pytss.util.simulator import Simulator

# parsing/utility
import json
import itertools

# UI
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk
from gi.repository import Pango
import sys


def hexdump(byte_array, line_len=16):
    char_map = ''.join([(len(repr(chr(b))) == 3) and chr(b) or '.' for b in range(256)])
    lines = []

    # for each line
    for offset in range(0, len(byte_array), line_len):
        text = byte_array[offset:offset+line_len]
        hex = ' '.join(["%02x" % b for b in text])
        # replace non-printable chars with '.'
        printable = ''.join(["%s" % ((b <= 127 and char_map[b]) or '.') for b in text])
        lines.append("%04x  %-*s  |%s|\n" % (offset, line_len*3, hex, printable))
    return ''.join(lines)


class TPM():
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
        rc = self.fapi_ctx.Import("/ext/myExtPubKey", pubkey)

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

        rc = self.fapi_ctx.Import("/policy/myPolicy", policy)           # policy


        # TODO create some objects for debugging
        rc = self.fapi_ctx.CreateKey("HS/SRK/mySigKey", "noDa, sign", "", "")       # signature
        rc = self.fapi_ctx.CreateKey("HS/SRK/myDecKey", "noDa, decrypt", "", "")    # decrypt
        rc = self.fapi_ctx.CreateKey("HS/SRK/myRestrictedSignKey", "noDa, sign, restricted", "/policy/myPolicy", "")    # restricted

        # rc = self.fapi_ctx.CreateSeal("HS/SRK/mySeal", "noDa", 12, "", "", "Hello World!")

        rc = self.fapi_ctx.CreateNv("/nv/Owner/myNV", "noDa", 10, "", "")    # NV
        u8 = UINT8_PTR.frompointer(None)
        print()

        buf = ByteArray(3)    # 'cast', 'frompointer', 'this'
        buf[0] = 0
        buf[1] = 1
        buf[2] = 3
        # print(dir(buf))
        print(dir(buf.this))

        # with UINT8_PTR(value=1) as data:
        #     rc = self.fapi_ctx.NvWrite("/nv/Owner/myNV", data, 10)


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
        rc = self.fapi_ctx.SetCertificate("HS/SRK/mySigKey", cert)    # Cert



    def __del__(self):
        self.ctx_stack.pop_all() # TODO is this right?

    def get_path_tree(self):
        with CHAR_PTR_PTR() as info:
            info = self.fapi_ctx.List("", info)

        tree = dict()
        for path in info.split(":"):
            subtree = tree

            while path != None:
                parent = path.split('/', 1)[0]
                try:
                    path = path.split('/', 1)[1]
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
                        pcrValue, pcrLog = self.fapi_ctx.PcrRead(index, pcrValue, pcrValueSize, pcrLog)

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
                                public, private, policy = self.fapi_ctx.GetTpmBlobs(path, tpm2bPublic, tpm2bPublicSize, tpm2bPrivate, tpm2bPrivateSize, policy)
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
            print("encrypt \"" + str(plaintext) + "\" with " + str(path))

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
                ret = self.fapi_ctx.AuthorizePolicy(policy_path, key_path, policy_ref, 0)
                print(ret)
        except TPM2Error:
            # print("A----")  # TODO rm
            pass
        return None

    def pcr_extend(self, indices):
        for idx in indices:
            try:
                with UINT8_PTR(value=1) as data:
                    ret = self.fapi_ctx.PcrExtend(idx, data, 1, '{ "some": "data" }') # TODO
            except TPM2Error:
                pass
            #return policy

    def quote(self, path, indices):
        try:
            #with pcrList(size=len(indices), buffer=indices) as pcrList:
            with UINT32_PTR(len(indices)) as pcrListSize:
                with UINT8_PTR(value=1) as qualifyingData:
                    with UINT8_PTR(value=1) as signature:
                        ret = self.fapi_ctx.Quote(indices, pcrListSize.ptr(), path, "TPM-Quote", qualifyingData, 1, "", signature, 1, "", "")
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



class ChangeLabel:
    def __init__(self, label, get_text, set_text, get_path, grid=None, row=0):
        if grid is None:
            self.grid = Gtk.Grid(column_spacing=10, row_spacing=10)
        else:
            self.grid = grid

        self.label = Gtk.Label(label=label, xalign=0)
        self.grid.attach(self.label, 0, row, 1, 1)

        self.textview_buffer = Gtk.TextBuffer()
        self.textview = Gtk.TextView(buffer=self.textview_buffer)
        self.textview.set_hexpand(True)
        # self.textview.set_monospace(True)
        self.textview.set_editable(False)
        self.textview.connect("focus_out_event", self.on_textview_lost_focus)
        self.grid.attach(self.textview, 1, row, 1, 1)

        self.button = Gtk.Button(label="Edit")
        self.button.connect("clicked", self.on_button_clicked)
        self.grid.attach(self.button, 2, row, 1, 1)

        # Functions
        self.get_path = get_path
        self.get_text = get_text
        self.set_text = set_text

        self.update()

    def on_textview_lost_focus(self, textview, event_focus):
        pass

    def on_button_clicked(self, button):
        if self.textview.get_editable():
            # Safe text
            text = self.textview_buffer.props.text
            self.set_text(self.get_path(), text)
            self.textview.set_editable(False)

        else:
            # Enable editing text
            self.textview.set_editable(True)

        self.update()

    def reset(self):
        self.textview.set_editable(False)
        self.update()

    def update(self):
        text = self.get_text(self.get_path())

        if text is None:
            self.button.set_sensitive(False)
            text = "-"
        else:
            self.button.set_sensitive(True)

        self.textview_buffer.set_text(text)
        if self.textview.get_editable():
            self.button.set_label("Safe")
        else:
            self.button.set_label("Edit")



class TPMObjectDetails:
    def __init__(self, tpm):
        self.tpm = tpm
        self.path = None

        self.grid = Gtk.Grid(column_spacing=10, row_spacing=10)

        path_lbl = Gtk.Label(label="Path", xalign=0)
        self.grid.attach(path_lbl, 0, 0, 1, 1)
        self.path_txt = Gtk.Entry()
        self.path_txt.set_hexpand(True)
        self.path_txt.set_editable(False)
        self.grid.attach(self.path_txt, 1, 0, 1, 1)

        self.description_clbl = ChangeLabel("Description", self.tpm.get_description, self.tpm.set_description, self.get_tpm_path, grid=self.grid, row=1)

        self.appdata_clbl = ChangeLabel("Application Data", self.tpm.get_appdata, self.tpm.set_appdata, self.get_tpm_path, grid=self.grid, row=2)

        public_lbl = Gtk.Label(label="Public", xalign=0)
        self.grid.attach(public_lbl, 0, 3, 1, 1)
        self.public_txt_buffer = Gtk.TextBuffer()
        self.public_txt = Gtk.TextView(buffer=self.public_txt_buffer)
        self.public_txt.set_hexpand(True)
        self.public_txt.set_monospace(True)
        self.public_txt.set_editable(False)
        self.grid.attach(self.public_txt, 1, 3, 1, 1)

        # alternative: NVRead, Unseal

        private_lbl = Gtk.Label(label="Private", xalign=0)
        self.grid.attach(private_lbl, 0, 4, 1, 1)
        self.private_txt_buffer = Gtk.TextBuffer()
        self.private_txt = Gtk.TextView(buffer=self.private_txt_buffer)
        self.private_txt.set_hexpand(True)
        self.private_txt.set_monospace(True)
        self.private_txt.set_editable(False)
        self.grid.attach(self.private_txt, 1, 4, 1, 1)


        policy_lbl = Gtk.Label(label="Policy", xalign=0)
        self.grid.attach(policy_lbl, 0, 5, 1, 1)
        self.policy_txt_buffer = Gtk.TextBuffer()
        self.policy_txt = Gtk.TextView(buffer=self.policy_txt_buffer)
        self.policy_txt.set_hexpand(True)
        self.policy_txt.set_monospace(True)
        self.policy_txt.set_editable(False)
        self.policy_scroll = Gtk.ScrolledWindow()
        self.policy_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.NEVER)
        self.policy_scroll.add(self.policy_txt)
        self.grid.attach(self.policy_scroll, 1, 5, 1, 1)

        self.cert_clbl = ChangeLabel("Certificate", self.tpm.get_certificate, self.tpm.set_certificate, self.get_tpm_path, grid=self.grid, row=6)

        # cert_lbl = Gtk.Label(label="Certificate", xalign=0)
        # self.grid.attach(cert_lbl, 0, 6, 1, 1)
        # self.cert_txt_buffer = Gtk.TextBuffer()
        # self.cert_txt = Gtk.TextView(buffer=self.cert_txt_buffer)
        # self.cert_txt.set_hexpand(True)
        # self.cert_txt.set_monospace(True)
        # self.cert_txt.set_editable(False)
        # self.grid.attach(self.cert_txt, 1, 6, 1, 1)

        self.update()

    def get_tpm_path(self):
        return self.path

    def set_tpm_path(self, path):
        self.path = path
        self.update()

    def reset(self, *args, **kwargs):
        self.description_clbl.reset()
        self.appdata_clbl.reset()

    def update(self):
        if self.path is not None:
            self.path_txt.set_text(self.path)

            self.description_clbl.update()
            self.appdata_clbl.update()

            public, private, _ = self.tpm.get_public_private_policy(self.path)
            policy = self.tpm.get_policy(self.path)
            public = public if public else "-"
            private = private if private else "-"
            policy = policy if policy else "-"
            self.public_txt_buffer.set_text(public)
            self.private_txt_buffer.set_text(private)
            self.policy_txt_buffer.set_text(policy)

            # cert = self.tpm.get_certificate(self.path)
            # self.cert_txt_buffer.set_text(cert)

            self.cert_clbl.update()


class TPMObjectOperations:
    def __init__(self, tpm):
        self.tpm = tpm
        self.path = None

        self.listbox = Gtk.ListBox()
        self.listbox.set_hexpand(True)
        self.listbox.set_vexpand(True)
        self.listbox.set_selection_mode(Gtk.SelectionMode.NONE)

        self.grid = Gtk.Grid(column_spacing=10, row_spacing=10)

        self.input_txt_buffer = Gtk.TextBuffer()
        self.input_txt = Gtk.TextView(buffer=self.input_txt_buffer)
        self.input_txt.set_hexpand(True)
        self.input_txt.set_monospace(True)
        self.input_txt.set_editable(True)
        self.input_txt_buffer.connect("changed", self.perform_operation)
        self.grid.attach(self.input_txt, 0, 0, 1, 4)

        operation_cmb_store = Gtk.ListStore(int, str)
        self.operations = (self.tpm.encrypt, self.tpm.decrypt, self.tpm.sign, self.tpm.verify)
        operation_cmb_store.append([0, "Encrypt"])
        operation_cmb_store.append([1, "Decrypt"])
        operation_cmb_store.append([2, "Sign"])
        operation_cmb_store.append([3, "Verify Signature"])
        self.operation_cmb = Gtk.ComboBox.new_with_model_and_entry(operation_cmb_store)
        self.operation_cmb.set_entry_text_column(1)
        self.operation_cmb.set_active(0)
        self.operation_cmb.connect("changed", self.perform_operation)
        self.grid.attach(self.operation_cmb, 1, 0, 1, 4)

        self.output_txt_buffer = Gtk.TextBuffer()
        self.output_txt = Gtk.TextView(buffer=self.output_txt_buffer)
        self.output_txt.set_hexpand(True)
        self.output_txt.set_monospace(True)
        self.output_txt.set_editable(False)
        self.grid.attach(self.output_txt, 2, 0, 1, 4)

        self.update()

    def perform_operation(self, widget=None):
        cmb_tree_iter = self.operation_cmb.get_active_iter()
        cmb_selected_idx = self.operation_cmb.get_model()[cmb_tree_iter][:2][0]
        operation_func = self.operations[cmb_selected_idx]

        in_str = self.input_txt_buffer.props.text
        out_str = operation_func(self.path, in_str)
        self.output_txt_buffer.set_text(out_str)

    def set_tpm_path(self, path):
        self.path = path
        self.update()

    def update(self):
        self.perform_operation(None)

class TPMObjects():
    def tree_store_append(self, tree_data, piter_parent=None):
        """
        Take the dict tree_data and append it to the tree_store
        The root key will not be added
        """
        for key, value in tree_data.items():
            piter_this = self.store.append(piter_parent, [key, ""]) # TODO descr
            self.tree_store_append(value, piter_this)

    def update(self):
        """
        Fetch TPM objects and update tree_view
        """
        self.store.clear()
        path_tree = self.tpm.get_path_tree()['']
        self.tree_store_append(path_tree)
        self.view.expand_all()

    def path_from_tree_path(self, tree_path):
        """
        Get TPM object path from a tree_path object (pointing to a node in tree_store)
        """
        model = self.view.get_model()

        # walk through tree from root to node at tree_path
        path = ""
        walk_indices = []
        for walk_index in tree_path:
            walk_indices.append(walk_index)
            walk_tree_path = Gtk.TreePath.new_from_indices(walk_indices)
            path += "/" + model[walk_tree_path][0]

        return path

    def on_view_selection_changed(self, selection):
        """
        Determine the TPM object path of the selected row and call all listener functions
        """
        model, treeiter = selection.get_selected()
        tree_path = model.get_path(treeiter)
        path = self.path_from_tree_path(tree_path)

        if self.on_selection_fcns is not None:
            for on_selection_fcn in self.on_selection_fcns:
                on_selection_fcn(path)

    def __init__(self, tpm, on_selection_fcns=None):
        self.tpm = tpm
        self.store = Gtk.TreeStore(str, str)
        self.view = Gtk.TreeView()
        self.view.set_hexpand(True)
        self.view.set_vexpand(True)
        self.view.set_model(self.store)

        # column TPM Entity
        renderer_column_obj = Gtk.CellRendererText()
        column_obj = Gtk.TreeViewColumn("TPM Entity", renderer_column_obj, text=0)
        self.view.append_column(column_obj)

        # column Info
        renderer_column_info = Gtk.CellRendererText()
        column_info = Gtk.TreeViewColumn("Info", renderer_column_info, text=1)
        self.view.append_column(column_info)

        select = self.view.get_selection()
        select.connect("changed", self.on_view_selection_changed)
        if on_selection_fcns is not None:
            self.on_selection_fcns = on_selection_fcns
        else:
            self.on_selection_fcns = []

        self.update()

class TPMPcrs():
    def __init__(self, tpm, on_selection_fcns=None):
        self.tpm = tpm
        self.store = Gtk.ListStore(int, str)
        self.view = Gtk.TreeView()
        self.view.set_hexpand(True)
        self.view.set_vexpand(True)
        self.view.set_model(self.store)

        # column PCR index
        renderer_column_idx = Gtk.CellRendererText()
        column_idx = Gtk.TreeViewColumn("#", renderer_column_idx, text=0)
        self.view.append_column(column_idx)

        # column PCR Value
        renderer_column_val = Gtk.CellRendererText()
        renderer_column_val.set_property('editable', True)
        renderer_column_val.set_property('family', 'Monospace')
        column_val = Gtk.TreeViewColumn("PCR Value", renderer_column_val, text=1)
        self.view.append_column(column_val)

        select = self.view.get_selection()
        select.set_mode(Gtk.SelectionMode.MULTIPLE)
        select.connect("changed", self.on_view_selection_changed)
        if on_selection_fcns is not None:
            self.on_selection_fcns = on_selection_fcns
        else:
            self.on_selection_fcns = []

        self.update()

    def on_view_selection_changed(self, selection):
        model, treeiter = selection.get_selected_rows()

        indices = treeiter
        rows = [model[i] for i in indices]
        sel = [index for index, value in rows]

        if self.on_selection_fcns is not None:
            for on_selection_fcn in self.on_selection_fcns:
                on_selection_fcn(sel)

    def update(self):
        """
        Fetch TPM objects and update tree_view
        """
        pass
        self.store.clear()
        for idx in  itertools.count(start=0, step=1):
            value, log = self.tpm.get_pcr(idx)
            if value is None or log is None:
                break
            value = ''.join('{:02x}'.format(x) for x in value)
            self.store.append([idx, value])

class TPMPcrOperations:
    def __init__(self, tpm, extend_cb=None):
        self.tpm = tpm
        self.path = None

        self.grid = Gtk.Grid(column_spacing=10, row_spacing=10)

        data_lbl = Gtk.Label(label="Data", xalign=0)
        self.grid.attach(data_lbl, 0, 0, 1, 1)
        self.data_txt_buffer = Gtk.TextBuffer()
        self.data_txt_buffer.connect("changed", self.update_extend_btn)
        self.data_txt = Gtk.TextView(buffer=self.data_txt_buffer)
        self.data_txt.set_hexpand(True)
        self.data_txt.set_monospace(True)
        self.grid.attach(self.data_txt, 1, 0, 1, 1)

        self.extend_btn = Gtk.Button(label="Extend")
        self.extend_btn.set_hexpand(True)
        self.extend_btn.set_sensitive(False)
        self.extend_btn.connect("clicked", self.on_extend_clicked)
        self.grid.attach(self.extend_btn, 1, 1, 1, 1)

        self.quote_btn = Gtk.Button(label="Quote")
        self.quote_btn.set_hexpand(True)
        self.quote_btn.connect("clicked", self.on_quote_clicked)
        self.grid.attach(self.quote_btn, 1, 2, 1, 1)

        self.extend_cb = extend_cb

        self.pcr_selection = []

    def update_extend_btn(self, *extra):
        self.extend_btn.set_sensitive(bool(self.pcr_selection) and bool(self.data_txt_buffer.props.text))

    def set_pcr_selection(self, selection):
        self.pcr_selection = selection
        self.update_extend_btn()

    def on_extend_clicked(self, button):
        self.tpm.pcr_extend(self.pcr_selection)

        if self.extend_cb:
            self.extend_cb()

    def on_quote_clicked(self, button):
        print("Quote")
        self.tpm.quote("abc", [0])

class MyWindow(Gtk.ApplicationWindow):
    def __init__(self, app, tpm):
        Gtk.Window.__init__(self, title="Library", application=app)
        self.set_default_size(1500, 1000)
        self.set_border_width(10)

        self.grid = Gtk.Grid(column_spacing=10, row_spacing=10)

        self.tpm_objects = TPMObjects(tpm)
        self.grid.attach(self.tpm_objects.view, 0, 0, 1, 1)

        # refresh_btn = Gtk.Button(label="Refresh") # TODO
        # self.grid.attach(refresh_btn, 0, 1, 1, 1)

        self.tpm_details = TPMObjectDetails(tpm)
        self.grid.attach(self.tpm_details.grid, 1, 0, 1, 1)

        self.tpmpcrs = TPMPcrs(tpm)
        self.grid.attach(self.tpmpcrs.view, 0, 1, 1, 1)

        self.tpmpcr_operations = TPMPcrOperations(tpm, self.tpmpcrs.update)
        self.grid.attach(self.tpmpcr_operations.grid, 1, 1, 1, 1)

        self.tpm_operations = TPMObjectOperations(tpm)
        self.grid.attach(self.tpm_operations.grid, 0, 2, 2, 1)

        self.tpmpcrs.on_selection_fcns.append(self.tpmpcr_operations.set_pcr_selection)

        self.tpm_objects.on_selection_fcns.append(self.tpm_details.set_tpm_path)
        self.tpm_objects.on_selection_fcns.append(self.tpm_details.reset)
        self.tpm_objects.on_selection_fcns.append(self.tpm_operations.set_tpm_path)

        self.add(self.grid)

    def update(self):
        self.tpm_objects.update()
        self.tpm_details.update()

class MyApplication(Gtk.Application):

    def __init__(self, tpm):
        Gtk.Application.__init__(self)
        self.tpm = tpm

    def do_activate(self):
        win = MyWindow(self, self.tpm)
        win.show_all()

    def do_startup(self):
        Gtk.Application.do_startup(self)



def main():
    # Create a context stack
    with contextlib.ExitStack() as ctx_stack:
        # Create a simulator
        with Simulator() as simulator:
            # Create temporary directories to separate this example's state
            user_dir = ctx_stack.enter_context(tempfile.TemporaryDirectory())
            log_dir = ctx_stack.enter_context(tempfile.TemporaryDirectory())
            system_dir = ctx_stack.enter_context(tempfile.TemporaryDirectory())

            # Create the FAPI object
            fapi = FAPI(
                FAPIDefaultConfig._replace(
                    user_dir=user_dir,
                    system_dir=system_dir,
                    log_dir=log_dir,
                    tcti="mssim:port=%d" % (simulator.port,),
                    tcti_retry=100,
                    ek_cert_less=1,
                )
            )

            # Enter the context, create TCTI connection
            fapi_ctx = ctx_stack.enter_context(fapi)

            # Fapi_Provision
            fapi_ctx.Provision(None, None, None)

            # # ############ FAPI_GetRandom ############
            # length = 32
            # with UINT8_PTR_PTR() as random_uin8_ptr_ptr:
            #     random_swig = fapi_ctx.GetRandom(length, random_uin8_ptr_ptr)
            #     random_ByteArray = ByteArray.frompointer(random_swig)

            #     print('\n\n')
            #     print(length)
            #     print('\n\n')


            #     # random_bytearray = to_bytearray(length, random_swig)
            #     random_bytearray = bytearray(length)
            #     for i in range(0, length):
            #         random_bytearray[i] = random_ByteArray[i]

            #     if length != len(random_bytearray):
            #         raise AssertionError("Requested %d bytes, got %d" % (length, len(random_bytearray)))
            #     print("GetRandom(%d):" % length, random_bytearray)



            # ############ List Keys ############
            # with CHAR_PTR_PTR() as info:
            #     info = fapi_ctx.GetInfo(info)
            #     # print(json.dumps(info, indent=2))



            ############ Create Keys ############
            # rc = fapi_ctx.CreateKey("HS/SRK/mySigKey", "noDa, sign", "", "")       # signature
            # rc = fapi_ctx.CreateKey("HS/SRK/myDecKey", "noDa, decrypt", "", "")    # decrypt
            # rc = fapi_ctx.CreateKey("HS/SRK/myRestrictedSignKey", "noDa, sign, restricted", "", "")    # restricted
            # print(rc)


            # ############ set/GetDescription ############
            # fapi_ctx.SetDescription("/P_ECCP256SHA256/HS/SRK", "This is a key.")

            # with CHAR_PTR_PTR() as description:
            #     description = fapi_ctx.GetDescription("/P_ECCP256SHA256/HS/SRK", description)
            #     print("Desc: " + str(description))


            # ############ set/GetAppData ############
            # with UINT8_PTR() as appData:
            #     # TODO appData = "This is the App Data"
            #     appDataSize = 1000  # TODO
            #     fapi_ctx.SetAppData("/P_ECCP256SHA256/HS/SRK", appData, appDataSize)

            # with UINT8_PTR_PTR() as appData:
            #     with SIZE_T_PTR() as appDataSize:
            #         ret = fapi_ctx.GetAppData("/P_ECCP256SHA256/HS/SRK", appData, appDataSize)
            #         # print(ret)
            #         # print("")
            #         # print("".join(map(lambda b: format(b, "02x"), ret)))



            # ############ PCRs ############
            # pcrIndex = 0
            # with UINT8_PTR_PTR() as pcrValue:
            #     with SIZE_T_PTR() as pcrValueSize:
            #         with CHAR_PTR_PTR() as pcrLog:
            #             pcrLog = fapi_ctx.PcrRead(pcrIndex, pcrValue, pcrValueSize, pcrLog)
            #             print(pcrLog)





            ############ EK Cert ############

            # with CHAR_PTR_PTR() as x509certData:
            #     ret = fapi_ctx.GetCertificate("", x509certData)     # seg fault (bc missing ek cert?)
            #     print(ret)


    tpm = TPM()

    app = MyApplication(tpm)
    exit_status = app.run(sys.argv)
    sys.exit(exit_status)









if __name__ == "__main__":
    main()




