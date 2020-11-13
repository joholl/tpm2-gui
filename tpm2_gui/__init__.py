# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2020 Johannes Holland
# All rights reserved.

"""Graphical user interface to the TPM2 software stack (TSS) Feature API (FAPI) layer."""

import sys

import gi  # isort:skip

gi.require_version("Gdk", "3.0")  # pylint: disable=wrong-import-position
gi.require_version("Gtk", "3.0")  # pylint: disable=wrong-import-position

# isort:imports-thirdparty
from gi.repository import Gdk, Gtk  # noqa: E402

from .tpm.tpm import TPM
from .ui.config import Config
from .ui.info import Info
from .ui.objects import ObjectDetails, Objects
from .ui.pcrs import PcrOperations, Pcrs

# isort:imports-firstparty


class TPMObjectOperations(Gtk.Grid):
    """A widget for performing cryptographic operations on input data, using a TPM object."""

    def __init__(self, tpm):
        super().__init__(column_spacing=10, row_spacing=10)
        self._tpm = tpm
        self._path = None
        self._tpm_object = None

        self._input_txt_buffer = Gtk.TextBuffer()
        input_txt = Gtk.TextView(buffer=self._input_txt_buffer)
        input_txt.set_hexpand(True)
        input_txt.set_monospace(True)
        input_txt.set_editable(True)
        self._input_txt_buffer.connect("changed", self._perform_operation)
        self.attach(input_txt, 0, 0, 1, 4)

        operation_cmb_store = Gtk.ListStore(int, str)
        operation_cmb_store.append([0, "Encrypt"])
        operation_cmb_store.append([1, "Decrypt"])
        operation_cmb_store.append([2, "Sign"])
        operation_cmb_store.append([3, "Verify Signature"])
        self._operation_cmb = Gtk.ComboBox.new_with_model_and_entry(operation_cmb_store)
        self._operation_cmb.set_entry_text_column(1)
        self._operation_cmb.set_active(0)
        self._operation_cmb.connect("changed", self._perform_operation)
        self.attach(self._operation_cmb, 1, 0, 1, 4)

        self._output_txt_buffer = Gtk.TextBuffer()
        output_txt = Gtk.TextView(buffer=self._output_txt_buffer)
        output_txt.set_hexpand(True)
        output_txt.set_monospace(True)
        output_txt.set_editable(False)
        self.attach(output_txt, 2, 0, 1, 4)

        self.update()

    def _perform_operation(self, widget=None):  # pylint: disable=unused-argument
        if self._tpm_object is None:
            return

        cmb_tree_iter = self._operation_cmb.get_active_iter()
        cmb_selected_idx = self._operation_cmb.get_model()[cmb_tree_iter][:2][0]

        in_str = self._input_txt_buffer.get_text(
            self._input_txt_buffer.get_start_iter(), self._input_txt_buffer.get_end_iter(), True
        )
        out_str = {  # TODO align with above
            0: self._tpm_object.encrypt,
            1: self._tpm_object.decrypt,
            2: self._tpm_object.sign,
            3: self._tpm_object.verify,
        }[cmb_selected_idx](in_str.encode("utf-8"))

        self._output_txt_buffer.set_text(out_str)

    def set_tpm_path(self, path):
        """
        Set the TPM object path.
        The operations made accessible will be operated on this TPM object.
        """
        self._path = path
        self._tpm_object = self._tpm.fapi_object(self._path)
        self.update()

    def update(self):
        """Update the widget state according to the currently selected path."""
        self._perform_operation(None)


class MyWindow(Gtk.Window):
    """TPM GUI window."""

    def __init__(self, app, tpm):
        self._tpm = tpm
        Gtk.Window.__init__(self, title="Library", application=app)
        # self.set_default_size(1500, 1000)  # TODO
        self.set_border_width(10)
        self.set_title("tpm2-gui")
        self.set_icon_from_file("resources/tpm.svg")

        css = b"""notebook > * {
            /* background: yellow; */
        }"""
        self.style_provider = Gtk.CssProvider()
        self.style_provider.load_from_data(css)

        Gtk.StyleContext.add_provider_for_screen(
            Gdk.Screen.get_default(), self.style_provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

        self._grid = Gtk.Grid(column_spacing=10, row_spacing=10)

        # Path info
        path_lbl = Gtk.Label(label="Path", xalign=0)
        self._grid.attach(path_lbl, 0, 0, 1, 1)
        self._path_txt = Gtk.Entry()
        self._path_txt.set_hexpand(True)
        self._path_txt.set_editable(False)
        self._grid.attach(self._path_txt, 1, 0, 1, 1)

        # PCR info
        pcr_lbl = Gtk.Label(label="PCRs", xalign=0)
        self._grid.attach(pcr_lbl, 0, 1, 1, 1)
        self._pcr_txt = Gtk.Entry()
        self._pcr_txt.set_hexpand(True)
        self._pcr_txt.set_editable(False)
        self._grid.attach(self._pcr_txt, 1, 1, 1, 1)

        self._notebook = Gtk.Notebook()

        # page 1: tcti, config
        self._tpm_config = Config(self._tpm)
        self._notebook.append_page(self._tpm_config, Gtk.Label(label="Config"))

        # page 2: info
        self._tpm_info = Info(self._tpm)
        self._notebook.append_page(self._tpm_info, Gtk.Label(label="Info"))

        # page 3: tpm objects
        self._grid2 = Gtk.Grid(column_spacing=10, row_spacing=10)
        self._tpm_objects = Objects(self._tpm)
        self._grid2.attach(self._tpm_objects, 0, 0, 1, 1)
        # refresh_btn = Gtk.Button(label="Refresh") # TODO
        # self._grid2.attach(refresh_btn, 0, 1, 1, 1)
        self._tpm_details = ObjectDetails(self._tpm)
        self._grid2.attach(self._tpm_details, 1, 0, 1, 1)
        tpm_operations = TPMObjectOperations(self._tpm)
        self._grid2.attach(tpm_operations, 0, 1, 2, 1)

        # page 4: pcrs
        self._grid3 = Gtk.Grid(column_spacing=10, row_spacing=10)
        _tpmpcrs = Pcrs(self._tpm)
        self._grid3.attach(_tpmpcrs, 0, 0, 1, 1)
        _tpmpcr_operations = PcrOperations(self._tpm, _tpmpcrs.update)
        self._grid3.attach(_tpmpcr_operations, 1, 0, 1, 1)
        self._notebook.append_page(self._grid3, Gtk.Label(label="PCRs"))

        # register callbacks
        self._tpm_config.add_on_state_change(self.update)

        _tpmpcrs.on_selection_fcns.append(self._set_pcr_selection)
        _tpmpcrs.on_selection_fcns.append(_tpmpcr_operations.set_pcr_selection)

        self._tpm_objects.on_selection_fcns.append(self._set_tpm_path)
        self._tpm_objects.on_selection_fcns.append(self._tpm_details.set_tpm_path)
        self._tpm_objects.on_selection_fcns.append(self._tpm_details.reset)
        self._tpm_objects.on_selection_fcns.append(tpm_operations.set_tpm_path)

        self._grid.attach(self._notebook, 0, 2, 2, 1)
        self.add(self._grid)

        self.update()

    def _set_tpm_path(self, path):
        self._path_txt.set_text(path)

    def _set_pcr_selection(self, selection):
        self._pcr_txt.set_text(str(selection))

    def update(self):
        """Update all widget states."""
        self._tpm_config.update()

        if self._tpm.is_keystore_provisioned:  # TODO and TPM provisioned? and consistent?
            if self._notebook.page_num(self._grid2) == -1:
                self._notebook.append_page(self._grid2, Gtk.Label(label="Paths"))
                self._notebook.show_all()
            self._tpm_objects.update()

            if self._notebook.page_num(self._grid3) == -1:
                self._notebook.append_page(self._grid3, Gtk.Label(label="PCRs"))
                self._notebook.show_all()
            self._tpm_details.update()
        else:
            if self._notebook.page_num(self._grid2) > -1:
                self._notebook.remove_page(self._notebook.page_num(self._grid2))
            if self._notebook.page_num(self._grid3) > -1:
                self._notebook.remove_page(self._notebook.page_num(self._grid3))


class MyApplication(Gtk.Application):
    """TPM GUI application."""

    def __init__(self, tpm):
        super().__init__()
        self._tpm = tpm

    def do_activate(self):  # pylint: disable=arguments-differ
        win = MyWindow(self, self._tpm)
        win.set_position(Gtk.WindowPosition.CENTER)
        win.show_all()

    def do_startup(self):  # pylint: disable=arguments-differ
        Gtk.Application.do_startup(self)


def main():
    """Start TPM GUI."""
    tpm = TPM()

    app = MyApplication(tpm)
    exit_status = app.run(sys.argv)
    sys.exit(exit_status)
