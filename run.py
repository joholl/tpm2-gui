# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2020 Johannes Holland
# All rights reserved.

"""Graphical user interface to the TPM2 software stack (TSS) Feature API (FAPI) layer."""
import itertools
import sys

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

from tpm.tpm import TPM
from ui.config import Config


class ChangeLabel:
    """A text field consisting of a label, a text box and a button for editing and saving."""

    def __init__(self, label, get_text, set_text, get_path):
        self._label = Gtk.Label(label=label, xalign=0)

        self._textview_buffer = Gtk.TextBuffer()
        self._textview = Gtk.TextView(buffer=self._textview_buffer)
        self._textview.set_hexpand(True)
        # self.textview.set_monospace(True)
        self._textview.set_editable(False)
        self._textview.connect("focus_out_event", self._on_textview_lost_focus)

        self._button = Gtk.Button(label="Edit")
        self._button.connect("clicked", self._on_button_clicked)

        # Functions
        self._get_path = get_path
        self._get_text = get_text
        self._set_text = set_text

        self.update()

    def _on_textview_lost_focus(self, textview, event_focus):
        pass

    def _on_button_clicked(self, button):  # pylint: disable=unused-argument
        if self._textview.get_editable():
            # Safe text
            text = self._textview_buffer.props.text
            self._set_text(self._get_path(), text)
            self._textview.set_editable(False)

        else:
            # Enable editing text
            self._textview.set_editable(True)

        self.update()

    @property
    def label(self):
        """Get the Label widget."""
        return self._label

    @property
    def textview(self):
        """Get the TextView widget."""
        return self._textview

    @property
    def button(self):
        """Get the Button widget."""
        return self._button

    def reset(self):  # pylint: disable=unused-argument
        """Reset all widget state."""
        self._textview.set_editable(False)
        self.update()

    def update(self):
        """Update the widget state according to the currently selected path."""
        text = self._get_text(self._get_path())

        if text is None:
            self._button.set_sensitive(False)
            text = "-"
        else:
            self._button.set_sensitive(True)

        self._textview_buffer.set_text(text)
        if self._textview.get_editable():
            self._button.set_label("Safe")
        else:
            self._button.set_label("Edit")


class TPMObjectDetails(Gtk.Grid):
    """Make the details to a TPM object accessible, e.g. the associated app data and description."""

    def __init__(self, tpm):
        super().__init__(column_spacing=10, row_spacing=10)
        self._tpm = tpm
        self._path = None

        path_lbl = Gtk.Label(label="Path", xalign=0)
        self.attach(path_lbl, 0, 0, 1, 1)
        self._path_txt = Gtk.Entry()
        self._path_txt.set_hexpand(True)
        self._path_txt.set_editable(False)
        self.attach(self._path_txt, 1, 0, 1, 1)

        self._description_clbl = ChangeLabel(
            "Description",
            self._tpm.get_description,
            self._tpm.set_description,
            self._get_tpm_path,
        )
        self.attach(self._description_clbl.label, 0, 1, 1, 1)
        self.attach(self._description_clbl.textview, 1, 1, 1, 1)
        self.attach(self._description_clbl.button, 2, 1, 1, 1)

        self._appdata_clbl = ChangeLabel(
            "Application Data",
            self._tpm.get_appdata,
            self._tpm.set_appdata,
            self._get_tpm_path,
        )
        self.attach(self._appdata_clbl.label, 0, 2, 1, 1)
        self.attach(self._appdata_clbl.textview, 1, 2, 1, 1)
        self.attach(self._appdata_clbl.button, 2, 2, 1, 1)

        public_lbl = Gtk.Label(label="Public", xalign=0)
        self.attach(public_lbl, 0, 3, 1, 1)
        self._public_txt_buffer = Gtk.TextBuffer()
        public_txt = Gtk.TextView(buffer=self._public_txt_buffer)
        public_txt.set_hexpand(True)
        public_txt.set_monospace(True)
        public_txt.set_editable(False)
        self.attach(public_txt, 1, 3, 1, 1)

        # alternative: NVRead, Unseal

        private_lbl = Gtk.Label(label="Private", xalign=0)
        self.attach(private_lbl, 0, 4, 1, 1)
        self._private_txt_buffer = Gtk.TextBuffer()
        private_txt = Gtk.TextView(buffer=self._private_txt_buffer)
        private_txt.set_hexpand(True)
        private_txt.set_monospace(True)
        private_txt.set_editable(False)
        self.attach(private_txt, 1, 4, 1, 1)

        policy_lbl = Gtk.Label(label="Policy", xalign=0)
        self.attach(policy_lbl, 0, 5, 1, 1)
        self._policy_txt_buffer = Gtk.TextBuffer()
        policy_txt = Gtk.TextView(buffer=self._policy_txt_buffer)
        policy_txt.set_hexpand(True)
        policy_txt.set_monospace(True)
        policy_txt.set_editable(False)
        policy_scroll = Gtk.ScrolledWindow()
        policy_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.NEVER)
        policy_scroll.add(policy_txt)
        self.attach(policy_scroll, 1, 5, 1, 1)

        self._cert_clbl = ChangeLabel(
            "Certificate",
            self._tpm.get_certificate,
            self._tpm.set_certificate,
            self._get_tpm_path,
        )
        self.attach(self._cert_clbl.label, 0, 6, 1, 1)
        self.attach(self._cert_clbl.textview, 1, 6, 1, 1)
        self.attach(self._cert_clbl.button, 2, 6, 1, 1)

        self.update()

    def _get_tpm_path(self):
        return self._path

    def set_tpm_path(self, path):
        """Set the TPM object path. The details of this TPM object are made accessible."""
        self._path = path
        self.update()

    def reset(self, *args, **kwargs):  # pylint: disable=unused-argument
        """Reset all widget state."""
        self._description_clbl.reset()
        self._appdata_clbl.reset()

    def update(self):
        """Update the widget state according to the currently selected path."""
        if self._path is not None:
            self._path_txt.set_text(self._path)

            self._description_clbl.update()
            self._appdata_clbl.update()

            public, private, _ = self._tpm.get_public_private_policy(self._path)
            policy = self._tpm.get_policy(self._path)
            public = public if public else "-"
            private = private if private else "-"
            policy = policy if policy else "-"
            self._public_txt_buffer.set_text(public)
            self._private_txt_buffer.set_text(private)
            self._policy_txt_buffer.set_text(policy)

            self._cert_clbl.update()


class TPMObjectOperations(Gtk.Grid):
    """A widget for performing cryptographic operations on input data, using a TPM object."""

    def __init__(self, tpm):
        super().__init__(column_spacing=10, row_spacing=10)
        self._tpm = tpm
        self._path = None

        self._input_txt_buffer = Gtk.TextBuffer()
        input_txt = Gtk.TextView(buffer=self._input_txt_buffer)
        input_txt.set_hexpand(True)
        input_txt.set_monospace(True)
        input_txt.set_editable(True)
        self._input_txt_buffer.connect("changed", self._perform_operation)
        self.attach(input_txt, 0, 0, 1, 4)

        operation_cmb_store = Gtk.ListStore(int, str)
        self._operations = (
            self._tpm.encrypt,
            self._tpm.decrypt,
            self._tpm.sign,
            self._tpm.verify,
        )
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
        cmb_tree_iter = self._operation_cmb.get_active_iter()
        cmb_selected_idx = self._operation_cmb.get_model()[cmb_tree_iter][:2][0]
        operation_func = self._operations[cmb_selected_idx]

        in_str = self._input_txt_buffer.props.text
        out_str = operation_func(self._path, in_str)
        self._output_txt_buffer.set_text(out_str)

    def set_tpm_path(self, path):
        """Set the TPM object path. The operations made accessible will be operated on this TPM object."""
        self._path = path
        self.update()

    def update(self):
        """Update the widget state according to the currently selected path."""
        self._perform_operation(None)


class TPMObjects(Gtk.TreeView):
    """A widget for listing and selecting a FAPI TPM object."""

    def _tree_store_append(self, tree_data, piter_parent=None):
        """
        Take the dict tree_data and append it to the tree_store
        The root key will not be added
        """
        for key, value in tree_data.items():
            piter_this = self._store.append(piter_parent, [key, ""])  # TODO descr
            self._tree_store_append(value, piter_this)

    def update(self):
        """
        Fetch TPM objects and update tree_view
        """
        self._store.clear()
        path_tree = self._tpm.get_path_tree()[""]
        self._tree_store_append(path_tree)
        self.expand_all()

    def _path_from_tree_path(self, tree_path):
        """
        Get TPM object path from a tree_path object (pointing to a node in tree_store)
        """
        model = self.get_model()

        # walk through tree from root to node at tree_path
        path = ""
        walk_indices = []
        for walk_index in tree_path:
            walk_indices.append(walk_index)
            walk_tree_path = Gtk.TreePath.new_from_indices(walk_indices)
            path += "/" + model[walk_tree_path][0]

        return path

    def _on_view_selection_changed(self, selection):
        """
        Determine the TPM object path of the selected row and call all listener functions
        """
        model, treeiter = selection.get_selected()
        tree_path = model.get_path(treeiter)
        path = self._path_from_tree_path(tree_path)

        if self.on_selection_fcns is not None:
            for on_selection_fcn in self.on_selection_fcns:
                on_selection_fcn(path)

    def __init__(self, tpm, on_selection_fcns=None):
        super().__init__()
        self._tpm = tpm
        self._store = Gtk.TreeStore(str, str)
        self.set_hexpand(True)
        self.set_vexpand(True)
        self.set_model(self._store)

        # TODO selection must be always exactly 1 (comma must not unselect)

        # column TPM Entity
        renderer_column_obj = Gtk.CellRendererText()
        column_obj = Gtk.TreeViewColumn("TPM Entity", renderer_column_obj, text=0)
        self.append_column(column_obj)

        # column Info
        renderer_column_info = Gtk.CellRendererText()
        column_info = Gtk.TreeViewColumn("Info", renderer_column_info, text=1)
        self.append_column(column_info)

        select = self.get_selection()
        select.connect("changed", self._on_view_selection_changed)
        if on_selection_fcns is not None:
            self.on_selection_fcns = on_selection_fcns
        else:
            self.on_selection_fcns = []

        self.update()


class TPMPcrs(Gtk.TreeView):
    """A widget for listing and selecting TPM PCRs."""

    def __init__(self, tpm, on_selection_fcns=None):
        super().__init__()
        self._tpm = tpm
        self._store = Gtk.ListStore(int, str)
        self.set_hexpand(True)
        self.set_vexpand(True)
        self.set_model(self._store)

        # column PCR index
        renderer_column_idx = Gtk.CellRendererText()
        column_idx = Gtk.TreeViewColumn("#", renderer_column_idx, text=0)
        self.append_column(column_idx)

        # column PCR Value
        renderer_column_val = Gtk.CellRendererText()
        renderer_column_val.set_property("editable", True)
        renderer_column_val.set_property("family", "Monospace")
        column_val = Gtk.TreeViewColumn("PCR Value", renderer_column_val, text=1)
        self.append_column(column_val)

        select = self.get_selection()
        select.set_mode(Gtk.SelectionMode.MULTIPLE)
        select.connect("changed", self._on_view_selection_changed)
        if on_selection_fcns is not None:
            self.on_selection_fcns = on_selection_fcns
        else:
            self.on_selection_fcns = []

        self.update()

    def _on_view_selection_changed(self, selection):
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
        self._store.clear()
        for idx in itertools.count(start=0, step=1):
            value, log = self._tpm.get_pcr(idx)
            if value is None or log is None:
                break
            value = "".join("{:02x}".format(x) for x in value)
            self._store.append([idx, value])


class TPMPcrOperations(Gtk.Grid):
    """A widget performing operations on a selection of TPM PCRs."""

    def __init__(self, tpm, extend_cb=None):
        super().__init__(column_spacing=10, row_spacing=10)
        self._tpm = tpm
        self._path = None

        data_lbl = Gtk.Label(label="Data", xalign=0)
        self.attach(data_lbl, 0, 0, 1, 1)
        self._data_txt_buffer = Gtk.TextBuffer()
        self._data_txt_buffer.connect("changed", self._update_extend_btn)
        data_txt = Gtk.TextView(buffer=self._data_txt_buffer)
        data_txt.set_hexpand(True)
        data_txt.set_monospace(True)
        self.attach(data_txt, 1, 0, 1, 1)

        self._extend_btn = Gtk.Button(label="Extend")
        self._extend_btn.set_hexpand(True)
        self._extend_btn.set_sensitive(False)
        self._extend_btn.connect("clicked", self._on_extend_clicked)
        self.attach(self._extend_btn, 1, 1, 1, 1)

        self._quote_btn = Gtk.Button(label="Quote")
        self._quote_btn.set_hexpand(True)
        self._quote_btn.connect("clicked", self._on_quote_clicked)
        self.attach(self._quote_btn, 1, 2, 1, 1)

        self.extend_cb = extend_cb

        self.pcr_selection = []

    def _update_extend_btn(self, *extra):  # pylint: disable=unused-argument
        self._extend_btn.set_sensitive(
            bool(self.pcr_selection) and bool(self._data_txt_buffer.props.text)
        )

    def set_pcr_selection(self, selection):  # TODO callback in the other direction?
        """Set which PCRs are selected. All operations will be performed on these PCRs."""
        self.pcr_selection = selection
        self._update_extend_btn()

    def _on_extend_clicked(self, button):  # pylint: disable=unused-argument
        self._tpm.pcr_extend(self.pcr_selection)

        if self.extend_cb:
            self.extend_cb()

    def _on_quote_clicked(self, button):  # pylint: disable=unused-argument
        self._tpm.quote("abc", [0])  # TODO


class MyWindow(Gtk.Window):
    """TPM GUI window."""

    def __init__(self, app, tpm):
        Gtk.Window.__init__(self, title="Library", application=app)
        self.set_default_size(1500, 1000)
        self.set_border_width(10)

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
        tpm_config = Config(tpm)
        self._notebook.append_page(tpm_config, Gtk.Label(label="Config"))

        # page 2: tpm objects
        self._grid2 = Gtk.Grid(column_spacing=10, row_spacing=10)
        self._tpm_objects = TPMObjects(tpm)
        self._grid2.attach(self._tpm_objects, 0, 0, 1, 1)
        # refresh_btn = Gtk.Button(label="Refresh") # TODO
        # self._grid2.attach(refresh_btn, 0, 1, 1, 1)
        self._tpm_details = TPMObjectDetails(tpm)
        self._grid2.attach(self._tpm_details, 1, 0, 1, 1)
        tpm_operations = TPMObjectOperations(tpm)
        self._grid2.attach(tpm_operations, 0, 1, 2, 1)
        self._notebook.append_page(self._grid2, Gtk.Label(label="Paths"))

        # page 3: pcrs
        self._grid3 = Gtk.Grid(column_spacing=10, row_spacing=10)
        _tpmpcrs = TPMPcrs(tpm)
        self._grid3.attach(_tpmpcrs, 0, 0, 1, 1)
        _tpmpcr_operations = TPMPcrOperations(tpm, _tpmpcrs.update)
        self._grid3.attach(_tpmpcr_operations, 1, 0, 1, 1)
        self._notebook.append_page(self._grid3, Gtk.Label(label="PCRs"))

        # register callbacks
        _tpmpcrs.on_selection_fcns.append(self._set_pcr_selection)
        _tpmpcrs.on_selection_fcns.append(_tpmpcr_operations.set_pcr_selection)

        self._tpm_objects.on_selection_fcns.append(self._set_tpm_path)
        self._tpm_objects.on_selection_fcns.append(self._tpm_details.set_tpm_path)
        self._tpm_objects.on_selection_fcns.append(self._tpm_details.reset)
        self._tpm_objects.on_selection_fcns.append(tpm_operations.set_tpm_path)

        self._grid.attach(self._notebook, 0, 2, 2, 1)
        self.add(self._grid)

    def _set_tpm_path(self, path):
        self._path_txt.set_text(path)

    def _set_pcr_selection(self, selection):
        self._pcr_txt.set_text(str(selection))

    def update(self):
        """Update the all widget states."""
        self._tpm_objects.update()
        self._tpm_details.update()


class MyApplication(Gtk.Application):
    """TPM GUI application."""

    def __init__(self, tpm):
        super().__init__()
        self._tpm = tpm

    def do_activate(self):
        win = MyWindow(self, self._tpm)
        win.show_all()

    def do_startup(self):
        Gtk.Application.do_startup(self)


def main():
    """Start TPM GUI."""
    tpm = TPM()

    app = MyApplication(tpm)
    exit_status = app.run(sys.argv)
    sys.exit(exit_status)


if __name__ == "__main__":
    main()
