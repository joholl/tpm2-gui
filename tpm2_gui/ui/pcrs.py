# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2020 Johannes Holland
# All rights reserved.

"""Widgets to interact with TPM Platform Configuration Registers."""

import itertools

import gi  # isort:skip

gi.require_version("Gtk", "3.0")  # pylint: disable=wrong-import-position

# isort:imports-thirdparty
from gi.repository import Gtk


class Pcrs(Gtk.TreeView):
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


class PcrOperations(Gtk.Grid):
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
        is_pcr_selected = bool(self.pcr_selection)
        is_data_txt_buffer_not_empty = bool(
            self._data_txt_buffer.get_text(
                self._data_txt_buffer.get_start_iter(), self._data_txt_buffer.get_end_iter(), True
            )
        )
        self._extend_btn.set_sensitive(is_pcr_selected and is_data_txt_buffer_not_empty)

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
