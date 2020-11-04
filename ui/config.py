# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2020 Johannes Holland
# All rights reserved.

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk


class ConfigList(Gtk.TreeView):
    """A widget for listing TPM Configuration KVPs."""

    def __init__(self, tpm):
        super().__init__()
        self._tpm = tpm

        self._store = Gtk.ListStore(str, str)
        self.set_hexpand(True)
        self.set_vexpand(True)
        self.set_model(self._store)

        # column "key"
        renderer_column_key = Gtk.CellRendererText()
        renderer_column_key.set_property("editable", True)
        renderer_column_key.set_property("family", "Monospace")
        column_key = Gtk.TreeViewColumn("Key", renderer_column_key, text=0)
        self.append_column(column_key)

        # column "value"
        renderer_column_val = Gtk.CellRendererText()
        renderer_column_val.set_property("editable", True)
        renderer_column_val.set_property("family", "Monospace")
        column_val = Gtk.TreeViewColumn(
            "Value", renderer_column_val, markup=1
        )  # TODO selectable/copyable
        self.append_column(column_val)

        select = self.get_selection()
        select.set_mode(Gtk.SelectionMode.MULTIPLE)

        self.update()

    def update(self):
        """Update list according to currently valid config"""
        self._store.clear()
        for key, value in self._tpm.config.items():
            if (
                key in self._tpm.config_overlay
                and self._tpm.config[key] != self._tpm.config_overlay[key]
            ):
                value = f"<s>{value}</s>\n{self._tpm.config_overlay[key]}"
                self._store.append([str(key), str(value)])
            else:
                self._store.append([str(key), str(value)])


class Config(Gtk.Grid):
    """A widget to view and modify the configuration of the FAPI."""

    def __init__(self, tpm):
        super().__init__(column_spacing=10, row_spacing=10)
        self._tpm = tpm

        row = 0

        config_path_lbl = Gtk.Label(label="Loaded from file", xalign=0)
        self.attach(config_path_lbl, 0, row, 1, 1)
        self._config_path_txt_buffer = Gtk.TextBuffer()
        config_path_txt = Gtk.TextView(buffer=self._config_path_txt_buffer)
        config_path_txt.set_hexpand(True)
        config_path_txt.set_monospace(True)
        config_path_txt.set_editable(False)
        self._config_path_txt_buffer.set_text(str(self._tpm.config_path))
        self.attach(config_path_txt, 1, row, 1, 1)
        self._config_path_btn = Gtk.Button(label="Open")
        self._config_path_btn.connect("clicked", self._on_config_path_btn_clicked)
        self.attach(self._config_path_btn, 2, row, 1, 1)
        row += 1

        self.config_list = ConfigList(self._tpm)
        self.attach(self.config_list, 0, row, 3, 1)
        row += 1

        self._sim_chkbtn = Gtk.CheckButton()
        self._sim_chkbtn.set_label(
            "Use Simulator"
        )  # TODO + pulldown menu: which mssim vs swtpm
        self._sim_chkbtn.set_active(True)
        self.attach(self._sim_chkbtn, 0, row, 3, 1)
        row += 1

        self._tmp_keystore_chkbtn = Gtk.CheckButton()
        self._tmp_keystore_chkbtn.set_label("Use throw-away keystore")
        self._tmp_keystore_chkbtn.set_active(True)
        self.attach(self._tmp_keystore_chkbtn, 0, row, 3, 1)
        row += 1

        self._tmp_keystore_chkbtn.connect("toggled", self._on_config_changed)
        self._sim_chkbtn.connect("toggled", self._on_config_changed)

        keystore_provisioned_lbl = Gtk.Label(label="Keystore provisioned", xalign=0)
        self.attach(keystore_provisioned_lbl, 0, row, 1, 1)
        self._keystore_provisioned_value_lbl = Gtk.Label(label="Yes", xalign=0)
        self.attach(self._keystore_provisioned_value_lbl, 1, row, 1, 1)
        keystore_clear_btn = Gtk.Button(label="Clear Keystore")
        self.attach(keystore_clear_btn, 2, row, 1, 1)     # TODO
        row += 1

        tpm_provisioned_lbl = Gtk.Label(label="TPM provisioned", xalign=0)
        self.attach(tpm_provisioned_lbl, 0, row, 1, 1)
        self._tpm_provisioned_value_lbl = Gtk.Label(xalign=0)
        self.attach(self._tpm_provisioned_value_lbl, 1, row, 1, 1)
        tpm_clear_btn = Gtk.Button(label="Clear TPM")     # TODO
        self.attach(tpm_clear_btn, 2, row, 1, 1)
        row += 1

        consistent_lbl = Gtk.Label(label="Keystore/TPM consistent", xalign=0)
        self.attach(consistent_lbl, 0, row, 1, 1)
        self._consistent_value_lbl = Gtk.Label(xalign=0)  # TODO
        self.attach(self._consistent_value_lbl, 1, row, 1, 1)
        row += 1

        self.update()

    def _on_config_path_btn_clicked(self, button):  # pylint: disable=unused-argument
        dlg = Gtk.FileChooserDialog(
            "Open",
            None,
            Gtk.FileChooserAction.OPEN,
            (
                Gtk.STOCK_CANCEL,
                Gtk.ResponseType.CANCEL,
                Gtk.STOCK_OPEN,
                Gtk.ResponseType.OK,
            ),
        )  # TODO crashes on NixOs
        response = dlg.run()
        self.text.set_text(dlg.get_filename())

    def _on_config_changed(self, *args):  # pylint: disable=unused-argument
        """Called whenever the config, the path to the config or the config overlay changes."""
        use_simulator = self._sim_chkbtn.get_active()
        use_tmp_keystore = self._tmp_keystore_chkbtn.get_active()
        self._tpm.reload(use_simulator=use_simulator, use_tmp_keystore=use_tmp_keystore)

        self.update()

    def update(self):
        self.config_list.update()

        self._keystore_provisioned_value_lbl.set_text(str(self._tpm.is_keystore_provisioned))
        self._tpm_provisioned_value_lbl.set_text(str(self._tpm.is_tpm_provisioned))
        self._consistent_value_lbl.set_text(str(self._tpm.is_consistent))
