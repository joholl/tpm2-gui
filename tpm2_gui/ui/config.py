# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2020 Johannes Holland
# All rights reserved.

"""Widgets to configure the TPM interface."""

from pathlib import Path

import gi  # isort:skip

gi.require_version("Gtk", "3.0")  # pylint: disable=wrong-import-position

# isort:imports-thirdparty
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

    def __init__(self, tpm, on_state_change=None):
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
        # TODO reload butten (left next to open)
        self._config_path_btn = Gtk.Button(label="Open")
        self._config_path_btn.connect("clicked", self._on_config_path_btn_clicked)
        self.attach(self._config_path_btn, 2, row, 1, 1)
        row += 1

        self.config_list = ConfigList(self._tpm)
        self.attach(self.config_list, 0, row, 3, 1)
        row += 1

        self._sim_chkbtn = Gtk.CheckButton()
        self._sim_chkbtn.set_label("Start Simulator")  # TODO + pulldown menu: which mssim vs swtpm
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

        keystore_provisioned_lbl = Gtk.Label(label="TPM & Keystore provisioned:", xalign=0)
        self.attach(keystore_provisioned_lbl, 0, row, 1, 1)
        self._keystore_provisioned_value_box = Gtk.Box()
        self.attach(self._keystore_provisioned_value_box, 1, row, 1, 1)
        self._tpm_clear_btn = Gtk.Button(label="Clear TPM & Keystore")
        self._tpm_clear_btn.connect("clicked", self._on_tpm_clear_btn_clicked)
        self.attach(self._tpm_clear_btn, 2, row, 1, 1)
        row += 1

        self._add_dummy_obj_btn = Gtk.Button(label="Add Dummy Objects")
        self._add_dummy_obj_btn.set_halign(Gtk.Align.END)
        self._add_dummy_obj_btn.connect("clicked", self._on_add_dummy_obj_btn_clicked)
        hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=50)
        hbox.pack_end(self._add_dummy_obj_btn, True, True, 0)
        self.attach(hbox, 1, row, 1, 1)
        self._provision_btn = Gtk.Button(label="Provision TPM & Keystore")
        self._provision_btn.connect("clicked", self._on_provision_btn_clicked)
        self.attach(self._provision_btn, 2, row, 1, 1)
        row += 1

        if on_state_change:
            self._on_state_change = on_state_change
        else:
            self._on_state_change = []

        self.update()

    def add_on_state_change(self, callback):
        """
        Add callback function which will be notified if the TPM state is changed
        by this widget."""
        self._on_state_change.append(callback)

    def _on_config_path_btn_clicked(self, button):  # pylint: disable=unused-argument
        dialog = Gtk.FileChooserDialog(
            "Open",
            None,
            Gtk.FileChooserAction.OPEN,
            (
                Gtk.STOCK_CANCEL,
                Gtk.ResponseType.CANCEL,
                Gtk.STOCK_OPEN,
                Gtk.ResponseType.OK,
            ),
        )
        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            self._tpm.config_path = Path(dialog.get_filename())
            # TODO catch error and pop error message if file is not valid json/fapi config
        dialog.destroy()

        self._trigger_update()

    def _on_provision_btn_clicked(self, button):  # pylint: disable=unused-argument
        self._tpm.provision()
        self._trigger_update()

    def _on_tpm_clear_btn_clicked(self, button):  # pylint: disable=unused-argument
        self._tpm.tpm_clear()
        self._trigger_update()

    def _on_add_dummy_obj_btn_clicked(self, button):  # pylint: disable=unused-argument
        self._tpm.dummy_populate()
        self._trigger_update()

    def _on_config_changed(self, *args):  # pylint: disable=unused-argument
        """Called whenever the config, the path to the config or the config overlay changes."""
        use_simulator = self._sim_chkbtn.get_active()
        use_tmp_keystore = self._tmp_keystore_chkbtn.get_active()
        self._tpm.reload(use_simulator=use_simulator, use_tmp_keystore=use_tmp_keystore)

        self._trigger_update()

    def _trigger_update(self):
        """Called when the widget alters the FAPI state. Updates itself and notifies listeners"""
        self.update()

        for callback in self._on_state_change:
            callback()

    def update(self):
        """Update this widget. Not to be directly called internally."""
        self.config_list.update()

        # update provisioned icon
        for child in list(self._keystore_provisioned_value_box.get_children()):
            self._keystore_provisioned_value_box.remove(child)
        if self._tpm.is_keystore_provisioned:
            self._keystore_provisioned_value_box.add(
                Gtk.Image.new_from_stock(Gtk.STOCK_YES, Gtk.IconSize.MENU)
            )
        else:
            self._keystore_provisioned_value_box.add(
                Gtk.Image.new_from_stock(Gtk.STOCK_NO, Gtk.IconSize.MENU)
            )
        self._keystore_provisioned_value_box.show_all()

        self._add_dummy_obj_btn.set_sensitive(self._tpm.is_keystore_provisioned)
        self._provision_btn.set_sensitive(not self._tpm.is_keystore_provisioned)
