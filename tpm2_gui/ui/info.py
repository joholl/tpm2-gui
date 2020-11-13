# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2020 Johannes Holland
# All rights reserved.

"""Widgets to configure the TPM interface."""

import gi  # isort:skip

# TODO migrate to pygtk? (and spell it "gtk")
gi.require_version("Gtk", "3.0")  # pylint: disable=wrong-import-position

# isort:imports-thirdparty
from gi.repository import Gtk  # noqa: E402


class Info(Gtk.Grid):
    """A widget to view and modify the configuration of the FAPI."""

    def __init__(self, tpm):
        super().__init__(column_spacing=10, row_spacing=10)
        self._tpm = tpm

        name_attrs = {
            "Manufacturer": "manufacturer",
            "Vendor String": "vendor_string",
            "Firmware Version": "firmware_version",
            "Specification Revision": "spec_revision",
            "---": None,
            "TSS Version": "version",
        }

        row = 0

        for name, attr in name_attrs.items():
            if name == "---":
                sep = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
                self.attach(sep, 0, row, 2, 1)
            else:
                key_lbl = Gtk.Label(label=name, xalign=0)
                self.attach(key_lbl, 0, row, 1, 1)

                value = getattr(self._tpm.info, attr)
                value_lbl = Gtk.Label(label=value, xalign=0)  # TODO
                self.attach(value_lbl, 1, row, 1, 1)
            row += 1

        # sep = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
        # self.attach(sep, 0, row, 2, 1)
        # row += 1

        # # # TODO move to own class eventually
        # self.entry = Gtk.Entry()
        # self.entry.connect("key-press-event", self._on_entry_keypress)
        # self.completion = Gtk.EntryCompletion()
        # self.completion.set_inline_completion(True)
        # self.entry.set_completion(self.completion)
        # self._store = Gtk.ListStore(str)
        # self.completion.set_model(self._store)
        # self.completion.set_text_column(0)
        # self.attach(self.entry, 0, row, 1, 1)

        # self.value_lbl = Gtk.Label(label=value, xalign=0)  # TODO
        # self.attach(self.value_lbl, 1, row, 1, 1)
        # row += 1

        self.update()

    # def _on_entry_keypress(self, *args):
    #     self.update()

    def update(self):
        """Update this widget. Not to be directly called internally."""

        # self._store.clear()
        # for key in self._tpm.info.attrs_recursive():
        #     self._store.append([key])

        # self.value_lbl.set_text(self.entry.get_text())
