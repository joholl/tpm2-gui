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


class MyWindow(Gtk.Window):
    """TPM GUI window."""

    def __init__(self, app, tpm):
        self._tpm = tpm
        Gtk.Window.__init__(self, title="Library", application=app)
        self.set_default_size(1300, 800)
        self.set_border_width(10)
        self.set_title("tpm2_gui")
        #self.set_icon_from_file("resources/tpm.svg")

        css = b"""
        textview.view {
            padding: 8px;
        }
        notebook stack {
            padding: 16px;
        }

        .object_details {
            padding: 32px;
        }
        .object_details_heading {
            font-size: 1.5em;
        }
        """
        self.style_provider = Gtk.CssProvider()
        self.style_provider.load_from_data(css)

        Gtk.StyleContext.add_provider_for_screen(
            Gdk.Screen.get_default(), self.style_provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

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

        # page 4: pcrs
        self._grid3 = Gtk.Grid(column_spacing=10, row_spacing=10)
        _tpmpcrs = Pcrs(self._tpm)
        self._grid3.attach(_tpmpcrs, 0, 0, 1, 1)
        _tpmpcr_operations = PcrOperations(self._tpm, _tpmpcrs.update)
        self._grid3.attach(_tpmpcr_operations, 1, 0, 1, 1)
        self._notebook.append_page(self._grid3, Gtk.Label(label="PCRs"))

        # register callbacks
        self._tpm_config.add_on_state_change(self.update)

        _tpmpcrs.on_selection_fcns.append(_tpmpcr_operations.set_pcr_selection)

        self._tpm_objects.on_selection_fcns.append(self._tpm_details.set_tpm_path)
        self._tpm_objects.on_selection_fcns.append(self._tpm_details.reset)

        self.add(self._notebook)

        self.update()

    def update(self):
        """Update all widget states."""
        self._tpm_config.update()

        if self._tpm.is_keystore_provisioned:
            if self._notebook.page_num(self._grid2) == -1:
                self._notebook.append_page(self._grid2, Gtk.Label(label="Paths"))
                self._notebook.show_all()
            self._tpm_objects.update()
        else:
            if self._notebook.page_num(self._grid2) > -1:
                self._notebook.remove_page(self._notebook.page_num(self._grid2))


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
