# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2020 Johannes Holland
# All rights reserved.

"""Widgets to interact with TPM FAPI objects."""


import gi  # isort:skip

gi.require_version("Gtk", "3.0")  # pylint: disable=wrong-import-position

# isort:imports-thirdparty
from gi.repository import Gtk

from .widgets import Encoding, ValueEditView, ValueView


class ObjectDetails(Gtk.Grid):
    """Make the details to a TPM object accessible, e.g. the associated app data and description."""

    def __init__(self, tpm):
        super().__init__(column_spacing=10, row_spacing=10)
        self._tpm = tpm
        self._path = None
        self._tpm_object = None

        row = 0

        self.heading_lbl = Gtk.Label(xalign=0)
        self.heading_lbl.get_style_context().add_class("object_details_heading")
        self.heading_lbl.set_use_markup(True)
        self.attach(self.heading_lbl, 0, row, 1, 1)
        row += 1

        self._value_views = [
            ValueView("Path", self._tpm_object, "path", multiline=False),
            ValueView("Keystore File", self._tpm_object, "json_path", multiline=False),
            ValueEditView(
                "Description",
                self._tpm_object,
                "description",
                encodings=[Encoding.String],
            ),
            ValueEditView(
                "Application Data",
                self._tpm_object,
                "appdata",
                encodings=[Encoding.String, Encoding.Hex, Encoding.Hexdump],
            ),
            ValueView(
                "Public Key",
                self._tpm_object,
                "public",
                encodings=[Encoding.Info, Encoding.PEM, Encoding.DER],
            ),
            ValueView(
                "Object Attributes",
                self._tpm_object,
                "attributes",
                encodings=[Encoding.String],
            ),
            ValueView(
                "Policy",
                self._tpm_object,
                "policy",
                encodings=[Encoding.String],
            ),
            ValueEditView(
                "Certificate",
                self._tpm_object,
                "certificate",
                encodings=[Encoding.Info, Encoding.PEM, Encoding.DER],
            ),
            ValueEditView(
                "NV (secure memory)",
                self._tpm_object,
                "nv",
                encodings=[Encoding.String, Encoding.Hex, Encoding.Hexdump],
            ),
        ]

        for value_view in self._value_views:
            value_view.attach_to_grid(self, row)
            row += 1

        self.update()

    def _get_tpm_path(self):
        return self._path

    def set_tpm_path(self, path):
        """Set the TPM object path. The details of this TPM object are made accessible."""
        self._path = path
        self._tpm_object = self._tpm.fapi_object(self._path)
        for value_view in self._value_views:
            value_view.set_tpm_object(self._tpm_object)

        self.update()

    def reset(self, *args, **kwargs):  # pylint: disable=unused-argument
        """Reset all widget state."""
        for value_view in self._value_views:
            value_view.reset()

    def update(self):
        """Update the widget state according to the currently selected path."""

        if self._path is not None:
            obj = self._tpm.fapi_object(self._path)

            self.heading_lbl.set_text(obj.object_type_info)

            for value_view in self._value_views:
                value_view.automatic_visibility()
                value_view.update()


class Objects(Gtk.TreeView):
    """A widget for listing and selecting a FAPI TPM object."""

    def _tree_store_append(self, tree_data, path_parent="", piter_parent=None):
        """
        Take the dict tree_data and append it to the tree_store
        The root key will not be added
        """
        for key, value in tree_data.items():
            path = f"{path_parent}/{key}"
            piter_this = self._store.append(
                piter_parent, [key, self._tpm.fapi_object(path).object_type_info]
            )
            self._tree_store_append(value, path_parent=path, piter_parent=piter_this)

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
