# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2020 Johannes Holland
# All rights reserved.

"""Utility widgets."""

import gi  # isort:skip

gi.require_version("Gtk", "3.0")  # pylint: disable=wrong-import-position

# isort:imports-thirdparty
from gi.repository import Gtk

from .encoding import Encoder, Encoding


class EncodingChooser(Gtk.ComboBox):
    """Widget to choose an encoding from a list of options."""

    def __init__(self, options, on_selection=None):
        super().__init__()
        self.options = Gtk.ListStore(int, str)
        for enconding_option in options:
            self.options.append([int(enconding_option), str(enconding_option)])

        self.set_model(self.options)
        cell = Gtk.CellRendererText()
        self.pack_start(cell, True)
        self.add_attribute(cell, "text", 1)
        self.set_active(0)
        self.connect("changed", self._on_changed)

        self._on_selection = []
        if on_selection:
            self._on_selection.append(on_selection)

    @property
    def selected(self):
        """The Encoding currently selected."""
        index = self.get_model()[self.get_active_iter()][:2][0]
        return Encoding(index)

    def _on_changed(self, _widget):
        for callback in self._on_selection:
            callback(self.selected)


class ValueView:
    """A text field consisting of a label, a text box and a button for editing and saving."""

    def __init__(self, label, obj, attr, encodings=None, multiline=True):
        self._obj = obj
        self._attr = attr

        self._encoding = Encoding.String
        self._encoding_cmb = None
        if encodings:
            self._encoding = encodings[0]
            if len(encodings) > 1:
                self._encoding_cmb = EncodingChooser(encodings, self._on_encoding_changed)

        self._label = Gtk.Label(label=label, xalign=0)

        if multiline:
            self._textview_model = Gtk.TextBuffer()
            self._textview = Gtk.TextView(buffer=self._textview_model)
            self._textview.set_hexpand(True)
            self._textview.set_monospace(True)
            self._textview.set_editable(False)

            self._textview_widget = Gtk.ScrolledWindow()
            self._textview_widget.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
            self._textview_widget.set_max_content_height(200)
            self._textview_widget.set_min_content_width(500)
            self._textview_widget.set_propagate_natural_height(True)
            self._textview_widget.add(self._textview)
        else:
            self._textview = Gtk.Entry()
            self._textview.set_hexpand(True)
            self._textview.set_editable(False)

            self._textview_model = self._textview
            self._textview_widget = self._textview

        self.update()

    def _on_encoding_changed(self, encoding):
        self._encoding = encoding
        self.update()

    def set_tpm_object(self, obj):
        """Set TPM object whose whose attribute is made accessible."""
        self._obj = obj
        self.update()

    def hide(self):
        """Hide all associated widgets."""
        self._label.hide()
        self._textview_widget.hide()
        if self._encoding_cmb:
            self._encoding_cmb.hide()

    def show(self):
        """Show all associated widgets."""
        self._label.show()
        self._textview_widget.show()
        if self._encoding_cmb:
            self._encoding_cmb.show()

    def automatic_visibility(self):
        """Show if TPM attribute exists for path, hide otherwise."""
        if self._obj is None or getattr(self._obj, self._attr) is None:
            self.hide()
        else:
            self.show()

    def reset(self):  # pylint: disable=unused-argument
        """Reset all widget state."""
        self._textview.set_editable(False)
        self.update()

    def attach_to_grid(self, grid, row):
        """Attach all wigets to a given row in a Gtk.Grid."""
        grid.attach(self._label, 0, row, 1, 1)
        grid.attach(self._textview_widget, 1, row, 1, 1)
        if self._encoding_cmb:
            grid.attach(self._encoding_cmb, 2, row, 1, 1)

    def update(self):
        """Update the widget state according to the currently selected path."""
        if self._obj is not None:
            text = getattr(self._obj, self._attr)

            if text is not None:
                self._textview_model.set_text(Encoder.encode(text, self._encoding))


class ValueEditView(ValueView):
    """A text field consisting of a label, a text box and a button for editing and saving."""

    def __init__(self, label, obj, attr, encodings=None, multiline=True):
        super().__init__(label, obj, attr, encodings, multiline)

        self._button = Gtk.Button(label="Edit")
        self._button.connect("clicked", self._on_button_clicked)

        self.update()

    def _on_button_clicked(self, button):  # pylint: disable=unused-argument
        if self._textview.get_editable():
            # Safe text
            text = self._textview_model.get_text(
                self._textview_model.get_start_iter(), self._textview_model.get_end_iter(), True
            )
            setattr(self._obj, self._attr, text)
            self._textview.set_editable(False)

        else:
            # Enable editing text
            self._textview.set_editable(True)

        self.update()

    def hide(self):
        """Hide all associated widgets."""
        super().hide()
        self._button.hide()

    def show(self):
        """Show all associated widgets."""
        super().show()
        self._button.show()

    def reset(self):  # pylint: disable=unused-argument
        """Reset all widget state."""
        super().reset()
        self.update()

    def attach_to_grid(self, grid, row):
        super().attach_to_grid(grid, row)
        grid.attach(self._button, 3, row, 1, 1)

    def update(self):
        """Update the widget state according to the currently selected path."""
        super().update()

        if self._obj is not None:
            text = str(getattr(self._obj, self._attr))
            self._button.set_sensitive(text is not None)

            if self._textview.get_editable():
                self._button.set_label("Safe")
            else:
                self._button.set_label("Edit")
