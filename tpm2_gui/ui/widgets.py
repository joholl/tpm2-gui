# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2020 Johannes Holland
# All rights reserved.

"""Utility widgets."""

import gi  # isort:skip

gi.require_version("Gtk", "3.0")  # pylint: disable=wrong-import-position

# isort:imports-thirdparty
from gi.repository import Gtk


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
            text = self._textview_buffer.get_text(
                self._textview_buffer.get_start_iter(), self._textview_buffer.get_end_iter(), True
            )
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
