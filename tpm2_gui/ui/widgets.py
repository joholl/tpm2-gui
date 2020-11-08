# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2020 Johannes Holland
# All rights reserved.

"""Utility widgets."""

import gi  # isort:skip

gi.require_version("Gtk", "3.0")  # pylint: disable=wrong-import-position

# isort:imports-thirdparty
from gi.repository import Gtk


class ValueView:
    """A text field consisting of a label, a text box and a button for editing and saving."""

    def __init__(self, label, obj, attr):
        self._obj = obj
        self._attr = attr

        self._label = Gtk.Label(label=label, xalign=0)

        self._textview_buffer = Gtk.TextBuffer()
        self._textview = Gtk.TextView(buffer=self._textview_buffer)
        self._textview.set_hexpand(True)
        self._textview.set_monospace(True)
        self._textview.set_editable(False)

        self._textview_scroll = Gtk.ScrolledWindow()
        self._textview_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self._textview_scroll.set_max_content_height(200)
        self._textview_scroll.set_propagate_natural_height(True)
        self._textview_scroll.add(self._textview)

        self.update()

    def set_tpm_object(self, obj):
        """Set TPM object whose whose attribute is made accessible."""
        self._obj = obj
        self.update()

    @property
    def label(self):
        """Get the Label widget."""
        return self._label

    @property
    def textview(self):
        """Get the TextView widget."""
        return self._textview_scroll

    def hide(self):
        """Hide all associated widgets."""
        self.label.hide()
        self.textview.hide()

    def show(self):
        """Show all associated widgets."""
        self.label.show()
        self.textview.show()

    def reset(self):  # pylint: disable=unused-argument
        """Reset all widget state."""
        self._textview.set_editable(False)
        self.update()

    def update(self):
        """Update the widget state according to the currently selected path."""
        if self._obj is not None:
            text = getattr(self._obj, self._attr)

            if text is not None:
                self._textview_buffer.set_text(text)


class ValueEditView(ValueView):
    """A text field consisting of a label, a text box and a button for editing and saving."""

    def __init__(self, label, obj, attr):
        super().__init__(label, obj, attr)

        self._button = Gtk.Button(label="Edit")
        self._button.connect("clicked", self._on_button_clicked)

        self.update()

    def _on_button_clicked(self, button):  # pylint: disable=unused-argument
        if self._textview.get_editable():
            # Safe text
            text = self._textview_buffer.get_text(
                self._textview_buffer.get_start_iter(), self._textview_buffer.get_end_iter(), True
            )
            setattr(self._obj, self._attr, text)
            self._textview.set_editable(False)

        else:
            # Enable editing text
            self._textview.set_editable(True)

        self.update()

    @property
    def button(self):
        """Get the Button widget."""
        return self._button

    def hide(self):
        """Hide all associated widgets."""
        super().hide()
        self.button.hide()

    def show(self):
        """Show all associated widgets."""
        super().show()
        self.button.show()

    def reset(self):  # pylint: disable=unused-argument
        """Reset all widget state."""
        super().reset()
        self.update()

    def update(self):
        """Update the widget state according to the currently selected path."""
        super().update()

        if self._obj is not None:
            text = getattr(self._obj, self._attr)
            self._button.set_sensitive(text is not None)

            if self._textview.get_editable():
                self._button.set_label("Safe")
            else:
                self._button.set_label("Edit")
