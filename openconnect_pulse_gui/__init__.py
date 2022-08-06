"""
This script provides a wrapper around OpenConnect which allows a user to log in
through a WebKitGTK2 window.  This allows OpenConnect to be compatible with
web-based authentication mechanisms, such as SAML.
"""

from .openconnect_pulse_gui import main
