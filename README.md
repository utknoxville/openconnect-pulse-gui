# openconnect-nc-gui

This script provides a wrapper around [OpenConnect](https://www.infradead.org/openconnect/) which allows a user to log in through a WebKitGTK2 window.  This allows OpenConnect to be compatible with web-based authentication mechanisms, such as SAML.

## Requirements

The script can be used with python2 or python3, however python3 is recommended.  The following packages are also required:

 - python-gi or python-gobject
 - webkit2gtk
 - openconnect

Instruction for specific distros can be found below.

### Debian/Ubuntu

    sudo apt install python3-gi libwebkit2gtk-4.0-37 openconnect

### Fedora

    sudo yum install python-gi webkit2gtk3 openconnect

### Arch

    sudo pacman -S python-gobject webkit2gtk openconnect

## Installation

This repo can be downloaded with `git clone https://github.com/utknoxville/openconnect-pulse-gui` or via the GitHub webpage.

Installation can be performed using `pip install .` or directly calling `python setup.py install`.

## Usage

Once installed, the `openconnect-pulse-gui` script should be in your $PATH.  If not, the script `openconnect_pulse_gui/openconnect_pulse_gui.py` can be called directly.

The only required required argument is the sign-in link / server URL.  Other arguments can be found by using `python openconnect-pulse-gui.py -h`.

Note that this script will not run openconnect, it will only print the command with the correct arguments to stdout.

## Login process

Anybody wishing to recreate this functionality either manually or using another library can with the following steps:

1. Send the user to the sign-in URL.  This will either give them the ability to log in directly or redirect them to an external authentication server.
1. Wait for a `Set-Cookie` header that contains the `DSID` cookie.  This is the authentication cookie used by Pulse Secure.
1. Pass the cookie to `openconnect` using `--protocol nc` and `-C 'DSID=<cookie-value>'`.  Note that some workflows may work with `--protocol pulse`, but at this time SAML-based logins do not.


