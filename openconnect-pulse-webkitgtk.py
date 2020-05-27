#!/usr/bin/env python3
from __future__ import print_function

try:
    import gi
except ImportError:
    try:
        import pgi as gi
    except ImportError:
        gi = None
if gi is None:
    raise ImportError("Either gi (PyGObject) or pgi module is required.")

import argparse
import logging
import os
import queue
import subprocess
import sys
import time
import threading

try:
    from urllib.parse import urlparse, urlunparse
except ImportError:
    from urlparse import urlparse, urlunparse

gi.require_version("Gtk", "3.0")
gi.require_version("WebKit2", "4.0")
from gi.repository import Gtk, WebKit2, GLib

log = logging.getLogger("pulsegui")
#logging.basicConfig(level=logging.DEBUG)
logging.basicConfig(level=logging.INFO)

class SAMLLoginView:
    def __init__(self, uri, html=None, verbose=False, cookies=None, verify=True):
        self._window = Gtk.Window()

        # API reference: https://lazka.github.io/pgi-docs/#WebKit2-4.0

        uri_obj = urlparse(uri)._replace(scheme="https")
        uri = urlunparse(uri_obj)

        self.closed = False
        self.user_closed = False
        self.success = False
        self.verbose = verbose
        self.auth_cookie = None
        self._log = logging.getLogger(__name__)

        self._ctx = WebKit2.WebContext.get_default()
        if not verify:
            self._ctx.set_tls_errors_policy(WebKit2.TLSErrorsPolicy.IGNORE)

        self._cookies = self._ctx.get_cookie_manager()
        if cookies:
            log.info("Saving cookies to %s", cookies)
            self._cookies.set_accept_policy(WebKit2.CookieAcceptPolicy.ALWAYS)
            self._cookies.set_persistent_storage(
                cookies, WebKit2.CookiePersistentStorage.SQLITE
            )

        self._webview = WebKit2.WebView()
        self._webview.connect('load-failed-with-tls-errors', self._tls_error, None)

        self._window.resize(500, 500)
        self._window.add(self._webview)
        self._window.show_all()
        self._window.set_title("Pulse Connect Login")
        self._window.connect("delete-event", self._user_close)
        self._window.connect("destroy", self._close)
        self._webview.connect("resource-load-started", self._log_request)
        self._cookies.connect("changed", self._cookie_changed)

        self._request_id = 0

        if html:
            self._webview.load_html(html, uri)
        else:
            self._webview.load_uri(uri)

    def _user_close(self, *args, **kwargs):
        self.user_closed = True
        self._close()

    def _close(self, *args, **kwargs):
        if not self.closed:
            self.closed = True
            Gtk.main_quit()

    def _log_request(self, webview, resource, request):
        request_id = self._request_id
        self._request_id += 1
        # self._log.debug(
        # "[REQ  %d] %s %s"
        # , request_id, request.get_http_method() or "Request", resource.get_uri(),
        # )
        # if self.verbose > 2:
        resource.connect("finished", self._log_resource_details, (request_id, request))
        resource.connect("sent-request", self._log_sent_request, (request_id, request))

    def _tls_error(self, webview, failing_uri, certificate, errors, user_data):
        self._log.error('TLS error on {} : {}. Use --insecure to bypass certificate validation.'.format(failing_uri, ', '.join(errors.value_nicks)))

    def _log_sent_request(self, resource, request, redirected_response, userdata):
        request_id, request = userdata
        new_uri = request.get_uri()
        method = request.get_http_method() or "Request"
        if redirected_response:
            status_code = redirected_response.get_status_code()
            old_uri = redirected_response.get_uri()
            self._log.debug(
                "[REQ2 %d] %s redirect to %s", request_id, status_code, old_uri
            )
        else:
            self._log.debug("[REQ2 %d] %s %s", request_id, method, new_uri)

    def _log_resource_details(self, resource, userdata):
        request_id, request = userdata
        method = request.get_http_method() or "Request"
        uri = resource.get_uri()
        response = resource.get_response()
        if not response:
            return
        status_code = response.get_status_code()
        content_type = response.get_mime_type()
        content_length = response.get_content_length()
        content_details = "%d bytes of %s" % (content_length, content_type,)
        log.debug("[RESP %d] %s: %s", request_id, status_code, content_details)

    def log_resource_text(
        self, resource, result, content_type, charset=None, show_headers=None
    ):
        data = resource.get_data_finish(result)
        content_details = "%d bytes of %s%s for " % (
            len(data),
            content_type,
            ("; charset=" + charset) if charset else "",
        )
        log.info(
            "[DATA   ] %sresource %s", content_details, resource.get_uri(),
        )
        if show_headers:
            for h, v in show_headers.items():
                print("%s: %s" % (h, v), file=sys.stderr)
            print(file=sys.stderr)
        if charset or content_type.startswith("text/"):
            print(data.decode(charset or "utf-8"), file=sys.stderr)

    def _cookie_changed(self, event):
        uri = self._webview.get_uri()
        # if self.verbose:
        # print(event, uri)
        self._cookies.get_cookies(uri, None, self._check_for_authcookie, uri)

    def _check_for_authcookie(self, source_object, res, uri):
        cookies = source_object.get_cookies_finish(res)
        # print(uri)
        for cookie in cookies:
            #            print(
            #                " ",
            #                cookie.name,
            #                cookie.value,
            #                cookie.domain,
            #                cookie.path,
            #                cookie.expires,
            #                cookie.secure,
            #                cookie.http_only,
            #            )
            if cookie.name == "DSID":
                if not self.success:
                    # Only call destroy once
                    self.auth_cookie = cookie
                    self.success = True
                    print("Got auth cookie")
                    self._window.destroy()
        # print()


def parse_args(args=None):
    p = argparse.ArgumentParser()
    p.add_argument("server", help="Pulse Secure Connect URL")
    p.add_argument(
        "--insecure", action="store_true", help="Ignore invalid server certificate",
    )
    p.add_argument('--session-cookie', help="Name of the session cookie (default: %(default)s)", default="DSID")
    x = p.add_mutually_exclusive_group()
    x.add_argument(
        "-C",
        "--cookies",
        default="~/.config/pulse-gui-cookies",
        help="Use and store cookies in this file (instead of default %(default)s)",
    )
    x.add_argument(
        "-K",
        "--no-cookies",
        dest="cookies",
        action="store_const",
        const=None,
        help="Don't use or store cookies at all",
    )
    x = p.add_mutually_exclusive_group()
    x.add_argument(
        "-v",
        "--verbose",
        default=1,
        action="count",
        help="Increase verbosity of explanatory output to stderr",
    )
    x.add_argument(
        "-q",
        "--quiet",
        dest="verbose",
        action="store_const",
        const=0,
        help="Reduce verbosity to a minimum",
    )
    args = p.parse_args(args=None)

    if args.cookies:
        args.cookies = os.path.expanduser(args.cookies)

    return p, args


def openconnect(server, authcookie, run_openconnect=True):
    cmd = [
        "openconnect",
        "--protocol",
        "nc",
        "-C",
        "{}={}".format(authcookie.name, authcookie.value),
        server,
    ]
    if not run_openconnect:
        print(" ".join(cmd))
        return None
    # create = asyncio.create_subprocess_exec(*cmd) #, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    # proc = yield from create
    # ret = yield from proc.wait()
    else:
        proc = subprocess.Popen(cmd)
        print(proc)
        ret = proc.wait()
        return ret
    # stdout, stderr = await proc.communicate()
    # print(stdout.decode())


def saml_thread(jobQ, retQ, closeEvent):
    while not closeEvent.is_set():
        try:
            job = jobQ.get(block=False)
        except queue.Empty:
            time.sleep(0.1)
            continue
        slv = SAMLLoginView(
            job.server,
            verbose=job.verbose,
            cookies=job.cookies,
            verify=not job.insecure,
        )
        Gtk.main()
        if slv.user_closed:
            retQ.put({"error": "Login window closed by user", "retry": False})
        elif not slv.success:
            retQ.put(
                {
                    "error": "Login window closed without producing session cookie",
                    "retry": True,
                }
            )
        else:
            retQ.put({"auth_cookie": slv.auth_cookie})


if __name__ == "__main__":
    p, args = parse_args()

    if os.geteuid() != 0:
        log.warning(
            "Running as non-root user. Will not run openconnect, only print the command"
        )
        run_openconnect = False

    # Create a thread for GTK handling
    # This allows us to do things in the main python thread (e.g. catch SIGINT)

    # closeEvent signals to Gtk thread that it should immediately stop
    # when closeEvent is used, the main python thread calls Gtk.main_quit()

    jobQ = queue.Queue()
    retQ = queue.Queue()
    closeEvent = threading.Event()

    webkitthread = threading.Thread(target=saml_thread, args=(jobQ, retQ, closeEvent))
    webkitthread.start()

    while True:
        try:
            jobQ.put(args)
            ret = retQ.get()
            if "error" in ret:
                log.error(ret["error"])
                if not ret["retry"]:
                    break
                time.sleep(0.5)
                continue

            # extract response and convert to OpenConnect command-line
            exit_code = openconnect(
                args.server, ret["auth_cookie"], run_openconnect=run_openconnect
            )
        except KeyboardInterrupt:
            log.warning("User exited")
            Gtk.main_quit()
            break
        else:
            if exit_code is None:
                break
            # print(exit_code)
            log.info("Got exit code %d. Retrying..", exit_code)
            time.sleep(1)
    closeEvent.set()
    webkitthread.join()
    sys.exit(0)
