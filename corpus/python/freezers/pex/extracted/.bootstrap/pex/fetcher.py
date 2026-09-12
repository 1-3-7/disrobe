

from __future__ import absolute_import

import contextlib
import os
import socket
import sys
import threading
import time
from contextlib import closing, contextmanager

from pex.auth import PasswordDatabase, PasswordEntry
from pex.compatibility import (
    PY2,
    AbstractHTTPHandler,
    FileHandler,
    HTTPBasicAuthHandler,
    HTTPConnection,
    HTTPDigestAuthHandler,
    HTTPError,
    HTTPPasswordMgrWithDefaultRealm,
    HTTPResponse,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
    in_main_thread,
    urlparse,
)
from pex.exceptions import production_assert
from pex.network_configuration import NetworkConfiguration
from pex.typing import TYPE_CHECKING, cast
from pex.version import __version__

if TYPE_CHECKING:
    from ssl import SSLContext
    from typing import Any, BinaryIO, Dict, Iterable, Iterator, Mapping, Optional, Text

    import attr
else:
    BinaryIO = None
    from pex.third_party import attr


@contextmanager
def guard_stdout():
    # type: () -> Iterator[None]


    if hasattr(sys, "pypy_version_info") and sys.version_info[:2] >= (3, 9):
        with open(os.devnull, "w") as fp:

            with contextlib.redirect_stdout(fp):
                yield
    else:
        yield


@attr.s(frozen=True)
class _CertConfig(object):
    @classmethod
    def create(cls, network_configuration=None):
        # type: (Optional[NetworkConfiguration]) -> _CertConfig
        if network_configuration is None:
            return cls()
        return cls(cert=network_configuration.cert, client_cert=network_configuration.client_cert)

    cert = attr.ib(default=None)
    client_cert = attr.ib(default=None)

    def create_ssl_context(self):
        # type: () -> SSLContext


        production_assert(
            in_main_thread(),
            "An SSLContext must be initialized from the main thread. An attempt was made to "
            "initialize an SSLContext for {cert_config} from thread {thread}.",
            cert_config=self,
            thread=threading.current_thread(),
        )
        with guard_stdout():


            import ssl

            ssl_context = ssl.create_default_context(cafile=self.cert)
            if self.client_cert:
                ssl_context.load_cert_chain(self.client_cert)
            return ssl_context


_SSL_CONTEXTS = {}


def get_ssl_context(network_configuration=None):
    # type: (Optional[NetworkConfiguration]) -> SSLContext
    cert_config = _CertConfig.create(network_configuration=network_configuration)
    ssl_context = _SSL_CONTEXTS.get(cert_config)
    if not ssl_context:
        ssl_context = cert_config.create_ssl_context()
        _SSL_CONTEXTS[cert_config] = ssl_context
    return ssl_context


def initialize_ssl_context(network_configuration=None):
    # type: (Optional[NetworkConfiguration]) -> None
    get_ssl_context(network_configuration=network_configuration)


initialize_ssl_context()


class UnixHTTPConnection(HTTPConnection):
    def __init__(
        self,
        *args,
        **kwargs
    ):
        # type: (...) -> None
        path = kwargs.pop("path")
        super(UnixHTTPConnection, self).__init__(*args, **kwargs)
        self.path = path

    def connect(self):
        # type: () -> None
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.path)
        self.sock = sock


class UnixHTTPHandler(AbstractHTTPHandler):


    def unix_open(self, req):
        # type: (Request) -> HTTPResponse
        url_info = urlparse.urlparse(req.get_full_url())

        path = ""
        unix_socket_path = url_info.path
        while not os.path.basename(unix_socket_path).endswith(".sock"):
            path = os.path.join(path, os.path.basename(unix_socket_path))
            new_unix_socket_path = os.path.dirname(unix_socket_path)
            if new_unix_socket_path == unix_socket_path:

                path = ""
                unix_socket_path = url_info.path
                break
            unix_socket_path = new_unix_socket_path


        url = urlparse.urlunparse(
            ("unix", "localhost", path, url_info.params, url_info.query, url_info.fragment)
        )
        kwargs = {} if PY2 else {"method": req.get_method()}
        modified_req = Request(
            url,
            data=req.data,
            headers=req.headers,

            origin_req_host=cast(str, req.origin_req_host),
            unverifiable=req.unverifiable,
            **kwargs
        )


        # Python version.
        modified_req.timeout = req.timeout


        return cast(
            HTTPResponse, self.do_open(UnixHTTPConnection, modified_req, path=unix_socket_path)
        )


class URLFetcher(object):
    USER_AGENT = "pex/{version}".format(version=__version__)

    def __init__(
        self,
        network_configuration=None,
        handle_file_urls=False,
        password_entries=(),
        netrc_file="~/.netrc",
    ):
        # type: (...) -> None
        network_configuration = network_configuration or NetworkConfiguration()

        self._timeout = network_configuration.timeout
        self._max_retries = network_configuration.retries
        self._proxy = network_configuration.proxy
        self._cert = network_configuration.cert

        proxies = None
        if network_configuration.proxy:
            proxies = {protocol: network_configuration.proxy for protocol in ("http", "https")}

        handlers = [
            ProxyHandler(proxies),
            HTTPSHandler(context=get_ssl_context(network_configuration=network_configuration)),
            UnixHTTPHandler(),
        ]
        if handle_file_urls:
            handlers.append(FileHandler())

        self._password_database = PasswordDatabase.from_netrc(netrc_file=netrc_file).append(
            password_entries
        )
        self._handlers = tuple(handlers)

    def network_env(self):
        # type: () -> Dict[str, str]
        env = {}
        if self._proxy:
            env.update(
                ("{protocol}_proxy".format(protocol=protocol), self._proxy)
                for protocol in ("http", "https")
            )
        if self._cert:
            env["SSL_CERT_DIR" if os.path.isdir(self._cert) else "SSL_CERT_FILE"] = self._cert
        return env

    @contextmanager
    def get_body_stream(
        self,
        url,
        extra_headers=None,
    ):
        # type: (...) -> Iterator[BinaryIO]

        handlers = list(self._handlers)
        if self._password_database.entries:
            password_manager = HTTPPasswordMgrWithDefaultRealm()
            for password_entry in self._password_database.entries:


                password_manager.add_password(
                    realm=None,
                    uri=password_entry.uri_or_default(url),
                    user=password_entry.username,
                    passwd=password_entry.password,
                )
            handlers.extend(
                (HTTPBasicAuthHandler(password_manager), HTTPDigestAuthHandler(password_manager))
            )

        retries = 0
        retry_delay_secs = 0.1
        last_error = None
        while retries <= self._max_retries:
            if retries > 0:
                time.sleep(retry_delay_secs)
                retry_delay_secs *= 2

            opener = build_opener(*handlers)
            headers = dict(extra_headers) if extra_headers else {}
            headers["User-Agent"] = self.USER_AGENT
            request = Request(


                url,
                headers=headers,
            )


            fp = cast(BinaryIO, opener.open(request, timeout=self._timeout))
            try:
                with closing(fp) as body_stream:
                    yield body_stream
                    return
            except HTTPError as e:

                if e.code not in (
                    408,
                    500,
                    503,
                    504,
                ):
                    raise e
                last_error = e
            except (IOError, OSError) as e:


                last_error = e
            finally:
                retries += 1

        raise cast(Exception, last_error)

    @contextmanager
    def get_body_iter(self, url):
        # type: (Text) -> Iterator[Iterator[Text]]
        with self.get_body_stream(url) as body_stream:
            yield (line.decode("utf-8") for line in body_stream.readlines())
