"""PR-3B CI network guard: the probe suite is loopback-only BY CONSTRUCTION.

The suite's promise is not "the fixtures happen to point at 127.0.0.1"; it is
that no code path reached from this runner can generate public traffic -- not
a DNS lookup, not a TCP connect, not a UDP send, and not a bind to a
non-loopback interface. So the refusal is installed on CPython's audit
events, which fire below every library abstraction (socket, http.client,
ssl, the probe engine's own constructors) and cannot be bypassed by an
import the suite adds later. An audited operation fails with the exception
the hook raises, so a leak is a hard gate failure, never a silent request.

Run with ``--self-test`` first: a guard that refuses nothing is worse than no
guard, so the guard proves its own discrimination before it is trusted.

Usage:
    python3 no_public_network.py --self-test
    python3 no_public_network.py <harness.py> [group ...]
"""

import ipaddress
import runpy
import socket  # noqa: F401 -- imported so socket.__new__ is available to hooks
import sys

REASON = "pr3b_ci_network_guard"

# Hosts that are addressable without leaving the host. ``localhost`` is
# admitted because it resolves through the platform resolver, not the wire;
# every RESULT of a lookup is still guarded at connect time.
LOCAL_NAMES = frozenset({"localhost", "local", ""})


def _describe(addr):
    if isinstance(addr, tuple) and addr:
        return "%r" % (addr,)
    return "%r" % (addr,)


def _is_local(host):
    if isinstance(host, str):
        if host in LOCAL_NAMES:
            return True
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        return address.is_loopback
    return False


def _check(kind, addr):
    # A unix socket path / pipe name is not an internet destination.
    if isinstance(addr, str):
        return
    if not isinstance(addr, tuple) or not addr or not isinstance(addr[0], str):
        return
    if not _is_local(addr[0]):
        raise RuntimeError(
            "%s: %s to %s refused -- this suite may only ever speak to "
            "loopback" % (REASON, kind, _describe(addr)))


def _hook(event, args):
    if event == "socket.connect" or event == "socket.connect_ex":
        _check("connect", args[1])
    elif event == "socket.bind":
        _check("bind", args[1])
    elif event == "socket.sendto":
        _check("sendto", args[-1])
    elif event == "socket.getaddrinfo":
        host = args[0]
        if host is not None and not _is_local(str(host)):
            raise RuntimeError(
                "%s: dns lookup of %r refused -- this suite may only resolve "
                "loopback names" % (REASON, host))


def install():
    sys.addaudithook(_hook)


def _refused(fn):
    try:
        fn()
    except RuntimeError as exc:
        return REASON in str(exc)
    except Exception:  # noqa: BLE001 -- any OTHER error means it was not us
        return False
    return False


def _allowed(fn):
    try:
        fn()
    except Exception:  # noqa: BLE001
        return False
    return True


def self_test():
    """Prove the guard discriminates: public refuses, loopback proceeds."""
    results = {}

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    results["refuses_public_tcp_connect"] = _refused(
        lambda: socket.create_connection(("8.8.8.8", 53), timeout=0.05))
    results["refuses_public_udp_send"] = _refused(
        lambda: socket.socket(type=socket.SOCK_DGRAM).sendto(
            b"x", ("9.9.9.9", 53)))
    results["refuses_public_dns"] = _refused(
        lambda: socket.getaddrinfo("example.com", 80))
    results["refuses_public_bind"] = _refused(
        lambda: socket.socket().bind(("0.0.0.0", 0)))
    results["refuses_link_local_metadata"] = _refused(
        lambda: socket.create_connection(("169.254.169.254", 80),
                                         timeout=0.05))
    results["admits_loopback_tcp"] = _allowed(
        lambda: socket.create_connection(("127.0.0.1", port),
                                         timeout=1).close())
    results["admits_loopback_dns"] = _allowed(
        lambda: socket.getaddrinfo("localhost", None))
    listener.close()

    rc = 0
    for name in sorted(results):
        if results[name] is True:
            print("PASS guard/%s" % name)
        else:
            print("FAIL guard/%s" % name)
            rc = 1
    return rc


def main(argv):
    install()
    if argv and argv[0] == "--self-test":
        return self_test()
    if not argv:
        sys.stderr.write("usage: no_public_network.py --self-test | "
                         "<harness.py> [group ...]\n")
        return 2
    sys.argv = list(argv)
    runpy.run_path(argv[0], run_name="__main__")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
