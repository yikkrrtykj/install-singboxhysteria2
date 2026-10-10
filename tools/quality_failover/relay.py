"""Loopback-only encrypted-wire fault injection for a disposable pilot core.

No protocol inspection, credentials, system routing or firewall changes.
TCP/UDP targets are immutable numeric addresses from a canonical export.
"""
import ipaddress
import select
import socket
import threading
import time


class Wire:
    def __init__(self, target):
        address, port = target
        self.target = (str(ipaddress.ip_address(address)), port)
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("wire_target")
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.sockets = set()
        self.threads = []
        self.up = True
        self.rate = 0

    def fault(self, up=True, rate=0):
        if type(up) is not bool or type(rate) not in (int, float) or rate not in (0, 1):
            raise ValueError("wire_fault")
        with self.lock:
            self.up, self.rate = up, rate

    def register(self, sock):
        with self.lock:
            if self.stop.is_set():
                sock.close()
                raise OSError("wire_closed")
            self.sockets.add(sock)

    def spawn(self, fn):
        worker = threading.Thread(target=fn, daemon=True)
        # Thread objects are bounded: TCP admission includes both pump threads.
        with self.lock:
            if self.stop.is_set():
                return
            self.threads = [item for item in self.threads if item.is_alive()]
            self.threads.append(worker)
            worker.start()

    def close_socket(self, sock):
        with self.lock:
            self.sockets.discard(sock)
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()

    def close(self):
        self.stop.set()
        with self.lock:
            sockets, workers = list(self.sockets), list(self.threads)
        for sock in sockets:
            self.close_socket(sock)
        for worker in workers:
            worker.join(timeout=3)


class TCPWire(Wire):
    def __init__(self, target):
        super().__init__(target)
        self.gate = threading.BoundedSemaphore(16)
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.listener.settimeout(.2)
        self.port = self.listener.getsockname()[1]
        self.register(self.listener)
        self.spawn(self.accept)

    def accept(self):
        while not self.stop.is_set():
            try:
                incoming, _ = self.listener.accept()
                if not self.gate.acquire(blocking=False):
                    incoming.close()
                    continue
                self.register(incoming)
                self.spawn(lambda sock=incoming: self.forward(sock))
            except socket.timeout:
                pass
            except OSError:
                break

    def forward(self, incoming):
        outgoing = None
        downstream = None
        try:
            with self.lock:
                enabled = self.up
            if not enabled:
                return
            outgoing = socket.create_connection(self.target, timeout=2)
            self.register(outgoing)
            incoming.settimeout(.5)
            outgoing.settimeout(.5)

            def pump(source, destination, shaped):
                while not self.stop.is_set():
                    with self.lock:
                        enabled, rate = self.up, self.rate if shaped else 0
                    if not enabled:
                        break
                    try:
                        data = source.recv(8192)
                        if not data:
                            break
                        if rate and self.stop.wait(len(data) * 8 / (rate * 1e6)):
                            break
                        pending = memoryview(data)
                        while pending and not self.stop.is_set():
                            try:
                                count = destination.send(pending)
                                if not count:
                                    raise OSError("wire_disconnected")
                                pending = pending[count:]
                            except socket.timeout:
                                continue
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                try:
                    destination.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

            downstream = threading.Thread(target=pump, args=(outgoing, incoming, False), daemon=True)
            downstream.start()
            pump(incoming, outgoing, True)
            downstream.join(timeout=2)
        except OSError:
            pass
        finally:
            if outgoing is not None:
                self.close_socket(outgoing)
            self.close_socket(incoming)
            if downstream is not None:
                downstream.join(timeout=1)
            self.gate.release()


class UDPWire(Wire):
    """One bounded UDP port; connected peers ensure replies from the exact VPS.

    Hopping uses one bounded select loop across the allocated local port range.
    The pilot currently uses hard drop only; UDP quality/loss calibration is
    deliberately not inferred from this lossless forwarding bridge.
    """
    def __init__(self, target, hopping=None):
        super().__init__(target)
        self.listeners = {}
        self.port_range = None
        try:
            if hopping:
                parts = hopping.split("-")
                if len(parts) != 2 or not all(item.isdecimal() for item in parts):
                    raise ValueError("hopping_range")
                low, high = map(int, parts)
                if not 1 <= low <= high <= 65535 or high - low >= 128:
                    raise ValueError("pilot_hopping_too_wide")
                # Bind an equally sized private loopback range atomically; a
                # conflict refuses/retries the whole range, never claims it.
                for attempt in range(20):
                    candidate = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    candidate.bind(("127.0.0.1", 0))
                    start = candidate.getsockname()[1]
                    candidate.close()
                    trial = {}
                    try:
                        if start + high - low > 65535:
                            continue
                        for remote in range(low, high + 1):
                            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            trial[sock] = remote
                            sock.bind(("127.0.0.1", start + remote - low))
                        self.listeners.update(trial)
                        self.port_range = (start, start + high - low)
                        break
                    except OSError:
                        for sock in trial:
                            sock.close()
                if self.port_range is None:
                    raise OSError("hopping_ports_unavailable")
            own = next((sock for sock, remote in self.listeners.items() if remote == target[1]), None)
            if own is None:
                own = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.listeners[own] = target[1]
                own.bind(("127.0.0.1", 0))
            self.port = own.getsockname()[1]
            for sock in self.listeners:
                sock.setblocking(False)
                self.register(sock)
        except BaseException:
            for sock in self.listeners:
                sock.close()
            raise
        self.peers = {}
        self.sent_packets = 0
        self.received_packets = 0
        self.spawn(self.forward)

    def fault(self, up=True, rate=0):
        if rate:
            raise ValueError("udp_rate_not_supported")
        super().fault(up, rate)

    def forward(self):
        try:
            while not self.stop.is_set():
                now = time.monotonic()
                for sock, (_, _, last) in list(self.peers.items()):
                    if now - last > 30:
                        del self.peers[sock]
                        self.close_socket(sock)
                try:
                    ready, _, _ = select.select([*self.listeners, *self.peers], [], [], .1)
                except (OSError, ValueError):
                    break
                for sock in ready:
                    try:
                        data, sender = sock.recvfrom(65535)
                        with self.lock:
                            enabled = self.up
                        if not enabled:
                            continue
                        if sock in self.listeners:
                            peer = next((item for item, (address, inbound, _) in self.peers.items()
                                         if address == sender and inbound is sock), None)
                            if peer is None:
                                if len(self.peers) >= 256:
                                    continue
                                family = socket.AF_INET6 if ":" in self.target[0] else socket.AF_INET
                                peer = socket.socket(family, socket.SOCK_DGRAM)
                                peer.connect((self.target[0], self.listeners[sock]))
                                peer.setblocking(False)
                                self.register(peer)
                            self.peers[peer] = (sender, sock, now)
                            peer.send(data)
                            self.sent_packets += 1
                        else:
                            address, inbound, _ = self.peers[sock]
                            self.peers[sock] = (address, inbound, now)
                            inbound.sendto(data, address)
                            self.received_packets += 1
                    except (OSError, KeyError):
                        continue
        finally:
            for sock in list(self.peers):
                self.close_socket(sock)
            self.peers.clear()
