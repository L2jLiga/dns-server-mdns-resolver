#!/usr/bin/env python3
# encoding: utf-8
# -*- coding: utf-8 -*-

from __future__ import print_function

import socket
import struct
from threading import Timer

from dnslib import DNSRecord, RCODE, QTYPE
from dnslib.server import DNSServer, BaseResolver, DNSLogger, DNSHandler


class MdnsResolver(BaseResolver):
    timeout: float = 1.

    def __init__(self, timeout: float = 1.):
        self.timeout = timeout

    # Gets a multicast socket for use in mDNS queries and responses.
    def get_mdns_socket(self):
        # Set up a listening socket so we can sniff out all the mDNS traffic on the
        # network. REUSEADDR is required on all systems, REUSEPORT also for OS X.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if sys.platform == "darwin":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(("0.0.0.0", 5353))

        # Join the multicast group, prepare to receive packets from it.
        mreq = struct.pack("4sl", socket.inet_aton("224.0.0.251"), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        return sock

    def resolve(self, request: DNSRecord, handler: DNSHandler) -> DNSRecord:
        with self.get_mdns_socket() as sock:
            reply = request.reply()
            if request.q.qtype not in [
                getattr(QTYPE, "A"),
                getattr(QTYPE, "AAAA"),
            ] or not request.q.qname.matchSuffix("local"):
                reply.header.rcode = getattr(RCODE, "NXDOMAIN")
                return reply

            # Transmit.
            sock.sendto(request.pack(), ("224.0.0.251", 5353))

            # Handle incoming responses until we find ours, or time out.
            wait_until = time.time() + self.timeout
            timer = Timer(self.timeout, sock.close)
            while wait_until >= time.time():
                buf = sock.recv(16384)

                response = DNSRecord.parse(buf)
                if (response.header.aa == 1) and (response.header.a > 0):
                    # Check for a valid response to our request.
                    success = False
                    for rr in response.rr:
                        if request.q.qname == rr.rname and request.q.qtype == rr.rtype:
                            success = True
                            timer.cancel()
                            rr.rclass = 1
                            reply.add_answer(rr)

                    if success:
                        break

            if len(reply.rr) == 0:
                reply.header.rcode = getattr(RCODE, "NXDOMAIN")

            return reply


if __name__ == "__main__":
    import argparse
    import sys
    import time

    p = argparse.ArgumentParser(description="DNS Proxy")
    p.add_argument("--port", "-p", type=int, default=5053,
                   metavar="<port>",
                   help="Local proxy port (default:5053)")
    p.add_argument("--address", "-a", default="",
                   metavar="<address>",
                   help="Local proxy listen address (default:all)")
    p.add_argument("--log", default="request,reply,truncated,error",
                   help="Log hooks to enable (default: +request,+reply,+truncated,+error,-recv,-send,-data)")
    p.add_argument("--log-prefix", action="store_true", default=False,
                   help="Log prefix (timestamp/handler/resolver) (default: False)")
    args = p.parse_args()

    print(f"Starting Proxy Resolver ({args.address or '*'}:{args.port} -> mDNS) [UDP]")

    udp_server = DNSServer(resolver=MdnsResolver(),
                           port=args.port,
                           address=args.address,
                           logger=DNSLogger(args.log, prefix=args.log_prefix))
    udp_server.start_thread()

    try:
        while udp_server.isAlive():
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    except:
        sys.stderr.flush()
        sys.stdout.flush()
        pass
    finally:
        if udp_server.isAlive():
            udp_server.stop()
