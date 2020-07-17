#!/usr/bin/env python3
#
# Copyright (c) 2018-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.
#

import aioh2
import asyncio
import dns.message
import priority
import struct
import urllib.parse
import h2.events
import random
from bidict import bidict

from dohproxy import constants, utils

DOHSERVERS = bidict({'dns.google': 'Google',
                     'cloudflare-dns.com': 'CF',
                     'dns.quad9.net': 'Quad9'})


class StubServerProtocol:

    def __init__(self, args, logger=None, client_store=None):
        self.logger = logger
        self.args = args
        self._lock = asyncio.Lock()
        if logger is None:
            self.logger = utils.configure_logger('StubServerProtocol')

        # The client is wrapped in a mutable dictionary, so it may be shared
        # across multiple contexts if passed from higher in the chain.
        if client_store is None:
            self.client_store = {'client': None}
        else:
            self.client_store = client_store

    async def get_client(self, force_new=False):
        if force_new:
            self.client_store['client'] = None
        if self.client_store['client'] is not None:
            if self.client_store['client']._conn is not None:
                return self.client_store['client']

        # Open client connection
        self.logger.debug('Opening connection to {}'.format(self.args.domain))
        sslctx = utils.create_custom_ssl_context(
            insecure=self.args.insecure,
            cafile=self.args.cafile
        )
        remote_addr = self.args.remote_address \
            if self.args.remote_address else self.args.domain
        client = await aioh2.open_connection(
            remote_addr,
            self.args.port,
            functional_timeout=0.1,
            ssl=sslctx,
            server_hostname=self.args.domain)
        if hasattr(h2.events, "PingReceived"):
            # Need the hasattr here because some older versions of h2 may not
            # have the PingReceived event
            client._event_handlers[h2.events.PingReceived] = lambda _: None
        rtt = await client.wait_functional()
        if rtt:
            self.logger.debug('Round-trip time: %.1fms' % (rtt * 1000))

        self.client_store['client'] = client
        return client

    async def get_ddns_client(self, force_new=False):
        # if 'client' in self.client_store:
        #    self.client_store.pop('client')
        domain_list = self.args.domain.split(',')
        for domain in domain_list:
            if domain not in DOHSERVERS:
                DOHSERVERS[domain] = None
                # DOHDOMAINS[domain] = None

        if force_new:
            for domain in domain_list:
                self.client_store[DOHSERVERS[domain]] = None
        # self.logger.debug('DOMAINLIST',domain_list)
        # Check if ALL domains have an open connection
        for domain in domain_list:
            if DOHSERVERS[domain] not in self.client_store:
                self.client_store[DOHSERVERS[domain]] = None
            if self.client_store[DOHSERVERS[domain]] is not None:
                if self.client_store[DOHSERVERS[domain]]._conn is not None:
                    if domain == domain_list[-1]:
                        return self.client_store

            # Open client connection
            self.logger.debug('Opening connection to {}'.format(domain))
            sslctx = utils.create_custom_ssl_context(
                insecure=self.args.insecure,
                cafile=self.args.cafile
            )
            remote_addr = self.args.remote_address \
                if self.args.remote_address else domain
            client = await aioh2.open_connection(
                remote_addr,
                self.args.port,
                functional_timeout=0.1,
                ssl=sslctx,
                server_hostname=domain)
            if hasattr(h2.events, "PingReceived"):
                # Need the hasattr here because some older versions of h2 may not
                # have the PingReceived event
                client._event_handlers[h2.events.PingReceived] = lambda _: None
            rtt = await client.wait_functional()
            if rtt:
                self.logger.debug('Round-trip time: %.1fms' % (rtt * 1000))

            self.client_store[DOHSERVERS[domain]] = client
            # if domain == domain_list[-1]:
        return self.client_store

    def connection_made(self, transport):
        pass

    def connection_lost(self, exc):
        pass

    def on_answer(self, addr, msg):
        pass

    def on_message_received(self, stream_id, msg):
        """
        Takes a wired format message returned from a DOH server and convert it
        to a python dns message.
        """
        return dns.message.from_wire(msg)

    async def on_start_request(self, client, headers, end_stream):
        return await client.start_request(headers, end_stream=end_stream)

    async def on_send_data(self, client, stream_id, body):
        return await client.send_data(stream_id, body, end_stream=True)

    def on_recv_response(self, stream_id, headers):
        self.logger.debug('Response headers: {}'.format(headers))

    def _make_get_path(self, content):
        params = utils.build_query_params(content)
        self.logger.debug('Query parameters: {}'.format(params))
        params_str = urllib.parse.urlencode(params)
        if self.args.debug:
            url = utils.make_url(self.args.domain, self.args.uri)
            self.logger.debug('Sending {}?{}'.format(url, params_str))
        return self.args.uri + '?' + params_str

    def choose_resolver(self):
        res = random.choice(list(self.client_store))
        self.logger.info('CHOSE {} from {}'.format(
            res, self.client_store.keys()))
        return [self.client_store[res], DOHSERVERS.inverse[res]]

    async def make_request(self, addr, dnsq):
        # FIXME: maybe aioh2 should allow registering to connection_lost event
        # so we can find out when the connection get disconnected.

        if not self.args.ddns:
            with await self._lock:
                client = await self.get_client()
            resolver_domain = self.args.domain
        else:
            with await self._lock:
                client, resolver_domain = self.choose_resolver()

        headers = {'Accept': constants.DOH_MEDIA_TYPE}
        path = self.args.uri
        qid = dnsq.id
        dnsq.id = 0
        body = b''

        headers = [
            (':authority', resolver_domain),
            (':method', self.args.post and 'POST' or 'GET'),
            (':scheme', 'https'),
        ]
        if self.args.post:
            headers.append(('content-type', constants.DOH_MEDIA_TYPE))
            body = dnsq.to_wire()
        else:
            path = self._make_get_path(dnsq.to_wire())

        headers.insert(0, (':path', path))
        headers.extend([
            ('content-length', str(len(body))),
        ])
        # Start request with headers
        # FIXME: Find a better way to close old streams. See GH#11
        try:
            stream_id = await self.on_start_request(client, headers, not body)
        except priority.priority.TooManyStreamsError:
            if not self.args.ddns:
                client = await self.get_client(force_new=True)
            else:
                client, _ = await self.get_ddns_client(force_new=True)
            stream_id = await self.on_start_request(client, headers, not body)
        self.logger.debug(
            'Stream ID: {} / Total streams: {}'.format(
                stream_id, len(client._streams)
            )
        )
        # Send my name "world" as whole request body
        if body:
            await self.on_send_data(client, stream_id, body)

        # Receive response headers
        headers = await client.recv_response(stream_id)
        self.on_recv_response(stream_id, headers)
        # FIXME handled error with servfail

        # Read all response body
        resp = await client.read_stream(stream_id, -1)
        dnsr = self.on_message_received(stream_id, resp)

        dnsr.id = qid
        self.on_answer(addr, dnsr.to_wire())

        # Read response trailers
        trailers = await client.recv_trailers(stream_id)
        self.logger.debug('Response trailers: {}'.format(trailers))


class StubServerProtocolUDP(StubServerProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        dnsq = dns.message.from_wire(data)
        asyncio.ensure_future(self.make_request(addr, dnsq))

    def on_answer(self, addr, msg):
        self.transport.sendto(msg, addr)


class StubServerProtocolTCP(StubServerProtocol):
    def connection_made(self, transport):
        self.transport = transport
        self.addr = transport.get_extra_info('peername')
        self.buffer = b''

    def data_received(self, data):
        self.buffer = utils.handle_dns_tcp_data(
            self.buffer + data, self.receive_helper
        )

    def receive_helper(self, dnsq):
        asyncio.ensure_future(self.make_request(self.addr, dnsq))

    def on_answer(self, addr, msg):
        self.transport.write(struct.pack('!H', len(msg)) + msg)

    def eof_received(self):
        self.transport.close()
