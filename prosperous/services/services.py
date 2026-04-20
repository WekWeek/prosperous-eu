#!/usr/bin/env python3
'''
Services for ps5:
 * DNS redirector (dnschef)
 * HTTP server for webkit exploit (unused for gamehax)
 * TCP server for simple send/recv files
'''

import http.server
import socket
import socketserver
import os
import time
import threading
import logging
import argparse
import struct
import ssl


def run_daemon(server):
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    return server_thread


def run_dns_server(iface, port):
    import dnschef
    return run_daemon(dnschef.start_server(iface, port))


class HttpHandler(http.server.SimpleHTTPRequestHandler):

    def send_nocache(self):
        self.send_response(200)
        self.send_header(
            'Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        if self.path.endswith('.js'):
            self.send_header('Content-Type', 'application/x-javascript')

    def end_headers(self):
        self.send_nocache()
        http.server.SimpleHTTPRequestHandler.end_headers(self)

    def do_GET(self):
        manual_base = '/document/en/ps5'
        if self.path.startswith(manual_base):
            self.path = self.path.replace(manual_base, '')

        http.server.SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        self.end_headers()

        if self.path.startswith('/networktest'):
            return

        self.payload = self.rfile.read(int(self.headers.get('content-length')))

        logging.error(f'POST {self.path}')

    def log_message(self, fmt, *args):
        logging.debug(
            f'{self.address_string()} - - [{self.log_date_time_string()}] {fmt % args}')


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):

    def finish_request(self, request, client_address):
        request.settimeout(30)
        http.server.HTTPServer.finish_request(self, request, client_address)


def run_http_server(iface, port):
    '''
    HTTP server:
     * Routes requests to the proper files based on FW version
     * Handles logging via POST (and dumps, before exploits are
       fully working. Afterwards, prefer TCP dumping)
    '''
    server = ThreadedHTTPServer((iface, port), HttpHandler)
    if port == 443:
        server.socket = ssl.wrap_socket(server.socket, keyfile='key.pem',
                                        certfile='cert.pem', server_side=True)
    return run_daemon(server)


class TCPHandler(socketserver.BaseRequestHandler):

    CMD_UPLOAD_FILE = 0
    CMD_DOWNLOAD_FILE = 1
    CMD_LOG_TEXT = 2

    def _recvall(self, size):
        b = b''
        cur_len = 0
        last_recv = time.time()
        timeout = self.request.gettimeout()
        while cur_len != size:
            b += self.request.recv(size - len(b), 0)
            if cur_len != len(b):
                cur_len = len(b)
                last_recv = time.time()
            elif time.time() - last_recv >= timeout:
                raise TimeoutError('wanted %x got %x' % (size, len(b)))
        return b

    def read_u32(self):
        return struct.unpack('<I', self._recvall(4))[0]

    def read_sized(self):
        size = self.read_u32()
        return self._recvall(size)

    def write_sized(self, buf):
        self.request.sendall(struct.pack('<I', len(buf)) + buf)

    def read_string(self):
        return str(self.read_sized(), 'ascii')

    def xlate_path(self, path):
        if path.startswith('/'):
            path = path[1:]
        path = os.path.join('./xfer', path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return path

    def handle(self):
        self.request.settimeout(1)
        cmd = self.read_u32()
        if cmd == self.CMD_UPLOAD_FILE:
            path = self.xlate_path(self.read_string())
            buf = self.read_sized()
            with open(path, 'wb') as f:
                logging.info(f'writing {path}')
                f.write(buf)
        elif cmd == self.CMD_DOWNLOAD_FILE:
            path = self.xlate_path(self.read_string())
            with open(path, 'rb') as f:
                logging.info(f'reading {path}')
                self.write_sized(f.read())
        elif cmd == self.CMD_LOG_TEXT:
            print(self.read_string())
        else:
            logging.error(f'unrecognized cmd {cmd:8x}')


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):

    allow_reuse_address = True


def run_tcp_server(iface, port):
    '''
    TCP server:
     * Handles simple protocol to send/recv files (payloads, dumps, ..)
    '''
    return run_daemon(ThreadedTCPServer((iface, port), TCPHandler))


if __name__ == '__main__':
    parser = argparse.ArgumentParser('PS5 Services')
    parser.add_argument('-l', '--log', dest='log_level',
                        choices=['DEBUG', 'INFO',
                                 'WARNING', 'ERROR', 'CRITICAL'],
                        default='INFO')
    parser.add_argument('-n', '--nodns', dest='use_dns',
                        default=True, action="store_false")
    parser.add_argument('-p', '--http-port', dest='http_port',
                        default=443, type=int)
    parser.add_argument('-t', '--tcp-port', dest='tcp_port',
                        default=6666, type=int)
    parser.add_argument('-d', '--dns-port', dest='dns_port',
                        default=53, type=int)
    parser.add_argument('-b', '--bind-addr', dest='bind_addr',
                        default=None)
    args = parser.parse_args()

    logging.basicConfig(format='%(message)s',
                        level=logging.getLevelName(args.log_level))

    if args.bind_addr is None:
        hostname, aliaslist, ipaddrlist = socket.gethostbyname_ex(
            socket.gethostname())
        if len(ipaddrlist) == 1:
            args.bind_addr = ipaddrlist[0]
        elif len(ipaddrlist) > 1:
            print(f'{hostname} has multiple ips:')
            for i, ip in enumerate(ipaddrlist):
                print(f'{i} {ip}')
            args.bind_addr = ipaddrlist[int(input('iface index to use: '))]

    if args.use_dns:
        run_dns_server(args.bind_addr, args.dns_port)
    run_http_server(args.bind_addr, args.http_port)
    run_tcp_server(args.bind_addr, args.tcp_port)

    logging.info(f'Serving on {args.bind_addr}')

    while True:
        time.sleep(100)
