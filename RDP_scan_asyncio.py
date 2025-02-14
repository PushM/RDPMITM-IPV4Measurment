#!/usr/bin/env python3

import asyncio

import sys
import select

import os
import json
import struct
import binascii
import argparse
import ipaddress
import csv
import time

import ssl
import enum

from datetime import datetime
from RDP_structs import *
from RDP_consts import *

PACKET_NEGO = build_x224_conn_req()
PACKET_NEGO_CRED_SSP = build_x224_conn_req(protocols=PROTOCOL_HYBRID)
PACKET_NEGO_NOSSL = build_x224_conn_req(protocols=0) # Standard RDP security
PACKET_NEGO_DOWNGRADETEST =  build_x224_conn_req(protocols=PROTOCOL_DOWNGRADE)
PACKET_CONN = build_mcs_initial()
PACKET_CONN_RDPSEC = bytes.fromhex("0300019b02f0807f6582018f0401010401010101ff301a020122020102020100020101020100020101020300ffff0201023019020101020101020101020101020100020101020204200201023020020300ffff020300fc17020300ffff020101020100020101020300ffff02010204820129000500147c00018120000800100001c00044756361811201c0ea000c0008002003580201ca03aa00000000bb470000660066002d0075006e006900000000000000000000000000000000000000000004000000000000000c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ca0100000000001000070021040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000004c00c000d0000000000000002c00c00130000000000000006c00800000000000ac0080000000000")
PACKET_CONN_CRED_SSP = bytes.fromhex("3037a003020106a130302e302ca02a04284e544c4d5353500001000000b78208e2000000000000000000000000000000000a00614a0000000f")

class PeriodicBoundedSemaphore(asyncio.BoundedSemaphore):
    def __init__(self, conn_per_sec, loop):
        super().__init__(conn_per_sec)
        self.loop = loop
        self.refresh = loop.call_later(1, self._refresh)

    def _refresh(self):
        for _ in range(self._bound_value - self._value):
            self.release()
        self.refresh = self.loop.call_later(1, self._refresh)

class RDPProtocolException(Exception):
    pass

class SSLProtocol(asyncio.Protocol):
    def __init__(self, inner, loop, timeout):
        self.inner = inner
        self.timeout_time = timeout
        self.loop = loop
        self.inbuf_raw = b""
        self.inbuf_ssl = b""
        self.tcpconnnect_endtime = None
        self.x224_rttTime = None
        self.mcsntlm_rttTime = None

    def _timeout(self):
        self.inner.timeout()
    
    def connection_made(self, transport):
        self.tcpconnnect_endtime = time.time()
        self.transport = transport
        self.timeout_handle = self.loop.call_later(self.timeout_time, self._timeout)

        self.ssl_in = ssl.MemoryBIO()
        self.ssl_out = ssl.MemoryBIO()
        self.ssl_enabled = False
        self.ssl_handshake_done = False
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.VerifyMode.CERT_NONE
        # ssl
        self.ssl = ssl_ctx.wrap_bio(self.ssl_in, self.ssl_out)

        self.inner.connection_made(self)#外层协议传给内层协议，RDPProtocol的transport就是SSLProtocol

    def start_tls(self):
        if self.ssl_enabled:
            raise Exception("TLS Handshake already performed or running!")
        self.try_ssl_handshake()
        self.ssl_enabled = True
    
    def try_ssl_handshake(self):
        try:
            self.ssl.do_handshake() #握手
            self.ssl_handshake_done = True
            self.inner.tls_started()
        except ssl.SSLWantReadError:
            pass
        data = self.ssl_out.read()
        self.transport.write(data)

    def write(self, data):
        if self.ssl_enabled:
            self.ssl.write(data)
            enc_data = self.ssl_out.read()
            try:
                self.transport.write(enc_data)
            except ssl.SSLWantReadError:
                pass
        else:
            
            self.transport.write(data)

    def data_received(self, data):
        if self.inner.state == 0:
            self.x224_rttTime = time.time() - self.inner.x224_startTime
        if self.inner.state > 0 and self.ssl_handshake_done:
            self.mcsntlm_rttTime = time.time() - self.inner.mcsntlm_startTime

        self.timeout_handle.cancel()
        self.timeout_handle = self.loop.call_later(self.timeout_time, self._timeout) # restart the timeout

        self.inbuf_raw += data
        if self.ssl_enabled:
            self.ssl_in.write(data)
            if self.ssl_handshake_done:
                try:
                    dec = self.ssl.read()
                    self.inbuf_ssl += dec  #这是解密后的吧
                    self.inner.data_received(dec)
                except ssl.SSLWantReadError:
                    pass
            else:
                self.try_ssl_handshake()
        else:
            self.inner.data_received(data)

    def close(self):
        self.transport.close()

    def connection_lost(self, exc):
        self.timeout_handle.cancel()
        self.inner.connection_lost(exc)
        
    def eof_received(self):
        self.inner.eof_received()

class RDPConnection(asyncio.Protocol):
    def __init__(self, on_con_close, loop, ip, conntype):
        self.on_con_close = on_con_close
        self.loop = loop
        self.state = 0
        self.data = {}
        self.error = None
        self.ssl_data = dict()
        self.eof = False
        self.is_timeout = False
        self.ip = ip
        self.conntype = conntype
        self.buffer = b""
        self.transport = None
        self.x224_startTime = None
        self.mcsntlm_startTime = None
    
    def timeout(self):
        self.is_timeout = True
        if self.transport is not None:
            self.transport.close()

    def connection_made(self, transport):
        self.transport = transport

        self.x224_startTime = time.time()

        if self.conntype == PROTOCOL_HYBRID:
            transport.write(PACKET_NEGO_CRED_SSP)
        elif self.conntype == PROTOCOL_RDP:
            transport.write(PACKET_NEGO_NOSSL)
        elif self.conntype == PROTOCOL_SSL:
            transport.write(PACKET_NEGO)
        else :
            transport.write(PACKET_NEGO_DOWNGRADETEST)

    def tls_started(self):

        self.mcsntlm_startTime = time.time()

        if self.conntype == PROTOCOL_SSL :
            self.transport.write(PACKET_CONN)
        elif self.conntype == PROTOCOL_HYBRID :
            self.transport.write(PACKET_CONN_CRED_SSP)
            
        self.data["tls_cipher"] = self.transport.ssl.cipher()
        self.data["tls_certificate"] = self.transport.ssl.getpeercert(binary_form=True).hex()

    def data_received(self, data):
        self.buffer += data
        if len(self.buffer) > 4: # length information received?
            data_len = struct.unpack(">H", self.buffer[2:4])[0] # check header for length and compare with received length
            if len(self.buffer) >= data_len:
                self.buffer = self.buffer[data_len:] # TPKT done, receive next
                if self.state == 0: # self.state = 0表示处于x224协商 self.state = 1 是tls建立后的第一次
                    self.state += 1
                    if self.conntype == PROTOCOL_HYBRID or self.conntype == PROTOCOL_SSL:#credssp和ssl都发mcsinit
                        self.transport.start_tls()
                    elif self.conntype == PROTOCOL_RDP:
                        self.mcsntlm_startTime = time.time()#rdpsec的rtt也记录一下吧
                        self.transport.write(PACKET_CONN_RDPSEC)
                    else : # PROTOCOL_downgradtest
                        self.transport.close()

                
                else:
                    self.transport.close()

    def eof_received(self):
        self.eof = True
        
    def connection_lost(self, exc):
        print(f"{self.ip} {self.conntype}: ", end="")
        if exc is None:
            if self.eof:
                self.data["exception"] = 1
                print("Connection closed by remote host.")
            elif self.is_timeout:
                self.data["exception"] = 2
                print("Connection timed out.")
            else:
                print("Connection ended successfully.")
        elif isinstance(exc, ConnectionResetError):
            self.data["exception"] = 3
            print("Connection reset by remote host.")
        elif isinstance(exc, ssl.SSLError):
            self.data["exception"] = 5
            self.data["ssl_error_msg"] = repr(exc)
            print("SSLError occurred")
        else:
            self.data["exception"] = 4
            print(exc)
            print("Encountered unknown exception.")
        self.on_con_close.set_result(True)

async def handle_connection(loop, ip, timeout, sem, response_log, rdp_protocol):
    con_close = loop.create_future()
    on_tls = loop.create_future()
    await sem.acquire()
    try:
        tcpconnect_starttime = time.time()
        transport, protocol = await asyncio.wait_for(loop.create_connection(lambda: SSLProtocol(RDPConnection(con_close, loop, ip, rdp_protocol), loop, timeout), ip, args.port), timeout=timeout)
        #这句话不懂：loop.create_connection
        #loop.create_connection()：通常接受protocol_factory参数，该参数用于为接受的连接创建Protocol对象，由Transport对象表示。 这些方法通常返回(传输，协议)元组。
    except asyncio.exceptions.TimeoutError:
        print(f"{ip} {rdp_protocol}: Connect timed out")
        return
    except ConnectionRefusedError as e:
        print(f"{ip} {rdp_protocol}: Connect refused")
        return
    except OSError as e:
        print(f"{ip} {rdp_protocol}: {e}")
        return
    await con_close

    connection_rttTime = protocol.tcpconnnect_endtime - tcpconnect_starttime
    fields = []
    if rdp_protocol == PROTOCOL_DOWNGRADE:
        fields = [
            protocol.inner.ip,
            f"{rdp_protocol}",
            json.dumps({"connection":connection_rttTime,"x224":protocol.x224_rttTime}),
            #protocol.inbuf_raw.hex(),#未加密和加密后的消息,服务端选择1还是2
        ]
    else:
        fields = [
            protocol.inner.ip,
            f"{rdp_protocol}",
            json.dumps({"connection":connection_rttTime,"x224":protocol.x224_rttTime,"mcsntlm":protocol.mcsntlm_rttTime}),
            protocol.inbuf_raw.hex(),#未加密和加密后的消息
            protocol.inbuf_ssl.hex(),#ssl加密后的消息，应该只有mode=1时才会有，mode=2时加入了ntlm，应该ssl建立不了就报错了？
            json.dumps(protocol.inner.data)#包含cipher、certification、exception
        ]#之后就是分析模块
    response_log.writerow(fields)
    return

async def main(args):
    loop = asyncio.get_running_loop()
    #loop.create_connection
    sem = PeriodicBoundedSemaphore(args.max_cps, loop)
    stdin_closed = False

    ips_buffered = []
    connections = set()
    finished = 0
    with open(os.path.join(results_dir, "test.csv"), "a") as response_log_f:
        response_log = csv.writer(response_log_f)
        while True:
            if finished % args.progress == 0:
                sys.stderr.write("Finished: {}\r".format(finished))
            #一次create max_connections 个connection后再执行
            while len(connections) < args.max_connections: # create as many concurrent connections as possible
                ready = select.select([sys.stdin], [], [], 0.0)[0]#zmap 给程序输入
                if not ready: # no input available on stdin
                    if not connections: # nothing to do, only waiting for input
                        ready = select.select([sys.stdin], [], [])[0]
                    else: # no input in time
                        break

                ip = ready[0].readline().strip()#zmap扫描到的开启3389端口的主机
                # ip = '18.143.159.103'
                if not ip: # stdin is closed
                    if not connections:
                        return # stdin is closed, no connections remaining, we are done
                    else:
                        break # stdin is closed, wait for remaining connections

                try:
                    check = ipaddress.ip_address(ip)
                    if check.is_global or not args.global_check: # add a check for any subnet here
                        # connections.add(asyncio.create_task(handle_connection(loop, ip, args.timeout, sem, response_log, PROTOCOL_DOWNGRADE))) # RPD Standard Security without TLS
                        # connections.add(asyncio.create_task(handle_connection(loop, ip, args.timeout, sem, response_log, PROTOCOL_RDP))) # RPD Standard Security without TLS
                       
                        connections.add(asyncio.create_task(handle_connection(loop, ip, args.timeout, sem, response_log, PROTOCOL_SSL))) # Standard packet
                        connections.add(asyncio.create_task(handle_connection(loop, ip, args.timeout, sem, response_log, PROTOCOL_HYBRID))) # CredSSP enabled
                        connections.add(asyncio.create_task(handle_connection(loop, ip, args.timeout, sem, response_log, PROTOCOL_DOWNGRADE)))
                        connections.add(asyncio.create_task(handle_connection(loop, ip, args.timeout, sem, response_log, PROTOCOL_DOWNGRADE)))
                        connections.add(asyncio.create_task(handle_connection(loop, ip, args.timeout, sem, response_log, PROTOCOL_DOWNGRADE)))
                        connections.add(asyncio.create_task(handle_connection(loop, ip, args.timeout, sem, response_log, PROTOCOL_DOWNGRADE)))
                        connections.add(asyncio.create_task(handle_connection(loop, ip, args.timeout, sem, response_log, PROTOCOL_DOWNGRADE)))
                        connections.add(asyncio.create_task(handle_connection(loop, ip, args.timeout, sem, response_log, PROTOCOL_DOWNGRADE)))
                        connections.add(asyncio.create_task(handle_connection(loop, ip, args.timeout, sem, response_log, PROTOCOL_DOWNGRADE)))
                        connections.add(asyncio.create_task(handle_connection(loop, ip, args.timeout, sem, response_log, PROTOCOL_DOWNGRADE)))
                        
                except ValueError:
                    pass

                    #如果设置了timeout值，则意味着此处最多等待的秒，完成的协程返回值写入到done中，未完成则写到pending中。done, pending = await asyncio.wait(task_list, timeout=None)

            _, connections = await asyncio.wait(connections, return_when=asyncio.FIRST_COMPLETED) # wait for first connection to finish
            # return_when=asyncio.FIRST_COMPLETED 当第一个结果返回“幕后”时，应该终止所有剩余的任务
            #第一个连接搞完就继续了？是因为更好地并行？因为zmap给下一个max_connections个ip还有一定时间，这段时间足够处理完这些connections了？
            finished += 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-connections", type=int, dest="max_connections", default=1000)
    parser.add_argument("--timeout", type=float, dest="timeout", default=10)
    parser.add_argument("--port", dest="port", default=3389)
    parser.add_argument("--max-cps", type=int, dest="max_cps", default=100)
    parser.add_argument("--progress", type=int, dest="progress", default=500)
    parser.add_argument("--output", type=str)
    parser.add_argument("--no-global-check", action="store_false", dest="global_check", default=True)
    args = parser.parse_args()
    
    start = datetime.now()
    now = start.strftime("%y_%m_%d_%H_%M_%S")
    if args.output:
        results_dir = os.path.join(args.output, "scans_" + now)
    else:
        results_dir = "scans_" + now

    try:
        import git
        repo = git.Repo(os.getcwd())
        head = str(repo.commit("HEAD"))[:7]
        clean = "clean" if not (repo.index.diff(None) or repo.untracked_files) else "dirty"
        results_dir += "_{}_{}".format(head, clean)
        print("# {} commit {} {}".format(now, head, clean))
    except ImportError:
        print("# {} (git status unknown)".format(now))
        pass

    os.mkdir(results_dir)
    keylogpath = os.path.join(results_dir, "sslkeys.log")
    os.environ["SSLKEYLOGFILE"] = keylogpath
    
    asyncio.run(main(args))

    end = datetime.now()
    print("Elapsed time: {}".format(str(end - start)))
