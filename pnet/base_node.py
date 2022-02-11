"""
PNET - Local p2p protocol

(c) Dax Harris 2021
MIT License
"""

import rsa
import rsa.pkcs1
from cryptography.fernet import Fernet, InvalidToken
import base64
import pickle
import random
import typing
import socket
import socketserver
import time
from threading import Thread
from logging import warning, exception
import re
from .crypt import Crypt
        

class Node:
    def __init__(
        self,
        name: str,
        network_id: str,
        onmessage = print,
        crypt: Crypt = None,
        network_key: bytes | None = None,
        server_port: int = 3333,
        advertise_port: int = 3334,
        advertise_interval: float | int = 2.5,
        bind_ip: str = "localhost"
    ):
        """
        P2P Node
        :name Unique name within network - Should not use | or @
        :network_id ID of network to listen to - Should not use |
        :onmessage Callback to run when a message is recieved. Takes one argument
        :crypt Crypt object or None. If None, auto-generates object.
        :network_key Fernet encryption key of network. Leaving as None will disable network-level encryption
        :server_port Port to listen on
        :advertise_port Port to advertise on. Should be shared across a network
        :broadcast_interval Time between UDP advertisements
        :bind_ip IP to bind to.
        """
        
        self.name = name
        self.network_id = network_id
        if network_key:
            self.fernet = Fernet(network_key)
            self.net_encrypted = True
        else:
            self.net_encrypted = False
            self.fernet = None
        
        self.server_port = server_port
        self.advertise_port = advertise_port
        self.peers = {}
        self.ad_interval = advertise_interval
        self.running = False
        self.bind_ip = bind_ip
        self.callback = onmessage
        if crypt:
            self.crypt = crypt
        else:
            self.crypt = Crypt()
        self.pk = base64.urlsafe_b64encode(self.crypt.public.save_pkcs1()).decode("utf-8")
        self.sserver = None
    
    def _advertiser(self):
        advertiser = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        advertiser.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        advertiser.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        advertiser.bind(("", 0))
        advertiser.settimeout(0.001)
        msgcontent = f"{self.name}@{socket.gethostbyname(socket.gethostname()) if self.bind_ip in ['', '0.0.0.0'] else self.bind_ip}:{self.server_port}"
        if self.net_encrypted:
            msgcontent = base64.urlsafe_b64encode(self.fernet.encrypt(msgcontent.encode("utf-8"))).decode("utf-8")
        broadcast_message = f"{self.network_id}|adv|{msgcontent}|{self.pk}|END\n".encode("utf-8")
        while self.running:
            advertiser.sendto(broadcast_message, ("<broadcast>", self.advertise_port))
            time.sleep(self.ad_interval)
        advertiser.close()
    
    def _proc_udp(self, data):
        data = data.strip()
        parts = data.decode("utf-8").split("|")
        if "brd" in parts:
            print(len(parts))
        if len(parts) != 5:
            return
        if parts[4] != "END":
            return
        if parts[0] != self.network_id:
            return

        _, ptype, content, pk, _ = parts

        # Check packet type
        if not ptype == "adv":
            return
        
        # Attempt to decrypt packet on network level
        if self.net_encrypted:
            try:
                content: bytes = self.fernet.decrypt(base64.urlsafe_b64decode(content.encode("utf-8")))
            except InvalidToken:
                return
        else:
            content: bytes = content.encode("utf-8")
        
        content = content.decode("utf-8")
        if "@" in content and ":" in content:
            name, addr = content.split("@")
            if name == self.name:
                return
            if not re.search("^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9]):[0-9]{1,5}$", addr) and not addr.startswith("localhost:"):
                return
            
            self.peers[name] = {
                "name": name,
                "addr": addr,
                "public_key": rsa.PublicKey.load_pkcs1(base64.urlsafe_b64decode(pk.encode("utf-8")))
            }

    def discover(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #create UDP socket
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', self.advertise_port))
        while self.running:
            datas = b""
            while True:
                _data, _ = s.recvfrom(1024)
                if not _data: break
                datas += _data
                if b"END\n" in datas:
                    packs = datas.split(b"\n")
                    datas = packs.pop()
                    [Thread(target=self._proc_udp, daemon=True, args=[i,]).start() for i in packs]
        s.close()
            
    
    def create_handler(self, *args):
        return NodeHandler(self, *args)
    
    def serve(self):
        """
        Runs node server
        """
        print("Starting advertiser")
        self.running = True
        ad_thread = Thread(target=self._advertiser, name=f"{self.name}-ad", daemon=True)
        ad_thread.start()

        print("Starting server")
        self.sserver = socketserver.ThreadingTCPServer((self.bind_ip, self.server_port), self.create_handler)
        srv_thread = Thread(target=self.sserver.serve_forever, name=f"{self.name}-srv", daemon=True, kwargs={"poll_interval" : 0.25})
        srv_thread.start()

        print("Starting listener")
        ls_thread = Thread(target=self.discover, name=f"{self.name}-ls", daemon=True)
        ls_thread.start()
    
    def shutdown(self):
        if self.sserver != None:
            self.running = False
            self.sserver.shutdown()
    
    def send(self, target: str, message: typing.Any):
        try:
            if not target in self.peers.keys():
                raise KeyError(f"Peer {target} not found")
            
            data = self.crypt.encrypt(message, self.peers[target]["public_key"])
            if self.net_encrypted:
                data = base64.urlsafe_b64encode(self.fernet.encrypt(data))
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                # Connect to server and send data
                sock.connect((self.peers[target]["addr"].split(":")[0], int(self.peers[target]["addr"].split(":")[1])))
                sock.sendall(f"{self.network_id}|msg|{data.decode('utf-8')}|{self.pk}|END\n".encode("utf-8"))

                # Receive data from the server and shut down
                received = b""
                nr = sock.recv(1024).strip()
                while nr:
                    received += nr
                    nr = sock.recv(1024).strip()
                received += nr
            
            parts = received.decode("utf-8").split("|")
            if len(parts) != 5:
                warning(f"Malformed packet {parts} - Too many/few sections")
                return
            if parts[4] != "END":
                warning(f"Malformed packet {parts} - Packet incomplete")
                return
            if parts[0] != self.network_id:
                warning(f"Recieved response from non-network node in network {parts[0]}")
                return

            _, ptype, content, _, _ = parts

            # Check packet type
            if ptype != "rsp":
                raise ValueError(f"Packet is not a response packet: {ptype}")
            
            # Attempt to decrypt packet on network level
            if self.net_encrypted:
                try:
                    content: bytes = self.fernet.decrypt(base64.urlsafe_b64decode(content.encode("utf-8")))
                except InvalidToken:
                    raise ValueError("Bad net encryption")
            else:
                content: bytes = content.encode("utf-8")
            
            try:
                content = self.crypt.decrypt(content)
            except rsa.pkcs1.DecryptionError:
                raise ValueError("Bad node encryption")
            return content
        except:
            exception()
            return "$error"
            

class NodeHandler(socketserver.StreamRequestHandler):
    def __init__(self, node: Node, *args):
        self.node: Node = node
        super().__init__(*args)

    def handle(self) -> None:
        data: bytes = self.rfile.readline().strip()
        
        # Check packet
        parts = data.decode("utf-8").split("|")
        if len(parts) != 5:
            warning(f"Malformed packet {parts} - Too many/few sections")
            self.wfile.write(f"{self.node.network_id}|err|ERR_SECTION_COUNT||END\n".encode("utf-8"))
            return
        if parts[4] != "END":
            warning(f"Malformed packet {parts} - Packet incomplete")
            self.wfile.write(f"{self.node.network_id}|err|ERR_PACKET_INCOMPLETE||END\n".encode("utf-8"))
            return
        if parts[0] != self.node.network_id:
            self.wfile.write(f"{self.node.network_id}|err|ERR_NETWORK_INCORRECT||END\n".encode("utf-8"))
            return

        _, ptype, content, pk, _ = parts

        # Check packet type
        if not ptype in ["adv", "msg", "brd"]:
            self.wfile.write(f"{self.node.network_id}|err|ERR_PACKET_TYPE||END\n".encode("utf-8"))
            return
        
        # Attempt to decrypt packet on network level
        if self.node.net_encrypted:
            try:
                content: bytes = self.node.fernet.decrypt(base64.urlsafe_b64decode(content.encode("utf-8")))
            except InvalidToken:
                self.wfile.write(f"{self.node.network_id}|err|ERR_NET_DECRYPTION_FAILED||END\n".encode("utf-8"))
                return
        else:
            content: bytes = content.encode("utf-8")
        
        if ptype == "msg":
            # Attempt to decrypt packet on node level
            try:
                content = self.node.crypt.decrypt(content)
            except rsa.pkcs1.DecryptionError:
                self.wfile.write(f"{self.node.network_id}|err|ERR_RSA_DECRYPTION_FAILED|{self.node.pk}|END\n".encode("utf-8"))
                return
            
            result = self.node.callback(content)
            enc_result: bytes = self.node.crypt.encrypt(result, rsa.PublicKey.load_pkcs1(base64.urlsafe_b64decode(pk.encode("utf-8"))))
            if self.node.net_encrypted:
                enc_result = base64.urlsafe_b64encode(self.node.fernet.encrypt(enc_result)).decode("utf-8")
            self.wfile.write(f"{self.node.network_id}|rsp|{enc_result}|{self.node.pk}|END\n".encode("utf-8"))

        
        elif ptype == "adv":
            content = content.decode("utf-8")
            if "@" in content and ":" in content:
                name, addr = content.split("@")
                if not re.search("^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9]):[0-9]{1,5}$", addr):
                    self.wfile.write(f"{self.node.network_id}|err|ERR_BR_INVALID_IP|{self.node.pk}|END\n".encode("utf-8"))
                    return
                
                self.node.peers[name] = {
                    "name": name,
                    "addr": addr,
                    "public_key": rsa.PublicKey.load_pkcs1(base64.urlsafe_b64decode(pk.encode("utf-8")))
                }

                return
            else:
                self.wfile.write(f"{self.node.network_id}|err|ERR_BR_INVALID_FORMAT|{self.node.pk}|END\n".encode("utf-8"))
                return
        else:
            self.node.callback(content)
        

        

        