from .base_node import Node
from .crypt import Crypt, universal_decode, universal_encode

from tempfile import TemporaryFile
from typing import Any
from io import FileIO, BytesIO, IOBase, BufferedRandom
import os, base64, hashlib
import math
import json
from logging import exception


class AdvancedNode(
    Node
):  # Node that implements high-level processes like chunking and multiple target selection
    def __init__(
        self,
        name: str,
        network_id: str,
        crypt: Crypt = None,
        network_key: bytes | None = None,
        server_port: int = 3333,
        advertise_port: int = 3334,
        advertise_interval: float | int = 2.5,
        bind_ip: str = "localhost",
        chunk_size: int = 16384,
        functions: dict = {},
    ):
        if not all(
            [
                i.lower()
                in "1234567890qwertyuiopasdfghjklzxcvbnm!@#$%^&*()[]{}:,<.>/-_+`~"
                for i in name
            ]
        ):
            raise ValueError(
                'All name characters must be in "1234567890qwertyuiopasdfghjklzxcvbnm!@#$%^&*()[]{}:,<.>/-_+`~"'
            )
        super().__init__(
            name,
            network_id,
            self.handle,
            crypt,
            network_key,
            server_port,
            advertise_port,
            advertise_interval,
            bind_ip,
        )
        self.current_chunked = {}
        self.chunk_size = chunk_size
        self.functions = functions

    def register(self, command: str):
        """
        Decorated functions should take 3 arguments: The Node instance, the originator name, and a readable IOStream.
        They should return a readable IOStream or any object. IOStreams will be chunked and returned to the originator that way,
        while other objects will be returned as a raw universal stream
        """

        def register_decorator(func):
            self.functions[command] = func
            return func

        return register_decorator

    def _parse_args(self, args: str):
        return args.split("?")[0], {
            x.split("=")[0]: x.split("=")[1] for x in args.split("?")[1].split("&")
        }

    def _send_chunked(
        self, target: str, command: str, data_or_stream: bytes | FileIO
    ) -> IOBase:
        try:
            if type(data_or_stream) == bytes:
                data_size = len(data_or_stream)
                data_or_stream = BytesIO(data_or_stream)
            else:
                data_or_stream.seek(0, 2)
                data_size = data_or_stream.tell()
                data_or_stream.seek(0)

            stream_id = base64.urlsafe_b64encode(os.urandom(8))

            super().send(
                target,
                f"CHUNKED?pt=initiator&ln={math.ceil(data_size/self.chunk_size)}&id={stream_id}&og={self.name}&fn={command}",
            )
            chunk_index = 0
            shas = []
            while True:
                last_pos = data_or_stream.tell()
                new_data = data_or_stream.read(self.chunk_size)
                if not new_data:
                    break
                new_data = base64.urlsafe_b64encode(new_data)
                sha = hashlib.sha256(new_data).hexdigest()
                new_data = new_data.decode("utf-8").replace("=", "~")
                chunk_result = super().send(
                    target,
                    f"CHUNKED?pt=part&id={stream_id}&in={chunk_index}&dt={new_data}&ck={sha}&og={self.name}",
                )
                if not "?" in chunk_result:
                    raise ValueError("Invalid message")
                cmd, args = self._parse_args(chunk_result)
                if cmd == "RESPONSE" and args["rs"] == "success":
                    chunk_index += 1
                    shas.append(sha[:6])
                    continue
                data_or_stream.seek(last_pos)
            result = super().send(
                target,
                f"CHUNKED?pt=end&og={self.name}&ck={hashlib.sha256(''.join(shas).encode('utf-8')).hexdigest()}&id={stream_id}",
            )
            if not "?" in result:
                raise ValueError("Invalid message")
            cmd, args = self._parse_args(result)
            if cmd == "RESPONSE" and args["rs"] == "success":
                return BytesIO(
                    base64.urlsafe_b64decode(args["dt"].replace("~", "=").encode("utf-8"))
                )
            elif cmd == "CHUNKED_RESPONSE" and args["rs"] == "success":
                chunk = {
                    "num_packets": int(args["ln"]),
                    "originator": args["og"],
                    "data_storage": TemporaryFile(),
                    "id": args["id"],
                }
                c = 0
                shas = []
                while c <= chunk["num_packets"]:
                    chunk_result = super().send(
                        target, f"CHUNKED_REQUEST?pt=part&id={chunk['id']}&in={c}"
                    )
                    cmd, args = self._parse_args(chunk_result)
                    if cmd == "CHUNKED_RESPONSE":
                        if args["pt"] == "part":
                            checksum = hashlib.sha256(
                                args["dt"].replace("~", "=").encode("utf-8")
                            ).hexdigest()
                            if args["ck"] == checksum:
                                chunk["data_storage"].write(
                                    base64.urlsafe_b64decode(
                                        args["dt"].replace("~", "=").encode("utf-8")
                                    )
                                )
                                shas.append(checksum[:6])
                                c += 1
                                continue
                        elif args["pt"] == "end":
                            if (
                                args["ck"]
                                == hashlib.sha256("".join(shas).encode("utf-8")).hexdigest()
                            ):
                                chunk["data_storage"].seek(0)
                                return chunk["data_storage"]
                    raise ValueError(f"Error packet: {cmd}:{args}")
            raise ValueError("Invalid response")
        except:
            exception()
            return "$error"

    def handle(self, content: str):
        cmd, args = self._parse_args(content)
        if cmd == "CHUNKED":
            if args["pt"] == "initiator":
                if not args["fn"] in self.functions.keys():
                    return "ERROR?rs=unknown function"
                self.current_chunked[args["id"]] = {
                    "length": args["ln"],
                    "originator": args["og"],
                    "type": "request",
                    "storage": TemporaryFile(),
                    "hashes": [],
                    "command": args["fn"],
                }
                return "RESPONSE?rs=success"
            elif args["pt"] == "part":
                if args["id"] in self.current_chunked.keys():
                    checksum = hashlib.sha256(
                        args["dt"].replace("~", "=").encode("utf-8")
                    ).hexdigest()
                    if args["ck"] == checksum:
                        self.current_chunked[args["id"]]["hashes"].append(checksum[:6])
                        self.current_chunked[args["id"]]["storage"].write(
                            base64.urlsafe_b64decode(
                                args["dt"].replace("~", "=").encode("utf-8")
                            )
                        )
                        return "RESPONSE?rs=success"
                    else:
                        return "ERROR?rs=checksum error"
                else:
                    return "ERROR?rs=wrong id"
            else:
                if args["id"] in self.current_chunked.keys():
                    checksum = hashlib.sha256(
                        "".join(self.current_chunked[args["id"]]["hashes"]).encode(
                            "utf-8"
                        )
                    ).hexdigest()
                    if args["ck"] == checksum:
                        self.current_chunked[args["id"]]["storage"].seek(0)
                        result = self.functions[
                            self.current_chunked[args["id"]]["command"]
                        ](
                            self,
                            self.current_chunked[args["id"]]["originator"],
                            self.current_chunked[args["id"]]["storage"],
                        )
                    else:
                        return "ERROR?rs=checksum error"
                else:
                    return "ERROR?rs=wrong id"
        elif cmd == "CHUNKED_REQUEST":
            if args["id"] in self.current_chunked.keys():
                data = self.current_chunked[args["id"]]["storage"].read(self.chunk_size)
                if data:
                    data = base64.urlsafe_b64encode(data)
                    checksum = hashlib.sha256(data).hexdigest()
                    self.current_chunked[args["id"]]["hashes"].append(checksum[:6])
                    return f"CHUNKED_RESPONSE?pt=part&dt={data.decode('utf-8').replace('=', '~')}&ck={checksum}"
                else:
                    ret = f"CHUNKED_RESPONSE?pt=end&ck={hashlib.sha256(''.join(self.current_chunked[args['id']]['hashes']).encode('utf-8')).hexdigest()}"
                    del self.current_chunked[args["id"]]
                    return ret
            else:
                return "ERROR?rs=wrong id"
        elif cmd == "RAW":
            result = self.functions[args["fn"]](
                self,
                args["og"],
                BytesIO(
                    base64.urlsafe_b64decode(
                        args["dt"].replace("~", "=").encode("utf-8")
                    )
                ),
            )
        else:
            return "ERROR?rs=unknown command"

        if isinstance(result, IOBase) and result.seekable():
            result.seek(0, 2)
            _size = math.ceil(result.tell() / self.chunk_size)
            result.seek(0)
            stream_id = (
                base64.urlsafe_b64encode(os.urandom(8)).decode("utf-8").strip("=")
            )
            self.current_chunked[stream_id] = {
                "length": _size,
                "originator": self.name,
                "type": "response",
                "storage": result,
                "hashes": [],
            }
            return (
                f"CHUNKED_RESPONSE?rs=success&ln={_size}&og={self.name}&id={stream_id}"
            )
        else:
            return f"RESPONSE?rs=success&dt={universal_encode(result).decode('utf-8').replace('=', '~')}"

    def send(self, target: str | list[str], command: str, data: Any) -> Any:
        # Target selection
        if target == "*":
            targets = list(self.peers.keys())
        elif type(target) == list:
            targets = [t for t in target if t in self.peers.keys()]
        else:
            targets = [target]

        # Data encoding and preparation for chunking
        if isinstance(data, IOBase):
            to_send = data
            encoded = False
        else:
            enc_data = universal_encode(data)
            encoded = True
            if len(enc_data) > self.chunk_size:
                to_send = BytesIO(enc_data)
            else:
                to_send = enc_data

        if isinstance(to_send, IOBase):
            cmds = [command for c in targets]
            datas = [data for d in targets]
            results = map(self._send_chunked, targets, cmds, datas)
        else:
            datas = [
                f"RAW?fn={command}&og={self.name}&dt={enc_data.decode('utf-8').replace('=', '~')}"
                for t in targets
            ]
            results = [
                self._parse_args(i)[1]["dt"].replace("~", "=")
                for i in map(super().send, targets, datas)
            ]

        results = list(results)
        if len(results) == 1:
            return (
                universal_decode(
                    results[0] if isinstance(results[0], bytes) else results[0].read()
                )
                if encoded and results[0] != "$error"
                else results[0]
            )
        else:
            return (
                {
                    targets[i]: universal_decode(
                        results[i]
                        if isinstance(results[i], bytes) or isinstance(results[i], str)
                        else results[i].read()
                    )
                    if encoded and results[i] != "$error"
                    else results[i]
                    for i in range(len(targets))
                }
                if encoded
                else {targets[i]: results[i] for i in range(len(targets))}
            )

class Target:
    def __init__(self, node: AdvancedNode, target: str | list[str]) -> None:
        self.target = target
        self.origin = node
    
    def __getattr__(self, item):
        return CommandFunction(self, item)

class CommandFunction:
    def __init__(self, target: Target, func: str) -> None:
        self.origin = target
        self.function = func
    
    def __call__(self, *args: Any, **kwds: Any) -> Any:
        result = self.origin.origin.send(self.origin.target, "handle", BytesIO(json.dumps({
            "function": self.function,
            "args": args,
            "kwargs": kwds
        }).encode("utf-8")))
        if isinstance(result, BufferedRandom):
            result = json.loads(result.read().decode("utf-8"))
            if result["type"] == "success":
                return result["value"]
            else:
                raise ConnectionError(f"Failed to get result: error {result['description']}")
        else:
            ret = {}
            for k in result.keys():
                r = json.loads(result[k].read().decode("utf-8"))
                if r["type"] == "success":
                    ret[k] = r["value"]
                else:
                    ret[k] = f"Failed to get result: error {r['description']}"
            
            return ret


# Node that implements utility functions for RPC
class CommandNode(AdvancedNode):
    def __init__(
        self,
        name: str,
        network_id: str,
        crypt: Crypt = None,
        network_key: bytes | None = None,
        server_port: int = 3333,
        advertise_port: int = 3334,
        advertise_interval: float | int = 2.5,
        bind_ip: str = "localhost",
        chunk_size: int = 16384,
        functions: dict = {},
    ):
        self.registered_functions = functions
        self.registered_functions["get_peers"] = self._get_peers
        self.registered_functions["get_funcs"] = self._get_funcs
        super().__init__(
            name,
            network_id,
            crypt,
            network_key,
            server_port,
            advertise_port,
            advertise_interval,
            bind_ip,
            chunk_size,
            {"handle": self._handle},
        )
    
    def _handle(self, node: AdvancedNode, originator: str, data: BytesIO):
        try:
            args = json.loads(data.read().decode("utf-8"))
        except json.JSONDecodeError:
            return BytesIO(json.dumps({
                "type": "error",
                "description": "bad json data"
            }).encode("utf-8"))
        if not all([i in args.keys() for i in ["function", "args", "kwargs"]]):
            return BytesIO(json.dumps({
                "type": "error",
                "description": "not all required items (function, args, kwargs) are present"
            }).encode("utf-8"))
        if not args["function"] in self.registered_functions.keys():
            return BytesIO(json.dumps({
                "type": "error",
                "description": "function does not exist on node"
            }).encode("utf-8"))

        result = self.registered_functions[args["function"]](self, originator, *args["args"], **args["kwargs"])
        try:
            return BytesIO(json.dumps({
                "type": "success",
                "value": result
            }).encode("utf-8"))
        except:
            return BytesIO(json.dumps({
                "type": "error",
                "description": "bad return data"
            }).encode("utf-8"))
    
    def _get_peers(self, *args, **kwargs):
        return list(self.peers.keys())
    
    def _get_funcs(self, *args, **kwargs):
        return list(self.registered_functions.keys())
    
    def register(self, command: str):
        def register_decorator(func):
            self.registered_functions[command] = func
            return func

        return register_decorator

    def target(self, target: str | list[str]) -> Target:
        return Target(self, target)
        

