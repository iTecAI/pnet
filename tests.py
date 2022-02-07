import base64
from pnet import Crypt, Node, AdvancedNode
from cryptography.fernet import Fernet
import time
import random
import os

class Timer:
    def __init__(self):
        self.start = time.time()
        self.results = []
    def save(self):
        self.results.append(time.time() - self.start)
        return time.time() - self.start
    def reset(self):
        self.start = time.time()
    def resolve(self):
        return self.results, sum(self.results) / len(self.results)

def test_crypt_parity(rounds = 128):
    print("Testing encryption parity.")
    PSIZE = 4096
    timer = Timer()
    alice = Crypt()
    bob = Crypt()
    passed = []
    for r in range(rounds):
        input_data = os.urandom(PSIZE)
        timer.reset()
        enc_data = alice.encrypt(input_data, bob.public)
        result = bob.decrypt(enc_data)
        timer.save()
        #print(f"\tRound {r+1}: {'PASS' if result == input_data else 'FAIL'} - {timer.save()}s")
        passed.append(result == input_data)
    results, avg = timer.resolve()
    print(f"Results:\n\tAverage time: {avg}s\n\tAll passed: {all(passed)}\n\tLow/High: {min(results)}s / {max(results)}s")

class Dummy:
    def __init__(self):
        self.value = os.urandom(512)

def test_crypt_objects(rounds = 128):
    print("Testing encryption with python objects.")
    timer = Timer()
    alice = Crypt()
    bob = Crypt()
    passed = []
    for r in range(rounds):
        input_data = Dummy()
        timer.reset()
        enc_data = alice.encrypt(input_data, bob.public)
        result = bob.decrypt(enc_data)
        timer.save()
        #print(f"\tRound {r+1}: {'PASS' if result.value == input_data.value else 'FAIL'} - {timer.save()}s")
        passed.append(result.value == input_data.value)
    results, avg = timer.resolve()
    print(f"Results:\n\tAverage time: {avg}s\n\tAll passed: {all(passed)}\n\tLow/High: {min(results)}s / {max(results)}s")

def test_nodes(rounds = 128):
    print("Testing nodes")
    timer = Timer()
    nkey = Fernet.generate_key()
    alice = Node("alice", "ab", onmessage=lambda v: f"Pong - {v.decode('utf-8')}".encode("utf-8"), network_key=nkey)
    alice.serve()
    bob = Node("bob", "ab", onmessage=lambda v: f"Pong - {v.decode('utf-8')}".encode("utf-8"), network_key=nkey, server_port=random.randint(3340, 3399))
    bob.serve()

    print("Waiting for node detection")
    for i in range(2):
        #print(alice.peers, bob.peers)
        time.sleep(1)   

    passed = []
    for r in range(rounds):
        data = f"Ping - {random.random()}".encode("utf-8")
        timer.reset()
        result = alice.send("bob", data)
        t = timer.save()
        print(f"\tInput: {data} | Output: {result} | Pass: {'Pong - '.encode('utf-8') + data == result} | Elapsed: {t}s")
        passed.append('Pong - '.encode('utf-8') + data == result)
    
    results, avg = timer.resolve()
    print(f"Results:\n\tAverage time: {avg}s\n\tAll passed: {all(passed)}\n\tLow/High: {min(results)}s / {max(results)}s")
    alice.shutdown()
    bob.shutdown()

def test_big_nodes(rounds = 128, n = 48):
    print("Testing nodes")
    timer = Timer()
    nkey = Fernet.generate_key()

    nodes = []
    for i in range(n):
        n = Node(f"Node-{i}", "nodes", onmessage=lambda v: f"Pong - {v}", network_key=nkey, server_port=i+3400)
        n.serve()
        nodes.append(n)
    
    print("Waiting for node detection")
    time.sleep(2)

    passed = []
    for r in range(rounds):
        data = f"Ping - {random.random()}"
        random.shuffle(nodes)
        timer.reset()
        result = nodes[0].send(nodes[1].name, data)
        t = timer.save()
        print(f"\tNodes: {nodes[0].name} -> {nodes[1].name} | Input: {data} | Output: {result} | Pass: {'Pong - ' + data == result} | Elapsed: {t}s")
        passed.append('Pong - ' + data == result)
    
    results, avg = timer.resolve()
    print(f"Results:\n\tAverage time: {avg}s\n\tAll passed: {all(passed)}\n\tLow/High: {min(results)}s / {max(results)}s")
    [i.shutdown() for i in nodes]

def test_objects(rounds = 128, n = 20):
    print("Testing nodes")
    timer = Timer()
    nkey = Fernet.generate_key()

    nodes = []
    for i in range(n):
        n = Node(f"Node-{i}", "nodes", onmessage=lambda v: v.value, network_key=nkey, server_port=i+3400)
        n.serve()
        nodes.append(n)
    
    print("Waiting for node detection")
    time.sleep(2)

    passed = []
    for r in range(rounds):
        data = Dummy()
        random.shuffle(nodes)
        timer.reset()
        result = nodes[0].send(nodes[1].name, data)
        t = timer.save()
        print(f"\tNodes: {nodes[0].name} -> {nodes[1].name} | Input: {data} | Output: {result} | Pass: {result == data.value} | Elapsed: {t}s")
        passed.append(result == data.value)
    
    results, avg = timer.resolve()
    print(f"Results:\n\tAverage time: {avg}s\n\tAll passed: {all(passed)}\n\tLow/High: {min(results)}s / {max(results)}s")
    [i.shutdown() for i in nodes]

def test_adv_node_1():
    nkey = Fernet.generate_key()
    n1 = AdvancedNode("node1", "nodes", network_key=nkey, server_port=random.randint(3336, 5000))
    n2 = AdvancedNode("node2", "nodes", network_key=nkey, server_port=random.randint(3336, 5000))

    @n2.register("testfile")
    def rfile(node, originator, data):
        with open(os.path.join("testfiles", "testrecv.webm"), "wb+") as f:
            while True:
                new_data = data.read(16384)
                if not new_data: break
                f.write(new_data)
        data.close()
        return open(os.path.join("testfiles", "testrecv.webm"), "rb")

    n1.serve()
    n2.serve()
    time.sleep(2)

    timer = Timer()

    with open(os.path.join("testfiles", "testfile.webm"), "rb") as f:
        dat = n1._send_chunked("node2", "testfile", f)
        with open(os.path.join("testfiles", "testrecv2.webm"), "wb") as f2:
            while True:
                new_data = dat.read(16384)
                if not new_data: break
                f2.write(new_data)
        dat.close()
    timer.save()
    print(timer.resolve())

def _testdata(node, originator, data):
    data = data.read()
    print(f"\tGot {len(data)} bytes from {originator} on node {node.name}")
    return len(data)

def advanced_node_stress_test(rounds = 32, minsize = 128, maxsize = 1048576, nodes = 20):
    key = Fernet.generate_key()
    sp = random.randint(4000, 4800)
    nodes = [AdvancedNode(f"Node-{n}", "testnet", network_key=key, server_port=sp+n, functions={"test": _testdata}) for n in range(nodes)]
    [i.serve() for i in nodes]
    time.sleep(2)
    timer = Timer()

    passed = []
    for i in range(rounds):
        data = os.urandom(random.randint(minsize, maxsize))
        print(f"Round {i} - {len(data)} bytes")
        initiator: AdvancedNode = random.choice(nodes)

        timer.reset()
        result = initiator.send("*", "test", data)
        print(f"Test {i}: {timer.save()}s - PASS: {all([r == len(data) for r in result.values()])} - Result: {result}")
        passed.append(all([r == len(data) for r in result.values()]))

    results, avg = timer.resolve()
    print(f"Results:\n\tAverage time: {avg}s\n\tAll passed: {all(passed)}\n\tLow/High: {min(results)}s / {max(results)}s")
    [i.shutdown() for i in nodes]
    


if __name__ == "__main__":
    #test_crypt_parity(rounds=1024)
    #test_crypt_objects(rounds=1024)
    #test_nodes(rounds=1024)
    #test_big_nodes()
    #test_objects()
    #test_adv_node_1()
    advanced_node_stress_test()