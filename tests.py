from pnet import Crypt, Node
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
        passed.append(result == input_data)
    results, avg = timer.resolve()
    print(f"Results:\n\tAverage time: {avg}s\n\tAll passed: {all(passed)}\n\tLow/High: {min(results)}s / {max(results)}s")

def test_nodes(rounds = 128):
    print("Testing nodes")
    timer = Timer()
    nkey = Fernet.generate_key()
    alice = Node("alice", "ab", onmessage=lambda v: f"Pong - {v.decode('utf-8')}".encode("utf-8"), network_key=nkey)
    alice.serve()
    bob = Node("bob", "ab", onmessage=lambda v: f"Pong - {v.decode('utf-8')}".encode("utf-8"), network_key=nkey, server_port=3336)
    bob.serve()

    print("Waiting for node detection")
    for i in range(10):
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


if __name__ == "__main__":
    #test_crypt_parity(rounds=1024)
    #test_crypt_objects(rounds=1024)
    test_nodes(rounds=1024)