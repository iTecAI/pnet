from pnet import Crypt
import time
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



if __name__ == "__main__":
    test_crypt_parity(rounds=1024)
    test_crypt_objects(rounds=1024)