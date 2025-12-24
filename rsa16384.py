

import time
import sys
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

sys.set_int_max_str_digits(10000)  


KEY_SIZE = 16384
WORKLOAD_ROUNDS = 50  

def print_spinner(stop_event):
    """A little spinner to show the code hasn't crashed during long waits."""
    spinner = ['|', '/', '-', '\\']
    idx = 0
    while not stop_event():
        sys.stdout.write(f"\r    [CALCULATING] Finding 8000-bit Primes... {spinner[idx]}")
        sys.stdout.flush()
        time.sleep(0.1)
        idx = (idx + 1) % 4

print(f"  > KEY SIZE:   {KEY_SIZE} bits")
print(f"  > WORKLOAD:   {WORKLOAD_ROUNDS} cycles of heavy decryption")



print(f"[-] PHASE 1: GENERATING {KEY_SIZE}-BIT KEY PAIR")

start_total = time.time()
start_gen = time.time()

sys.stdout.write(f"    [WORKING] CPU is hunting for primes\n")


private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=KEY_SIZE,
)


public_key = private_key.public_key()
end_gen = time.time()
gen_duration = end_gen - start_gen

print(f"\r    [DONE] Primes found. Key structure built.")
print(f"\n[+] KEY GENERATION COMPLETE.")
print(f"    Time Taken: {gen_duration:.4f} seconds.")



print(f"\n[-] PHASE 2: VERIFICATION")
n_val = public_key.public_numbers().n
print(f"  > Modulus Bit Length: {n_val.bit_length()} bits")
print(f"  > Decimal Digits:     {len(str(n_val))} digits")
print(f"    (Imagine a number with {len(str(n_val))} digits. That is 'n'.)")



print(f"\n[-] PHASE 3: ENDURANCE TEST ({WORKLOAD_ROUNDS} Rounds)")
print("    We will now encrypt and decrypt a payload repeatedly.")
print("    This forces the CPU to perform modular exponentiation on huge numbers.")

message = b"This is a stress test payload." * 10  # Make it a bit longer
encrypted_payload = public_key.encrypt(
    message,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

print(f"    Payload size: {len(encrypted_payload)} bytes (Ciphertext)")

start_work = time.time()

for i in range(WORKLOAD_ROUNDS):
    # Decryption is the mathematically heavy operation (c^d mod n)
    # d is approx 16,384 bits long.
    decrypted = private_key.decrypt(
        encrypted_payload,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    # Progress bar
    if (i+1) % 5 == 0:
        sys.stdout.write(f"\r    [Processing] Round {i+1}/{WORKLOAD_ROUNDS} complete...")
        sys.stdout.flush()

end_work = time.time()
work_duration = end_work - start_work

print(f"\n\n[+] WORKLOAD COMPLETE.")
print(f"    Avg Decryption Time: {(work_duration/WORKLOAD_ROUNDS)*1000:.2f} ms per round")
print(f"    Total Workload Time: {work_duration:.4f} seconds")

# ---------------------------------------------------------
print("   BENCHMARK RESULT")
print(f"   Total Execution Time: {time.time() - start_total:.4f} seconds")