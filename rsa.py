

import time
import sys
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import numpy as np


KEY_SIZE = 8192  

def print_status(msg):
    sys.stdout.write(f"\r{msg}")
    sys.stdout.flush()

print("")
print(" INITIALIZING CRYPTO STRESS TEST  ☢️")
print("")
print(f" ALGORITHM:  RSA (Rivest–Shamir–Adleman)")
print(f"KEY SIZE:   {KEY_SIZE} bits (EXTREME SECURITY)")
print("\n")


print(f"[-] PHASE 1: GENERATING {KEY_SIZE}-BIT KEY PAIR")
print("    (This involves finding two 4096-bit prime numbers p and q...)")

start_total = time.time()

sys.stdout.write("    [WORKING] Searching for primes...\n")

#this basically means that we're generating the p and q primes. random 8192 bit numbers
#e is our public exponent and the key size is 8192 bits made up from 4096 and 4096
#the key size is 'n'
#public_key is basically the information publicly available (n and e)

start_gen = time.time()
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=KEY_SIZE,
)
end_gen = time.time()

public_key = private_key.public_key()
gen_duration = end_gen - start_gen

print(f"\n[+] KEY GENERATED SUCCESSFULLY.")
print(f"    Time Taken: {gen_duration:.4f} seconds.")


print(f"\n[-] PHASE 2: INSPECTING {KEY_SIZE}-BIT MODULUS")
print("    We will verify the bit-length of the generated numbers.")

#now we are extracting the public numbers and private numbers
#so here the n_len is the 'n' bits which is 8192, so our code should also output 8192

private_numbers = private_key.private_numbers()
public_numbers = public_key.public_numbers() 

n_val = public_numbers.n
n_hex = hex(n_val)
n_len = n_val.bit_length()

print(f"  > Verification: Modulus bit length is {n_len} bits.")
print(f"    (First 150 chars): {str(n_val)[:150]}...")
print(f"    (Last  150 chars): ...{str(n_val)[-150:]}")
print(f"    (Total Decimal Digits: {len(str(n_val))})")


print("\n[-] PHASE 3: ENCRYPTION LOAD TEST")
print("    Encrypting a large payload with OAEP padding...")


#oaep padding is basically a method to add noise, so basically
# our original mathematical rsa is c = m^e mod n where c is the ciphertext and m is the message
# but with oaep padding we add randomness to the message before encrypting it
#hashing is sha256


message = b"TOP SECRET: " + (b"A" * 128) + b" : END MESSAGE"

start_enc = time.time()
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
end_enc = time.time()

print(f"  > Encrypted {len(message)} bytes -> {len(ciphertext)} bytes ciphertext.")
print(f"  > Operation Time: {(end_enc - start_enc)*1000:.4f} ms")
print(f"  > Ciphertext Snippet (Hex):\n    {ciphertext.hex()[:100]}...[TRUNCATED]")


print("\n[-] PHASE 4: DECRYPTION")
print("    Using private key (d) to reverse the modular exponentiation...")

#similarly on bob's side we need to use the same oaep padding scheme to decrypt

start_dec = time.time()
decrypted = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
end_dec = time.time()

print(f"  > Decrypted successfully.")
print(f"  > Operation Time: {(end_dec - start_dec)*1000:.4f} ms")
print(f"  > Recovered: {decrypted[:20]}...")

if(decrypted == message):
    print(" Decryption matches original message.")
else:
    print(" Decryption failed. Mismatch with original message.")


print("   STRESS TEST COMPLETE")
print(f"   Total Execution Time: {time.time() - start_total:.4f} seconds")