import time
import sys
import oqs
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

sys.set_int_max_str_digits(10000)

ITERATIONS = 10  
RSA_KEY_SIZE = 8192
KYBER_ALG = "Kyber512"

print(f"   Speed test: RSA-{RSA_KEY_SIZE} vs. {KYBER_ALG}")
print(f"Running {ITERATIONS} rounds. Streaming results live...")
print(f"WARNING: RSA Key Gen might take 10-60 seconds PER ROUND.")
print(f"Please be patient.\n")

# Lists to store times for the final average
rsa_keygen_times = []
rsa_enc_times = []
rsa_dec_times = []
kyber_keygen_times = []
kyber_enc_times = []
kyber_dec_times = []

print(f"--- ROUND 1: RSA ({RSA_KEY_SIZE}-bit) ---")
print(f"{'Run':<5} | {'KeyGen (s)':<12} | {'Encrypt (s)':<12} | {'Decrypt (s)':<12} | {'Status'}")
print("-" * 65)

for i in range(ITERATIONS):
    
    start = time.time()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    public_key = private_key.public_key()
    t_keygen = time.time() - start
    rsa_keygen_times.append(t_keygen)

   
    message = b"Secret Message"
    start = time.time()
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    t_enc = time.time() - start
    rsa_enc_times.append(t_enc)

    # C. RSA Decryption
    start = time.time()
    decrypted = private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    t_dec = time.time() - start
    rsa_dec_times.append(t_dec)
    
    # Verify
    status = "✅" if decrypted == message else "❌"
    
    # Live Print
    print(f"{i+1:<5} | {t_keygen:.5f}      | {t_enc:.5f}      | {t_dec:.5f}      | {status}")

print("-" * 65)
print("RSA Testing Complete.\n")
time.sleep(1)



print(f"--- ROUND 2: KYBER ({KYBER_ALG}) ---")
print(f"{'Run':<5} | {'KeyGen (s)':<12} | {'Encap (s)':<12} | {'Decap (s)':<12} | {'Status'}")
print("-" * 65)

# Initialize Kyber
kem = oqs.KeyEncapsulation(KYBER_ALG)

for i in range(ITERATIONS):
    # A. Kyber Key Generation
    start = time.time()
    public_key_kyber = kem.generate_keypair()
    t_keygen = time.time() - start
    kyber_keygen_times.append(t_keygen)

    # B. Kyber Encapsulation
    start = time.time()
    ciphertext_kyber, shared_secret_alice = kem.encap_secret(public_key_kyber)
    t_enc = time.time() - start
    kyber_enc_times.append(t_enc)

    # C. Kyber Decapsulation
    start = time.time()
    shared_secret_bob = kem.decap_secret(ciphertext_kyber)
    t_dec = time.time() - start
    kyber_dec_times.append(t_dec)
    
    # Verify
    status = "✅" if shared_secret_alice == shared_secret_bob else "❌"

    # Live Print
    print(f"{i+1:<5} | {t_keygen:.5f}      | {t_enc:.5f}      | {t_dec:.5f}      | {status}")

print("-" * 65)
print("Kyber Testing Complete.\n")


# 3. FINAL COMPARISON SUMMARY
avg_rsa_k = sum(rsa_keygen_times) / ITERATIONS
avg_ky_k = sum(kyber_keygen_times) / ITERATIONS

avg_rsa_e = sum(rsa_enc_times) / ITERATIONS
avg_ky_e = sum(kyber_enc_times) / ITERATIONS

avg_rsa_d = sum(rsa_dec_times) / ITERATIONS
avg_ky_d = sum(kyber_dec_times) / ITERATIONS

print("\n" + "="*60)
print("   FINAL SCOREBOARD (AVERAGE TIMES)")
print("="*60)
print(f"{'OPERATION':<20} | {'RSA-8192 (s)':<12} | {'KYBER (s)':<12} | {'SPEEDUP'}")
print("-" * 60)

# Avoid division by zero if Kyber is too fast (0.0s)
if avg_ky_k == 0: avg_ky_k = 0.000001
if avg_ky_e == 0: avg_ky_e = 0.000001
if avg_ky_d == 0: avg_ky_d = 0.000001

print(f"{'Key Generation':<20} | {avg_rsa_k:.5f}      | {avg_ky_k:.5f}        | {avg_rsa_k/avg_ky_k:.1f}x FASTER")
print(f"{'Encap/Encrypt':<20} | {avg_rsa_e:.5f}      | {avg_ky_e:.5f}        | {avg_rsa_e/avg_ky_e:.1f}x FASTER")
print(f"{'Decap/Decrypt':<20} | {avg_rsa_d:.5f}      | {avg_ky_d:.5f}        | {avg_rsa_d/avg_ky_d:.1f}x FASTER")
print("-" * 60)
print("Conclusion: RSA struggles massively at high security levels.")
print("            Kyber remains incredibly fast regardless of security level.")