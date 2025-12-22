# -*- coding: utf-8 -*-
"""
btcshort.py - GPU Bitcoin Private Key Search dengan bt2.so
FIXED VERSION untuk range kecil dengan parameter yang benar
"""

import pycuda.driver as cuda
import pycuda.autoinit
from pycuda.compiler import SourceModule
import numpy as np
import time
import hashlib
import base58
import ecdsa
from ecdsa.curves import SECP256k1
import multiprocessing as mp
import os
import sys
import ctypes
import random
import math
import platform
import traceback

# ==================== LOAD BT2 LIBRARY ====================
def load_bt2_library():
    """Load bt2.so library untuk operasi BSGS GPU"""
    if platform.system().lower().startswith('win'):
        libfile = 'bt2.dll'
    elif platform.system().lower().startswith('lin'):
        libfile = 'bt2.so'
    else:
        print('[-] Unsupported Platform')
        sys.exit()
    
    if not os.path.isfile(libfile):
        print(f'File {libfile} not found')
        sys.exit()
    
    pathlib = os.path.realpath(libfile)
    bt2 = ctypes.CDLL(pathlib)
    
    # Define argument types untuk fungsi bsgsGPU
    bt2.bsgsGPU.argtypes = [
        ctypes.c_uint32,  # threads
        ctypes.c_uint32,  # blocks
        ctypes.c_uint32,  # points
        ctypes.c_uint32,  # gpu_bits
        ctypes.c_int,     # device
        ctypes.c_char_p,  # upubs
        ctypes.c_uint32,  # size
        ctypes.c_char_p,  # keyspace
        ctypes.c_char_p   # bp_size
    ]
    bt2.bsgsGPU.restype = ctypes.c_void_p
    bt2.free_memory.argtypes = [ctypes.c_void_p]
    
    print(f"✅ Loaded {libfile} library for GPU ECC operations")
    return bt2

# ==================== INSTALL PYCYPTODOME ====================
try:
    from Crypto.Hash import RIPEMD160
    RIPEMD160_AVAILABLE = True
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome"])
    from Crypto.Hash import RIPEMD160
    RIPEMD160_AVAILABLE = True

# ==================== KONFIGURASI FIXED ====================
MIN_RANGE = "80000"    # Start range (Hex) - 20-bit (524,288)
MAX_RANGE = "FFFFF"    # End range (Hex) - 20-bit (1,048,575)

TARGET_ADDR = "1HsMJxNiV7TLxmoF6uJNkydxPFDog4NQum"

# PARAMETER YANG DIPERBAIKI UNTUK RANGE KECIL
# Untuk range 20-bit (1,048,576 keys), BP_SIZE minimal 1024 agar valid
RANGE_SIZE = int(MAX_RANGE, 16) - int(MIN_RANGE, 16) + 1
print(f"📊 Range size: {RANGE_SIZE:,} keys")

# BP_SIZE minimal untuk bt2.so adalah 1024 (2^10) agar bloom filter valid
MIN_BP_SIZE = 1024  # Minimal untuk alokasi bloom filter
OPTIMAL_BP_SIZE = max(MIN_BP_SIZE, int(math.sqrt(RANGE_SIZE)))
print(f"📊 Minimal BP_SIZE: {MIN_BP_SIZE:,}")
print(f"📊 Optimal BP_SIZE: {OPTIMAL_BP_SIZE:,}")

# Konfigurasi GPU
BT2_GPU_THREADS = 64     # Kembali ke nilai normal
BT2_GPU_BLOCKS = 8       # Kembali ke nilai normal  
BT2_GPU_POINTS = 256     # Kembali ke nilai normal
BT2_BP_TABLE_SIZE = OPTIMAL_BP_SIZE

USE_ALL_GPUS = True
GPU_IDS = [0] if not USE_ALL_GPUS else list(range(cuda.Device.count()))

# ==================== FUNGSI UTILITAS ====================
def ripemd160_hash(data):
    """Implementasi RIPEMD160"""
    h = RIPEMD160.new()
    h.update(data)
    return h.digest()

def validate_bsgs_parameters(range_start, range_end, bp_size):
    """Validasi parameter sebelum memanggil bsgsGPU"""
    range_size = range_end - range_start
    
    print(f"\n🔍 Validating BSGS parameters:")
    print(f"  Range: {hex(range_start)} to {hex(range_end)}")
    print(f"  Range size: {range_size:,} keys")
    print(f"  BP Size: {bp_size:,}")
    print(f"  Range bits: {range_size.bit_length()}")
    print(f"  BP bits: {int(math.log2(bp_size))}")
    
    # Validasi 1: BP_SIZE harus >= 1024 untuk bt2.so
    if bp_size < 1024:
        print(f"  ⚠️ WARNING: BP_SIZE ({bp_size}) terlalu kecil!")
        print(f"  ℹ️ bt2.so requires BP_SIZE >= 1024")
        return False
    
    # Validasi 2: BP_SIZE harus <= range_size
    if bp_size > range_size:
        print(f"  ⚠️ WARNING: BP_SIZE ({bp_size}) > range_size ({range_size:,})!")
        print(f"  ℹ️ BP_SIZE should be <= range_size for BSGS")
        return False
    
    # Validasi 3: range_size harus cukup besar
    if range_size < bp_size * 10:
        print(f"  ⚠️ WARNING: Range terlalu kecil untuk BSGS")
        print(f"  ℹ️ For optimal BSGS: range_size >= BP_SIZE × 10")
        print(f"  ℹ️ Current: {range_size:,} < {bp_size * 10:,}")
    
    print(f"  ✅ Parameters are valid")
    return True

def decompress_pubkey(compressed_pubkey_hex):
    """Decompress compressed public key"""
    if not compressed_pubkey_hex.startswith(('02', '03')):
        raise ValueError("Not a compressed public key")
    
    x_hex = compressed_pubkey_hex[2:]
    x = int(x_hex, 16)
    
    curve = SECP256k1.curve
    p = curve.p()
    
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    
    if (y % 2) != (int(compressed_pubkey_hex[:2], 16) % 2):
        y = p - y
    
    return x, y

def pubkey_to_uncompressed_bytes(pubkey_hex):
    """Convert pubkey hex ke uncompressed bytes"""
    if len(pubkey_hex) == 130 and pubkey_hex.startswith('04'):
        return bytes.fromhex(pubkey_hex)
    elif len(pubkey_hex) == 66 and pubkey_hex.startswith(('02', '03')):
        x, y = decompress_pubkey(pubkey_hex)
        return bytes.fromhex(f"04{hex(x)[2:].zfill(64)}{hex(y)[2:].zfill(64)}")
    else:
        raise ValueError(f"Invalid public key format")

def generate_p3_table(pubkey_bytes, bp_size):
    """Generate P3 table untuk BSGS"""
    print(f"🔧 Generating P3 table ({bp_size:,} points)...")
    
    try:
        import secp256k1_lib as ice
        G = ice.scalar_multiplication(1)
        
        if bp_size <= 10000:
            P3 = ice.point_sequential_increment(bp_size, pubkey_bytes)
        else:
            P3 = ice.point_loop_addition(bp_size, pubkey_bytes, G)
            
        print(f"✅ P3 table: {len(P3):,} bytes, {len(P3)//65:,} points")
        return P3
        
    except ImportError:
        print("⚠️ secp256k1_lib not found, using fallback...")
        # Fallback sederhana untuk testing
        return bytes([0x04] * 65 * bp_size)

def bsgs_search_with_params(bt2_lib, P3, start_key, end_key, bp_size, gpu_id=0):
    """BSGS search dengan parameter yang divalidasi"""
    # Hitung gpu_bits
    gpu_bits = int(math.log2(bp_size))
    
    # Validasi parameter
    if not validate_bsgs_parameters(start_key, end_key, bp_size):
        print("❌ Parameter validation failed")
        return ""
    
    # Format keyspace tanpa padding berlebihan
    keyspace = f"{hex(start_key)[2:]}:{hex(end_key)[2:]}"
    
    print(f"\n🚀 Calling bsgsGPU with:")
    print(f"  threads={BT2_GPU_THREADS}, blocks={BT2_GPU_BLOCKS}, points={BT2_GPU_POINTS}")
    print(f"  gpu_bits={gpu_bits}, device={gpu_id}")
    print(f"  P3 points={len(P3)//65}, bp_size={bp_size}")
    print(f"  keyspace={keyspace}")
    
    try:
        res_ptr = bt2_lib.bsgsGPU(
            ctypes.c_uint32(BT2_GPU_THREADS),
            ctypes.c_uint32(BT2_GPU_BLOCKS),
            ctypes.c_uint32(BT2_GPU_POINTS),
            ctypes.c_uint32(gpu_bits),
            ctypes.c_int(gpu_id),
            ctypes.c_char_p(P3),
            ctypes.c_uint32(len(P3) // 65),
            ctypes.c_char_p(keyspace.encode('utf8')),
            ctypes.c_char_p(str(bp_size).encode('utf8'))
        )
        
        result = (ctypes.cast(res_ptr, ctypes.c_char_p).value)
        bt2_lib.free_memory(res_ptr)
        
        if result:
            return result.decode('utf8')
        return ""
        
    except Exception as e:
        print(f"❌ BSGS error: {e}")
        traceback.print_exc()
        return ""

def verify_private_key(private_key_hex, target_address):
    """Verify if private key matches target address"""
    try:
        if len(private_key_hex) != 64:
            return False
        
        priv_key_int = int(private_key_hex, 16)
        if priv_key_int <= 0:
            return False
            
        CURVE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8B0D1D0E8C
        if priv_key_int >= CURVE_N:
            return False
        
        sk = ecdsa.SigningKey.from_secret_exponent(priv_key_int, curve=SECP256k1)
        vk = sk.get_verifying_key()
        
        if vk.pubkey.point.y() % 2 == 0:
            public_key = b'\x02' + vk.to_string()[:32]
        else:
            public_key = b'\x03' + vk.to_string()[:32]
        
        sha256 = hashlib.sha256(public_key).digest()
        hash160 = ripemd160_hash(sha256)
        
        version_hash = b'\x00' + hash160
        checksum = hashlib.sha256(hashlib.sha256(version_hash).digest()).digest()[:4]
        address_bytes = version_hash + checksum
        generated_address = base58.b58encode(address_bytes).decode()
        
        return generated_address == target_address
        
    except Exception:
        return False

# ==================== SOLUSI UTAMA ====================
def run_correct_bsgs_search():
    """BSGS search dengan parameter yang benar-benar bekerja"""
    print("\n" + "="*70)
    print("BSGS GPU SEARCH - CORRECT PARAMETERS")
    print("="*70)
    
    # Load library
    bt2 = load_bt2_library()
    
    # Target pubkey (harus diketahui)
    target_pubkey_hex = "02CEB6CBBCDBDF5EF7150682150F4CE2C6F4807B349827DCDBDD1F2EFA885A2630"
    
    # Convert ke uncompressed
    P = pubkey_to_uncompressed_bytes(target_pubkey_hex)
    
    # Range
    min_key = int(MIN_RANGE, 16)
    max_key = int(MAX_RANGE, 16)
    range_size = max_key - min_key
    
    print(f"\n🎯 Target Address: {TARGET_ADDR}")
    print(f"🔍 Search Range: {hex(min_key)} to {hex(max_key)}")
    print(f"📊 Range Size: {range_size:,} keys ({range_size.bit_length()}-bit)")
    
    # ============================================================
    # SOLUSI 1: Gunakan BP_SIZE yang benar-benar valid (1024)
    # ============================================================
    bp_size = 1024  # HARUS minimal 1024 untuk bt2.so
    gpu_bits = 10   # log2(1024) = 10
    
    print(f"\n⚙️ Using FIXED parameters for bt2.so:")
    print(f"  BP_SIZE = {bp_size:,} (MINIMAL untuk bt2.so)")
    print(f"  GPU_BITS = {gpu_bits}")
    print(f"  Threads = {BT2_GPU_THREADS}")
    print(f"  Blocks = {BT2_GPU_BLOCKS}")
    print(f"  Points = {BT2_GPU_POINTS}")
    
    # Validasi
    if not validate_bsgs_parameters(min_key, max_key, bp_size):
        print("❌ Parameter tidak valid, adjusting...")
        
        # Jika range terlalu kecil untuk BP_SIZE=1024, perbesar range
        if range_size < bp_size * 2:
            print(f"⚠️ Range terlalu kecil, perluas range...")
            # Perbesar range secara artifisial untuk testing
            max_key = min_key + bp_size * 20
            print(f"  New range: {hex(min_key)} to {hex(max_key)}")
            print(f"  New size: {(max_key-min_key):,} keys")
    
    # Generate P3 table
    print(f"\n🔧 Generating P3 table...")
    P3 = generate_p3_table(P, bp_size)
    
    # Jalankan BSGS
    print(f"\n🚀 Starting BSGS Search...")
    start_time = time.time()
    
    result = bsgs_search_with_params(bt2, P3, min_key, max_key, bp_size, 0)
    
    elapsed = time.time() - start_time
    print(f"\n⏱️ Search completed in {elapsed:.2f} seconds")
    
    if result and result.strip():
        print(f"📝 Result: {result}")
        
        # Cek semua kandidat
        candidates = [c.strip() for c in result.split(',') if c.strip()]
        for candidate in candidates:
            if len(candidate) == 64:
                print(f"\n🔍 Verifying candidate: {candidate[:16]}...")
                if verify_private_key(candidate, TARGET_ADDR):
                    print(f"\n🎉🎉🎉 KEY FOUND! 🎉🎉🎉")
                    print(f"Private Key: {candidate}")
                    with open('found_key.txt', 'w') as f:
                        f.write(candidate)
                    return True
                else:
                    print(f"⚠️ False positive")
    
    print(f"\n❌ No valid key found in range")
    return False

def brute_force_fallback():
    """Fallback ke brute force CPU jika BSGS gagal"""
    print("\n" + "="*70)
    print("CPU BRUTE FORCE FALLBACK")
    print("="*70)
    
    min_key = int(MIN_RANGE, 16)
    max_key = int(MAX_RANGE, 16)
    total_keys = max_key - min_key
    
    print(f"\n🔍 Brute forcing range {hex(min_key)} to {hex(max_key)}")
    print(f"📊 Total keys: {total_keys:,}")
    
    start_time = time.time()
    keys_checked = 0
    batch_size = 10000
    
    for batch_start in range(min_key, max_key + 1, batch_size):
        batch_end = min(batch_start + batch_size, max_key + 1)
        
        for key_int in range(batch_start, batch_end):
            key_hex = hex(key_int)[2:].zfill(64)
            
            if verify_private_key(key_hex, TARGET_ADDR):
                print(f"\n🎉 KEY FOUND! {key_hex}")
                with open('found_key.txt', 'w') as f:
                    f.write(key_hex)
                return True
            
            keys_checked += 1
            
            if keys_checked % 10000 == 0:
                elapsed = time.time() - start_time
                if elapsed > 0:
                    speed = keys_checked / elapsed
                    progress = (key_int - min_key) / total_keys * 100
                    print(f"Progress: {progress:.1f}% | Speed: {speed:.0f} keys/s")
    
    elapsed = time.time() - start_time
    print(f"\n⏱️ Completed in {elapsed:.1f}s")
    print(f"📊 Keys checked: {keys_checked:,}")
    print(f"❌ Key not found")
    
    return False

def alternative_small_range_search():
    """Alternatif: bagi range menjadi bagian-bagian kecil"""
    print("\n" + "="*70)
    print("ALTERNATIVE: CHUNKED BSGS SEARCH")
    print("="*70)
    
    bt2 = load_bt2_library()
    target_pubkey_hex = "02CEB6CBBCDBDF5EF7150682150F4CE2C6F4807B349827DCDBDD1F2EFA885A2630"
    P = pubkey_to_uncompressed_bytes(target_pubkey_hex)
    
    min_key = int(MIN_RANGE, 16)
    max_key = int(MAX_RANGE, 16)
    
    # Gunakan BP_SIZE minimal yang valid
    bp_size = 1024
    P3 = generate_p3_table(P, bp_size)
    
    # Bagi range menjadi chunk yang lebih kecil
    chunk_size = bp_size * 50  # Setiap chunk 50x BP_SIZE
    total_chunks = (max_key - min_key) // chunk_size + 1
    
    print(f"\n🔧 Chunked search parameters:")
    print(f"  Total chunks: {total_chunks}")
    print(f"  Chunk size: {chunk_size:,} keys")
    print(f"  BP Size: {bp_size:,}")
    
    start_time = time.time()
    
    for chunk in range(total_chunks):
        chunk_start = min_key + (chunk * chunk_size)
        chunk_end = min(chunk_start + chunk_size, max_key)
        
        print(f"\n📦 Chunk {chunk+1}/{total_chunks}: {hex(chunk_start)} to {hex(chunk_end)}")
        print(f"   Size: {(chunk_end-chunk_start):,} keys")
        
        result = bsgs_search_with_params(bt2, P3, chunk_start, chunk_end, bp_size, 0)
        
        if result and result.strip():
            candidates = [c.strip() for c in result.split(',') if c.strip()]
            for candidate in candidates:
                if len(candidate) == 64 and verify_private_key(candidate, TARGET_ADDR):
                    print(f"\n🎉 KEY FOUND IN CHUNK {chunk+1}!")
                    print(f"Private Key: {candidate}")
                    with open('found_key.txt', 'w') as f:
                        f.write(candidate)
                    return True
    
    elapsed = time.time() - start_time
    print(f"\n⏱️ Chunked search completed in {elapsed:.1f}s")
    return False

# ==================== MAIN PROGRAM ====================
if __name__ == "__main__":
    print('\n' + '='*70)
    print('BITCOIN PRIVATE KEY SEARCH - FIXED VERSION')
    print('='*70)
    
    print(f"\n🎯 Target: {TARGET_ADDR}")
    print(f"🔍 Range: {MIN_RANGE} to {MAX_RANGE}")
    print(f"📊 Range size: {(int(MAX_RANGE, 16) - int(MIN_RANGE, 16)):,} keys")
    
    print("\n🔧 Available search methods:")
    print("1. BSGS GPU with correct parameters (BP_SIZE=1024)")
    print("2. CPU Brute Force (slow but reliable)")
    print("3. Chunked BSGS Search (alternative)")
    
    choice = input("\nSelect method (1-3): ").strip()
    
    success = False
    
    if choice == "1":
        print("\n" + "="*70)
        print("METHOD 1: BSGS GPU WITH FIXED PARAMETERS")
        print("="*70)
        success = run_correct_bsgs_search()
        
    elif choice == "2":
        success = brute_force_fallback()
        
    elif choice == "3":
        success = alternative_small_range_search()
        
    else:
        print("❌ Invalid choice, using method 1")
        success = run_correct_bsgs_search()
    
    if not success:
        print("\n" + "="*70)
        print("SEARCH FAILED - TRYING DIFFERENT PARAMETERS")
        print("="*70)
        
        # Coba dengan BP_SIZE yang berbeda
        bt2 = load_bt2_library()
        target_pubkey_hex = "02CEB6CBBCDBDF5EF7150682150F4CE2C6F4807B349827DCDBDD1F2EFA885A2630"
        P = pubkey_to_uncompressed_bytes(target_pubkey_hex)
        
        min_key = int(MIN_RANGE, 16)
        max_key = int(MAX_RANGE, 16)
        
        # Coba beberapa BP_SIZE yang mungkin bekerja
        bp_sizes_to_try = [2048, 4096, 8192, 16384]
        
        for bp_size in bp_sizes_to_try:
            print(f"\n🔄 Trying BP_SIZE = {bp_size:,}...")
            
            if bp_size > (max_key - min_key):
                print(f"  ⚠️ BP_SIZE terlalu besar untuk range, skipping...")
                continue
            
            P3 = generate_p3_table(P, bp_size)
            result = bsgs_search_with_params(bt2, P3, min_key, max_key, bp_size, 0)
            
            if result and result.strip():
                print(f"  📝 Got result: {result[:50]}...")
                # Verifikasi kandidat
                candidates = [c.strip() for c in result.split(',') if c.strip()]
                for candidate in candidates:
                    if len(candidate) == 64 and verify_private_key(candidate, TARGET_ADDR):
                        print(f"\n🎉 KEY FOUND WITH BP_SIZE={bp_size}!")
                        print(f"Private Key: {candidate}")
                        with open('found_key.txt', 'w') as f:
                            f.write(candidate)
                        success = True
                        break
                
                if success:
                    break
    
    print("\n" + "="*70)
    print("SEARCH COMPLETED")
    print("="*70)
    
    if success:
        print("✅ Key found and saved to found_key.txt")
    else:
        print("❌ Key not found in the specified range")
        print("💡 Try:")
        print("  1. Increase the search range")
        print("  2. Use a different target address")
        print("  3. Check if the target address is within the range")
