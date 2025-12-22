# -*- coding: utf-8 -*-
"""
btcshort.py - GPU Bitcoin Private Key Search dengan Integrasi bt2.so
Optimized untuk range kecil dengan parameter yang benar
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

# ==================== KONFIGURASI OPTIMIZED ====================
MIN_RANGE = "80000"    # Start range (Hex) - 20-bit
MAX_RANGE = "FFFFF"    # End range (Hex) - 20-bit

TARGET_ADDR = "1HsMJxNiV7TLxmoF6uJNkydxPFDog4NQum"

USE_ALL_GPUS = True
GPU_IDS = [0] if not USE_ALL_GPUS else list(range(cuda.Device.count()))

# ==================== PARAMETER BSGS UNTUK RANGE KECIL ====================
# Untuk range 20-bit (1,048,576 keys), kita butuh BP_SIZE yang sangat kecil
RANGE_SIZE = int(MAX_RANGE, 16) - int(MIN_RANGE, 16) + 1
print(f"📊 Range size: {RANGE_SIZE:,} keys ({RANGE_SIZE.bit_length()}-bit)")

# Rule: BP_SIZE ≈ sqrt(range_size) untuk BSGS optimal
# Tapi untuk range kecil, kita gunakan BP_SIZE yang sangat kecil
OPTIMAL_BP_SIZE = max(100, min(1000, int(math.sqrt(RANGE_SIZE))))
print(f"📊 Optimal BP_SIZE for {RANGE_SIZE:,} keys: {OPTIMAL_BP_SIZE:,}")

BT2_GPU_THREADS = 32    # Kurangi untuk range kecil
BT2_GPU_BLOCKS = 4      # Kurangi untuk range kecil  
BT2_GPU_POINTS = 128    # Kurangi untuk range kecil
BT2_BP_TABLE_SIZE = OPTIMAL_BP_SIZE  # Gunakan yang optimal

WINDOW_SIZE = 4
USE_BT2_LIBRARY = True
USE_CUDA_KERNEL = False

# ==================== FUNGSI UTILITAS ====================
def ripemd160_hash(data):
    """Implementasi RIPEMD160"""
    h = RIPEMD160.new()
    h.update(data)
    return h.digest()

def calculate_optimal_parameters(range_size):
    """Hitung parameter optimal untuk BSGS berdasarkan ukuran range"""
    # Untuk BSGS: BP_SIZE ≈ sqrt(N), step_size ≈ N/BP_SIZE
    bp_size = max(100, min(5000, int(math.sqrt(range_size))))
    
    # Threads/blocks disesuaikan dengan range kecil
    threads = 32 if range_size < 1000000 else 64
    blocks = 4 if range_size < 1000000 else 8
    points = 128 if range_size < 1000000 else 256
    
    # Hitung step size (jumlah keys per iterasi GPU)
    step_size = max(bp_size * 10, min(1000000, range_size))
    
    return {
        'bp_size': bp_size,
        'threads': threads,
        'blocks': blocks,
        'points': points,
        'step_size': step_size,
        'gpu_bits': int(math.log2(bp_size))
    }

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

def generate_p3_table_fast(pubkey_bytes, bp_size):
    """Generate P3 table dengan optimasi"""
    print(f"🔧 Generating P3 table ({bp_size:,} points)...")
    
    try:
        # Coba gunakan secp256k1_lib untuk performa terbaik
        import secp256k1_lib as ice
        G = ice.scalar_multiplication(1)
        
        # Untuk range kecil, gunakan point_sequential_increment yang lebih efisien
        if bp_size <= 10000:
            P3 = ice.point_sequential_increment(bp_size, pubkey_bytes)
        else:
            P3 = ice.point_loop_addition(bp_size, pubkey_bytes, G)
            
        print(f"✅ P3 table: {len(P3):,} bytes, {len(P3)//65:,} points")
        return P3
        
    except ImportError:
        print("⚠️ secp256k1_lib not found, using slow fallback")
        # Fallback manual
        curve = SECP256k1
        G = curve.generator
        
        if pubkey_bytes[0] != 0x04:
            raise ValueError("Uncompressed pubkey required")
        
        x = int(pubkey_bytes[1:33].hex(), 16)
        y = int(pubkey_bytes[33:].hex(), 16)
        P = ecdsa.ellipticcurve.Point(curve.curve, x, y)
        
        points = []
        current = P
        for i in range(bp_size):
            x_hex = format(current.x(), '064x')
            y_hex = format(current.y(), '064x')
            points.append(bytes.fromhex(f"04{x_hex}{y_hex}"))
            current = current + G
            
        P3 = b''.join(points)
        print(f"⚠️ Slow P3 table: {len(P3):,} bytes")
        return P3

def bsgs_search_small_range(bt2_lib, P3, start_key, end_key, params, gpu_id=0):
    """BSGS search untuk range kecil dengan parameter yang disesuaikan"""
    bp_size = params['bp_size']
    gpu_bits = params['gpu_bits']
    threads = params['threads']
    blocks = params['blocks']
    points = params['points']
    
    # Format keyspace dengan benar
    keyspace = f"{hex(start_key)[2:].zfill(16)}:{hex(end_key)[2:].zfill(16)}"
    
    print(f"🔍 BSGS Range: {hex(start_key)} to {hex(end_key)}")
    print(f"   Keys: {(end_key-start_key):,}, BP: {bp_size:,}, Bits: {gpu_bits}")
    
    try:
        res_ptr = bt2_lib.bsgsGPU(
            ctypes.c_uint32(threads),
            ctypes.c_uint32(blocks),
            ctypes.c_uint32(points),
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
        return ""

def verify_private_key(private_key_hex, target_address):
    """Verify if private key matches target address"""
    try:
        # Validasi dasar
        if len(private_key_hex) != 64:
            return False
        
        priv_key_int = int(private_key_hex, 16)
        if priv_key_int <= 0:
            return False
            
        CURVE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8B0D1D0E8C
        if priv_key_int >= CURVE_N:
            return False
        
        # Generate address
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

def address_to_hash160(address):
    """Convert Bitcoin address ke hash160"""
    decoded = base58.b58decode(address)
    return decoded[1:-4]

# ==================== GPU WORKER OPTIMIZED ====================
class GPUWorkerOptimized:
    def __init__(self, gpu_id, min_key, max_key, target_addr, result_queue):
        self.gpu_id = gpu_id
        self.min_key = min_key
        self.max_key = max_key
        self.target_addr = target_addr
        self.result_queue = result_queue
        self.found = False
        self.bt2_lib = None
        self.params = None
        
    def run(self):
        try:
            # Inisialisasi GPU
            cuda.init()
            device = cuda.Device(self.gpu_id)
            print(f"🚀 GPU {self.gpu_id}: {device.name()}")
            
            # Load library
            self.bt2_lib = load_bt2_library()
            
            # Hitung parameter optimal
            range_size = self.max_key - self.min_key
            self.params = calculate_optimal_parameters(range_size)
            
            print(f"⚙️ GPU {self.gpu_id} Parameters:")
            print(f"  BP Size: {self.params['bp_size']:,}")
            print(f"  Threads: {self.params['threads']}, Blocks: {self.params['blocks']}")
            print(f"  Points: {self.params['points']}, GPU Bits: {self.params['gpu_bits']}")
            print(f"  Step Size: {self.params['step_size']:,}")
            
            # Target pubkey (harus diketahui sebelumnya)
            # NOTE: Dalam implementasi nyata, perlu cari pubkey dari address
            target_pubkey_hex = "02CEB6CBBCDBDF5EF7150682150F4CE2C6F4807B349827DCDBDD1F2EFA885A2630"
            
            # Generate P3 table
            P = pubkey_to_uncompressed_bytes(target_pubkey_hex)
            P3 = generate_p3_table_fast(P, self.params['bp_size'])
            
            # Mulai pencarian
            total_checked = 0
            start_time = time.time()
            current_key = self.min_key
            
            while current_key < self.max_key and not self.found:
                # Tentukan batch size
                batch_end = min(current_key + self.params['step_size'], self.max_key)
                
                print(f"\n📦 GPU {self.gpu_id} Batch: {hex(current_key)} to {hex(batch_end)}")
                print(f"   Batch size: {(batch_end-current_key):,} keys")
                
                # Lakukan BSGS search
                result = bsgs_search_small_range(
                    self.bt2_lib, P3, current_key, batch_end, 
                    self.params, self.gpu_id
                )
                
                # Verifikasi jika ada hasil
                if result and result.strip():
                    candidates = result.split(',')
                    for candidate in candidates:
                        candidate = candidate.strip()
                        if candidate and len(candidate) == 64:
                            print(f"🎯 Candidate: {candidate[:16]}...")
                            
                            if verify_private_key(candidate, self.target_addr):
                                print(f"✅ VERIFIED! Key matches target address")
                                self.found = True
                                self.result_queue.put({
                                    'gpu_id': self.gpu_id,
                                    'private_key': candidate,
                                    'status': 'FOUND'
                                })
                                return
                            else:
                                print(f"⚠️ False positive")
                
                total_checked += (batch_end - current_key)
                current_key = batch_end
                
                # Progress report
                elapsed = time.time() - start_time
                progress_pct = ((current_key - self.min_key) / range_size * 100)
                
                if elapsed > 0:
                    speed = total_checked / elapsed
                    print(f"📊 Progress: {progress_pct:.1f}% | Speed: {speed:,.0f} keys/s")
                    print(f"   Elapsed: {elapsed:.1f}s | Checked: {total_checked:,}")
            
            # Jika selesai tanpa menemukan
            if not self.found:
                self.result_queue.put({
                    'gpu_id': self.gpu_id,
                    'status': 'COMPLETED',
                    'keys_checked': total_checked,
                    'time_elapsed': time.time() - start_time
                })
                
        except Exception as e:
            print(f"❌ GPU {self.gpu_id} Error: {e}")
            traceback.print_exc()
            self.result_queue.put({
                'gpu_id': self.gpu_id,
                'status': 'ERROR',
                'error': str(e)
            })

# ==================== DIRECT BSGS APPROACH ====================
def direct_bsgs_search():
    """Pendekatan langsung dengan parameter yang tepat"""
    print("\n" + "="*70)
    print("DIRECT BSGS SEARCH FOR SMALL RANGE")
    print("="*70)
    
    # Load library
    bt2 = load_bt2_library()
    
    # Target pubkey
    target_pubkey_hex = "02CEB6CBBCDBDF5EF7150682150F4CE2C6F4807B349827DCDBDD1F2EFA885A2630"
    
    # Convert ke uncompressed
    P = pubkey_to_uncompressed_bytes(target_pubkey_hex)
    
    # Hitung parameter untuk range 20-bit
    min_key = int(MIN_RANGE, 16)
    max_key = int(MAX_RANGE, 16)
    range_size = max_key - min_key
    
    # Untuk range kecil, gunakan BP_SIZE yang sangat kecil
    bp_size = 100  # Cukup kecil untuk range 20-bit
    gpu_bits = int(math.log2(bp_size))
    
    print(f"\n🔧 Search Parameters:")
    print(f"  Range: {hex(min_key)} to {hex(max_key)}")
    print(f"  Size: {range_size:,} keys ({range_size.bit_length()}-bit)")
    print(f"  BP Size: {bp_size:,}")
    print(f"  GPU Bits: {gpu_bits}")
    
    # Generate P3 table
    print(f"\n🔧 Generating P3 table...")
    P3 = generate_p3_table_fast(P, bp_size)
    
    # Setup GPU parameters konservatif
    threads = 32
    blocks = 4
    points = 64  # Sangat kecil untuk range kecil
    
    print(f"\n🚀 Starting BSGS Search...")
    start_time = time.time()
    
    keyspace = f"{hex(min_key)[2:].zfill(16)}:{hex(max_key)[2:].zfill(16)}"
    
    print(f"📤 Calling bsgsGPU with:")
    print(f"  threads={threads}, blocks={blocks}, points={points}")
    print(f"  gpu_bits={gpu_bits}, device=0")
    print(f"  P3 points={len(P3)//65}, bp_size={bp_size}")
    print(f"  keyspace={keyspace}")
    
    try:
        res_ptr = bt2.bsgsGPU(
            ctypes.c_uint32(threads),
            ctypes.c_uint32(blocks),
            ctypes.c_uint32(points),
            ctypes.c_uint32(gpu_bits),
            ctypes.c_int(0),
            ctypes.c_char_p(P3),
            ctypes.c_uint32(len(P3) // 65),
            ctypes.c_char_p(keyspace.encode('utf8')),
            ctypes.c_char_p(str(bp_size).encode('utf8'))
        )
        
        result = (ctypes.cast(res_ptr, ctypes.c_char_p).value)
        bt2.free_memory(res_ptr)
        
        elapsed = time.time() - start_time
        
        if result:
            result_str = result.decode('utf8')
            print(f"\n✅ BSGS completed in {elapsed:.2f}s")
            print(f"📝 Result: {result_str}")
            
            # Verifikasi kandidat
            if result_str and len(result_str) >= 64:
                candidate = result_str[:64]
                print(f"\n🔍 Verifying candidate: {candidate[:16]}...")
                
                if verify_private_key(candidate, TARGET_ADDR):
                    print(f"\n🎉🎉🎉 KEY FOUND! 🎉🎉🎉")
                    print(f"Private Key: {candidate}")
                    with open('found_key.txt', 'w') as f:
                        f.write(candidate)
                    return True
                else:
                    print(f"⚠️ False positive")
        else:
            print(f"\n❌ No key found in range")
            
    except Exception as e:
        print(f"\n❌ BSGS Error: {e}")
        traceback.print_exc()
    
    return False

# ==================== MAIN PROGRAM ====================
if __name__ == "__main__":
    print('\n' + '='*70)
    print('BITCOIN PRIVATE KEY SEARCH - SMALL RANGE OPTIMIZED')
    print('='*70)
    
    # Pilih metode
    print("\n1. Direct BSGS (single GPU, small range)")
    print("2. Multi-GPU BSGS")
    
    choice = input("\nSelect method (1 or 2): ").strip()
    
    if choice == "1":
        # Metode langsung untuk range kecil
        success = direct_bsgs_search()
        
        if not success:
            print("\n" + "="*70)
            print("FALLBACK TO SIMPLE BRUTE FORCE")
            print("="*70)
            
            # Fallback ke brute force sederhana
            min_key = int(MIN_RANGE, 16)
            max_key = int(MAX_RANGE, 16)
            
            print(f"\n🔍 Brute forcing {hex(min_key)} to {hex(max_key)}")
            print(f"   Total keys: {(max_key-min_key):,}")
            
            start_time = time.time()
            keys_checked = 0
            
            for key_int in range(min_key, max_key + 1):
                key_hex = hex(key_int)[2:].zfill(64)
                
                if verify_private_key(key_hex, TARGET_ADDR):
                    print(f"\n🎉 KEY FOUND! {key_hex}")
                    with open('found_key.txt', 'w') as f:
                        f.write(key_hex)
                    break
                    
                keys_checked += 1
                
                if keys_checked % 10000 == 0:
                    elapsed = time.time() - start_time
                    if elapsed > 0:
                        speed = keys_checked / elapsed
                        progress = (key_int - min_key) / (max_key - min_key) * 100
                        print(f"Progress: {progress:.1f}% | Speed: {speed:.0f} keys/s")
            
            elapsed = time.time() - start_time
            print(f"\n⏱️  Completed in {elapsed:.1f}s")
            print(f"📊 Keys checked: {keys_checked:,}")
        
    elif choice == "2":
        # Multi-GPU approach
        mp.set_start_method('spawn', force=True)
        
        # Inisialisasi manager
        cuda.init()
        num_gpus = cuda.Device.count()
        print(f"\n🔧 Found {num_gpus} GPU(s)")
        
        # Setup search
        min_int = int(MIN_RANGE, 16)
        max_int = int(MAX_RANGE, 16)
        total_keys = max_int - min_int
        
        print(f"\n🎯 Target: {TARGET_ADDR}")
        print(f"🔍 Range: {MIN_RANGE} to {MAX_RANGE}")
        print(f"📊 Total keys: {total_keys:,}")
        
        # Start workers
        processes = []
        result_queue = mp.Queue()
        
        for gpu_id in range(min(num_gpus, 1)):  # Hanya GPU 0 untuk range kecil
            p = mp.Process(
                target=worker_wrapper,
                args=(gpu_id, min_int, max_int, TARGET_ADDR, result_queue)
            )
            p.daemon = True
            p.start()
            processes.append(p)
            time.sleep(1)
        
        # Monitor results
        found = False
        start_time = time.time()
        
        try:
            while not found:
                try:
                    res = result_queue.get(timeout=5)
                    
                    if res['status'] == 'FOUND':
                        found = True
                        print(f"\n🎉 KEY FOUND BY GPU {res['gpu_id']}!")
                        print(f"Key: {res['private_key']}")
                        
                    elif res['status'] == 'COMPLETED':
                        print(f"✅ GPU {res['gpu_id']}: Completed")
                        
                    elif res['status'] == 'ERROR':
                        print(f"❌ GPU {res['gpu_id']}: {res['error']}")
                        
                except:
                    if not any(p.is_alive() for p in processes):
                        break
            
            elapsed = time.time() - start_time
            print(f"\n⏱️  Total time: {elapsed:.1f}s")
            
        except KeyboardInterrupt:
            print("\n⚠️ Interrupted by user")
        finally:
            for p in processes:
                if p.is_alive():
                    p.terminate()
    
    else:
        print("❌ Invalid choice")

def worker_wrapper(gpu_id, min_k, max_k, target_addr, q):
    os.environ['CUDA_VISIBLE_DEVICES'] = str(gpu_id)
    worker = GPUWorkerOptimized(gpu_id, min_k, max_k, target_addr, q)
    worker.run()
