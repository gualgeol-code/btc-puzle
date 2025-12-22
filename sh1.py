# -*- coding: utf-8 -*-
"""
btcshort.py - GPU Bitcoin Private Key Search dengan Integrasi bt2.so
Menggunakan library bt2.so untuk operasi ECC GPU yang lebih cepat
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

# ==================== INSTALL PYCYPTODOME IF NOT AVAILABLE ====================
try:
    from Crypto.Hash import RIPEMD160
    RIPEMD160_AVAILABLE = True
    print("✅ pycryptodome RIPEMD160 available")
except ImportError:
    print("⚠️ pycryptodome not available, installing...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome"])
    from Crypto.Hash import RIPEMD160
    RIPEMD160_AVAILABLE = True
    print("✅ pycryptodome RIPEMD160 installed")

# ==================== KONFIGURASI ====================
MIN_RANGE = "100000"  # Start range (Hex) - diperkecil untuk testing
MAX_RANGE = "1FFFFF"  # End range (Hex)

TARGET_ADDR = "1HsMJxNiV7TLxmoF6uJNkydxPFDog4NQum"  # Alamat target

USE_ALL_GPUS = True
GPU_IDS = [0] if not USE_ALL_GPUS else list(range(cuda.Device.count()))

# Konfigurasi bt2.so
BT2_GPU_THREADS = 64
BT2_GPU_BLOCKS = 10
BT2_GPU_POINTS = 256
BT2_BP_TABLE_SIZE = 50000  # Diperkecil untuk range kecil

WINDOW_SIZE = 4
USE_BT2_LIBRARY = True  # Gunakan bt2.so untuk operasi GPU
USE_CUDA_KERNEL = False  # Nonaktifkan kernel CUDA custom

# ==================== FUNGSI RIPEMD160 YANG BENAR ====================
def ripemd160_hash(data):
    """Implementasi RIPEMD160 yang benar menggunakan pycryptodome"""
    h = RIPEMD160.new()
    h.update(data)
    return h.digest()

# ==================== BT2 LIBRARY FUNCTIONS ====================
def decompress_pubkey(compressed_pubkey_hex):
    """Decompress compressed public key (02/03 prefix)"""
    if not compressed_pubkey_hex.startswith(('02', '03')):
        raise ValueError("Not a compressed public key")
    
    # Parse x coordinate
    x_hex = compressed_pubkey_hex[2:]
    x = int(x_hex, 16)
    
    # Curve parameters
    curve = SECP256k1.curve
    p = curve.p()
    
    # Calculate y^2 = x^3 + 7 (untuk secp256k1)
    y_sq = (pow(x, 3, p) + 7) % p
    
    # Calculate square root mod p (p ≡ 3 mod 4)
    y = pow(y_sq, (p + 1) // 4, p)
    
    # Check parity
    if (y % 2) != (int(compressed_pubkey_hex[:2], 16) % 2):
        y = p - y
    
    return x, y

def pubkey_to_uncompressed_bytes(pubkey_hex):
    """Convert pubkey hex ke uncompressed bytes"""
    if len(pubkey_hex) == 130 and pubkey_hex.startswith('04'):
        # Already uncompressed
        return bytes.fromhex(pubkey_hex)
    elif len(pubkey_hex) == 66 and pubkey_hex.startswith(('02', '03')):
        # Compressed - decompress
        x, y = decompress_pubkey(pubkey_hex)
        return bytes.fromhex(f"04{hex(x)[2:].zfill(64)}{hex(y)[2:].zfill(64)}")
    else:
        raise ValueError(f"Invalid public key format: {pubkey_hex[:20]}...")

def generate_p3_table(pubkey_bytes, bp_size):
    """Generate P3 table untuk BSGS algorithm menggunakan bt2"""
    print(f"Generating P3 table dengan {bp_size:,} points...")
    
    # Gunakan secp256k1_lib jika tersedia
    try:
        import secp256k1_lib as ice
        G = ice.scalar_multiplication(1)
        P3 = ice.point_loop_addition(bp_size, pubkey_bytes, G)
        print(f"P3 table generated: {len(P3)} bytes ({len(P3)//65} points)")
        return P3
    except ImportError:
        print("⚠️ secp256k1_lib not available, using fallback method")
        # Fallback: generate secara manual
        curve = SECP256k1
        G = curve.generator
        
        # Parse pubkey
        if pubkey_bytes[0] == 0x04:
            x = int(pubkey_bytes[1:33].hex(), 16)
            y = int(pubkey_bytes[33:].hex(), 16)
            P = ecdsa.ellipticcurve.Point(curve.curve, x, y)
        else:
            raise ValueError("Uncompressed pubkey required")
        
        # Generate table (sederhana, untuk testing)
        points = []
        for i in range(bp_size):
            point = P + (G * i)
            x_hex = format(point.x(), '064x')
            y_hex = format(point.y(), '064x')
            points.append(bytes.fromhex(f"04{x_hex}{y_hex}"))
        
        P3 = b''.join(points)
        print(f"P3 table generated (fallback): {len(P3)} bytes ({len(points)} points)")
        return P3

def bsgs_search_with_bt2(bt2_lib, P3, start_key, end_key, bp_size, gpu_id=0):
    """Lakukan pencarian menggunakan BSGS GPU dari bt2.so"""
    # Hitung gpu_bits
    gpu_bits = int(math.log2(bp_size))
    
    # Format keyspace
    keyspace = f"{hex(start_key)[2:]}:{hex(end_key)[2:]}"
    
    print(f"🔍 BSGS Search: {hex(start_key)} to {hex(end_key)}")
    print(f"   GPU Device: {gpu_id}, Bits: {gpu_bits}, BP Size: {bp_size:,}")
    
    # Panggil fungsi GPU
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
    
    # Dapatkan hasil
    result = (ctypes.cast(res_ptr, ctypes.c_char_p).value).decode('utf8')
    bt2_lib.free_memory(res_ptr)
    
    return result

# ==================== CUDA KERNEL (BACKUP) ====================
cuda_code = """
// Simplified CUDA kernel sebagai backup
#include <stdint.h>

__global__ void generate_keys(
    unsigned long long start_value,
    unsigned long long *results,
    unsigned long long num_keys
) {
    unsigned long long idx = threadIdx.x + blockIdx.x * blockDim.x;
    if (idx >= num_keys) return;
    
    results[idx] = start_value + idx;
}
"""

# ==================== VERIFICATION FUNCTIONS ====================
def is_valid_private_key_hex(private_key_hex):
    """Validasi private key sebelum verifikasi"""
    try:
        if not all(c in '0123456789abcdefABCDEF' for c in private_key_hex):
            return False
        
        if len(private_key_hex) != 64:
            return False
        
        priv_key_int = int(private_key_hex, 16)
        CURVE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8B0D1D0E8C
        
        if priv_key_int <= 0:
            return False
        if priv_key_int >= CURVE_N:
            return False
            
        return True
    except:
        return False

def verify_private_key(private_key_hex, target_address):
    """Verify if private key matches target address"""
    try:
        if not is_valid_private_key_hex(private_key_hex):
            return False
        
        priv_key_int = int(private_key_hex, 16)
        sk = ecdsa.SigningKey.from_secret_exponent(priv_key_int, curve=SECP256k1)
        vk = sk.get_verifying_key()
        
        # Compressed public key
        if vk.pubkey.point.y() % 2 == 0:
            public_key = b'\x02' + vk.to_string()[:32]
        else:
            public_key = b'\x03' + vk.to_string()[:32]
        
        # SHA256
        sha256 = hashlib.sha256(public_key).digest()
        
        # RIPEMD160
        hash160 = ripemd160_hash(sha256)
        
        # Bitcoin address
        version_hash = b'\x00' + hash160
        checksum = hashlib.sha256(hashlib.sha256(version_hash).digest()).digest()[:4]
        address_bytes = version_hash + checksum
        generated_address = base58.b58encode(address_bytes).decode()
        
        return generated_address == target_address
    except Exception as e:
        return False

def address_to_hash160(address):
    """Convert Bitcoin address ke hash160"""
    decoded = base58.b58decode(address)
    return decoded[1:-4]

def test_ripemd160():
    """Test our RIPEMD160 implementation"""
    print("\n🔧 Testing RIPEMD160 implementation...")
    
    test_cases = [
        (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
        (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    ]
    
    all_passed = True
    for data, expected in test_cases:
        result = ripemd160_hash(data).hex()
        passed = result == expected
        all_passed = all_passed and passed
        status = "✅" if passed else "❌"
        print(f"  {status} '{data.decode() if data else 'empty'}': {result}")
    
    if all_passed:
        print("  ✅ All RIPEMD160 tests passed!")
    else:
        print("  ❌ Some RIPEMD160 tests failed!")
    
    return all_passed

# ==================== GPU WORKER WITH BT2 ====================
class GPUWorkerBT2:
    def __init__(self, gpu_id, min_key, max_key, target_hash, result_queue):
        self.gpu_id = gpu_id
        self.min_key = min_key
        self.max_key = max_key
        self.target_hash = target_hash
        self.result_queue = result_queue
        self.found = False
        self.bt2_lib = None
        
    def run(self):
        try:
            # Set GPU device untuk CUDA
            cuda.init()
            device = cuda.Device(self.gpu_id)
            
            # Load bt2 library
            self.bt2_lib = load_bt2_library()
            
            print(f"🚀 GPU {self.gpu_id}: Initialized ({device.name()})")
            
            # Convert target address ke public key (harus diketahui)
            # Untuk demo, kita gunakan pubkey dari target address (harus diketahui sebelumnya)
            # Dalam implementasi nyata, perlu diketahui public key target
            target_pubkey_hex = "02CEB6CBBCDBDF5EF7150682150F4CE2C6F4807B349827DCDBDD1F2EFA885A2630"
            
            try:
                # Convert ke uncompressed bytes
                P = pubkey_to_uncompressed_bytes(target_pubkey_hex)
                
                # Generate P3 table
                P3 = generate_p3_table(P, BT2_BP_TABLE_SIZE)
                
                # Calculate optimal batch size
                total_keys = self.max_key - self.min_key
                batch_size = min(1000000, total_keys)  # Batasi batch size
                
                print(f"⚡ GPU {self.gpu_id}: Total keys: {total_keys:,}, Batch: {batch_size:,}")
                
                current_key = self.min_key
                total_checked = 0
                start_time = time.time()
                
                while current_key < self.max_key and not self.found:
                    batch_end = min(current_key + batch_size, self.max_key)
                    
                    # Lakukan pencarian dengan bt2
                    result = bsgs_search_with_bt2(
                        self.bt2_lib, P3, current_key, batch_end, 
                        BT2_BP_TABLE_SIZE, self.gpu_id
                    )
                    
                    if result and result != '':
                        print(f"🎯 GPU {self.gpu_id}: Candidate found: {result}")
                        
                        # Verifikasi candidate
                        if verify_private_key(result, TARGET_ADDR):
                            self.found = True
                            self.result_queue.put({
                                'gpu_id': self.gpu_id,
                                'private_key': result,
                                'status': 'FOUND'
                            })
                            print(f"🎉 GPU {self.gpu_id}: Found key: {result}")
                            break
                        else:
                            print(f"⚠️ GPU {self.gpu_id}: False positive: {result}")
                    
                    total_checked += (batch_end - current_key)
                    current_key = batch_end
                    
                    # Print progress
                    elapsed = time.time() - start_time
                    if elapsed > 0:
                        speed = total_checked / elapsed
                        progress = min(100.0, (current_key - self.min_key) / total_keys * 100)
                        
                        current_disp = hex(current_key)[2:].zfill(16)
                        print(f"GPU {self.gpu_id} | Speed: {speed/1_000:.1f} KKeys/s | "
                              f"Progress: {progress:.1f}% | Current: ...{current_disp[-8:]}")
                
                if not self.found:
                    self.result_queue.put({
                        'gpu_id': self.gpu_id,
                        'status': 'COMPLETED',
                        'keys_checked': total_checked
                    })
                    
            except Exception as e:
                print(f"❌ GPU {self.gpu_id}: Error in BSGS search: {e}")
                import traceback
                traceback.print_exc()
                self.result_queue.put({
                    'gpu_id': self.gpu_id,
                    'status': 'ERROR',
                    'error': str(e)
                })
                
        except Exception as e:
            print(f"❌ GPU {self.gpu_id}: Initialization error - {e}")
            self.result_queue.put({
                'gpu_id': self.gpu_id,
                'status': 'ERROR',
                'error': str(e)
            })

# ==================== MULTI-GPU MANAGER ====================
class MultiGPUManager:
    def __init__(self):
        cuda.init()
        self.num_gpus = cuda.Device.count()
        print(f"🔧 Found {self.num_gpus} GPU(s)")
        
        # Run tests
        print("\n🔧 Running tests...")
        ripemd160_ok = test_ripemd160()
        
        if not ripemd160_ok:
            print("❌ Critical tests failed. Exiting.")
            sys.exit(1)
    
    def start_search(self, target_addr):
        print(f"\n{'='*60}")
        print(f"🎯 TARGET ADDRESS: {target_addr}")
        print(f"🔍 SEARCH RANGE: {MIN_RANGE} to {MAX_RANGE}")
        print(f"🔄 USING BT2 LIBRARY: {USE_BT2_LIBRARY}")
        print(f"{'='*60}")
        
        try:
            target_hash = address_to_hash160(target_addr)
            print(f"📝 Target Hash160: {target_hash.hex()}")
        except Exception as e:
            print(f"❌ Initialization Error: {e}")
            return
        
        min_int = int(MIN_RANGE, 16)
        max_int = int(MAX_RANGE, 16)
        total_keys = max_int - min_int
        
        print(f"📊 Total keys to search: {total_keys:,}")
        
        gpu_ids = GPU_IDS if not USE_ALL_GPUS else list(range(self.num_gpus))
        if not gpu_ids:
            print("❌ No GPUs available")
            return
        
        print(f"🚀 Using {len(gpu_ids)} GPU(s): {gpu_ids}")
        print(f"⚙️ BT2 Config: {BT2_GPU_THREADS} threads, {BT2_GPU_BLOCKS} blocks")
        print(f"⚙️ BT2 Points: {BT2_GPU_POINTS}, BP Size: {BT2_BP_TABLE_SIZE:,}")
        
        range_per_gpu = total_keys // len(gpu_ids)
        processes = []
        result_queue = mp.Queue()
        
        for i, gpu_id in enumerate(gpu_ids):
            sub_min = min_int + (i * range_per_gpu)
            sub_max = sub_min + range_per_gpu if i < len(gpu_ids) - 1 else max_int
            sub_min = max(sub_min, min_int)
            sub_max = min(sub_max, max_int)
            
            p = mp.Process(
                target=worker_wrapper_bt2,
                args=(gpu_id, sub_min, sub_max, target_hash, result_queue)
            )
            p.daemon = True
            p.start()
            processes.append(p)
            time.sleep(0.5)
        
        print(f"\n🔍 Search started at {time.strftime('%H:%M:%S')}")
        print("Press Ctrl+C to stop\n")
        
        found = False
        completed = 0
        errors = 0
        start_time = time.time()
        
        try:
            while completed + errors < len(processes) and not found:
                try:
                    res = result_queue.get(timeout=10)
                    
                    if res['status'] == 'FOUND':
                        found = True
                        private_key = res['private_key']
                        print(f"\n{'='*60}")
                        print(f"🎉 KEY FOUND! GPU {res['gpu_id']} 🎉")
                        print(f"KEY: {private_key}")
                        print(f"{'='*60}")
                        with open('found_key.txt', 'w') as f:
                            f.write(private_key)
                        break
                        
                    elif res['status'] == 'COMPLETED':
                        completed += 1
                        print(f"✅ GPU {res['gpu_id']}: Completed ({res['keys_checked']:,} keys checked)")
                        
                    elif res['status'] == 'ERROR':
                        errors += 1
                        print(f"❌ GPU {res['gpu_id']}: Error - {res['error']}")
                        
                except:
                    if not any(p.is_alive() for p in processes):
                        break
                    continue
            
            elapsed = time.time() - start_time
            
            if not found:
                print(f"\n❌ Key not found in range {MIN_RANGE}-{MAX_RANGE}")
            
            print(f"\n📊 Summary:")
            print(f"  Time elapsed: {elapsed:.2f}s")
            print(f"  GPUs completed: {completed}/{len(gpu_ids)}")
            print(f"  GPUs with errors: {errors}")
            
        except KeyboardInterrupt:
            print("\n⚠️ Interrupted by user")
        finally:
            for p in processes:
                if p.is_alive():
                    p.terminate()

def worker_wrapper_bt2(gpu_id, min_k, max_k, t_hash, q):
    os.environ['CUDA_VISIBLE_DEVICES'] = str(gpu_id)
    worker = GPUWorkerBT2(gpu_id, min_k, max_k, t_hash, q)
    worker.run()

# ==================== CUDA BACKUP WORKER ====================
class GPUWorkerCUDA:
    def __init__(self, gpu_id, min_key, max_key, target_hash, result_queue):
        self.gpu_id = gpu_id
        self.min_key = min_key
        self.max_key = max_key
        self.target_hash = target_hash
        self.result_queue = result_queue
        self.found = False
        
    def run(self):
        context = None
        stream = None
        
        try:
            cuda.init()
            device = cuda.Device(self.gpu_id)
            context = device.make_context()
            
            print(f"🚀 GPU {self.gpu_id}: CUDA Initialized ({device.name()})")
            
            # Simple kernel untuk generate keys
            mod = SourceModule(cuda_code)
            generate_keys_kernel = mod.get_function("generate_keys")
            
            batch_size = 100000
            block_size = 256
            grid_size = (batch_size + block_size - 1) // block_size
            
            print(f"⚡ GPU {self.gpu_id}: Using CUDA backup method")
            
            current_key = self.min_key
            total_checked = 0
            start_time = time.time()
            
            while current_key < self.max_key and not self.found:
                actual_batch = min(batch_size, self.max_key - current_key)
                
                # Allocate memory
                keys_gpu = cuda.mem_alloc(actual_batch * 8)  # 8 bytes per uint64
                keys_host = np.zeros(actual_batch, dtype=np.uint64)
                
                # Generate keys
                generate_keys_kernel(
                    np.uint64(current_key),
                    keys_gpu,
                    np.uint64(actual_batch),
                    block=(block_size, 1, 1),
                    grid=(grid_size, 1)
                )
                
                # Copy back
                cuda.memcpy_dtoh(keys_host, keys_gpu)
                
                # Check each key
                for key_int in keys_host:
                    if key_int == 0:
                        continue
                    
                    key_hex = hex(key_int)[2:].zfill(64)
                    
                    if verify_private_key(key_hex, TARGET_ADDR):
                        self.found = True
                        self.result_queue.put({
                            'gpu_id': self.gpu_id,
                            'private_key': key_hex,
                            'status': 'FOUND'
                        })
                        print(f"🎉 GPU {self.gpu_id}: Found key: {key_hex}")
                        break
                
                total_checked += actual_batch
                current_key += actual_batch
                
                # Print progress
                elapsed = time.time() - start_time
                if elapsed > 0:
                    speed = total_checked / elapsed
                    progress = min(100.0, (current_key - self.min_key) / (self.max_key - self.min_key) * 100)
                    
                    print(f"GPU {self.gpu_id} | CUDA Speed: {speed/1_000:.1f} KKeys/s | "
                          f"Progress: {progress:.1f}%")
                
                if self.found:
                    break
            
            if not self.found:
                self.result_queue.put({
                    'gpu_id': self.gpu_id,
                    'status': 'COMPLETED',
                    'keys_checked': total_checked
                })
                
        except Exception as e:
            print(f"❌ GPU {self.gpu_id}: CUDA Error - {e}")
            self.result_queue.put({
                'gpu_id': self.gpu_id,
                'status': 'ERROR',
                'error': str(e)
            })
        finally:
            if context:
                context.pop()

# ==================== MAIN PROGRAM ====================
if __name__ == "__main__":
    mp.set_start_method('spawn', force=True)
    
    print('\n' + '='*70)
    print('BITCOIN PRIVATE KEY SEARCH - BT2 INTEGRATION')
    print('='*70)
    
    # Pilih metode berdasarkan konfigurasi
    if USE_BT2_LIBRARY:
        print("🔧 Using bt2.so library for GPU acceleration")
        manager = MultiGPUManager()
        manager.start_search(TARGET_ADDR)
    elif USE_CUDA_KERNEL:
        print("🔧 Using custom CUDA kernel (backup mode)")
        # Implementasi CUDA backup bisa ditambahkan di sini
        print("⚠️ CUDA backup mode not fully implemented")
    else:
        print("❌ No valid search method selected")
