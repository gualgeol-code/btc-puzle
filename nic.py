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
MIN_RANGE = "100000"  # Start range (Hex) - bisa disesuaikan
MAX_RANGE = "1FFFFF"  # End range (Hex)

TARGET_ADDR = "1HsMJxNiV7TLxmoF6uJNkydxPFDog4NQum"  # Alamat target

USE_ALL_GPUS = True
GPU_IDS = [0] if not USE_ALL_GPUS else list(range(cuda.Device.count()))

# Konfigurasi bt2.so
BT2_GPU_THREADS = 64
BT2_GPU_BLOCKS = 256
BT2_GPU_POINTS = 1024
BT2_BP_TABLE_SIZE = 5000000  # Ukuran tabel BSGS

WINDOW_SIZE = 4
USE_BT2_LIBRARY = True  # Gunakan bt2.so untuk operasi GPU
USE_CUDA_KERNEL = False  # Nonaktifkan kernel CUDA custom

# ==================== FUNGSI RIPEMD160 YANG BENAR ====================
def ripemd160_hash(data):
    """Implementasi RIPEMD160 yang benar menggunakan pycryptodome"""
    h = RIPEMD160.new()
    h.update(data)
    return h.digest()

# ==================== FUNGSI KONVERSI ADDRESS KE PUBKEY ====================
def get_pubkey_from_address(target_address, bloom_filename='pubs.bin'):
    """
    Mencari public key dari address dalam file bloom filter
    Format file bloom: pubs.bin (dari bxx.py)
    """
    try:
        # Hash160 dari target address
        decoded = base58.b58decode(target_address)
        target_hash160 = decoded[1:-4]  # Skip version byte and checksum
        
        print(f"🔍 Mencari pubkey untuk address: {target_address}")
        print(f"📝 Target Hash160: {target_hash160.hex()}")
        
        # Cari di file bloom filter
        if not os.path.exists(bloom_filename):
            print(f"⚠️ File {bloom_filename} tidak ditemukan")
            return None
        
        # Baca file bloom filter
        with open(bloom_filename, 'rb') as f:
            bloom_data = f.read()
        
        # Parse bloom filter
        # Format: [hash160][compressed_pubkey] berulang
        entry_size = 20 + 33  # 20 bytes hash160 + 33 bytes compressed pubkey
        
        if len(bloom_data) % entry_size != 0:
            print(f"⚠️ Format file {bloom_filename} tidak valid")
            return None
        
        num_entries = len(bloom_data) // entry_size
        print(f"📊 Total entries dalam bloom filter: {num_entries:,}")
        
        # Cari hash160 yang cocok
        for i in range(num_entries):
            offset = i * entry_size
            hash160_in_file = bloom_data[offset:offset+20]
            compressed_pubkey = bloom_data[offset+20:offset+53]
            
            if hash160_in_file == target_hash160:
                pubkey_hex = compressed_pubkey.hex()
                print(f"✅ Pubkey ditemukan: {pubkey_hex}")
                return pubkey_hex
        
        print(f"❌ Pubkey tidak ditemukan untuk address: {target_address}")
        return None
        
    except Exception as e:
        print(f"❌ Error mencari pubkey: {e}")
        import traceback
        traceback.print_exc()
        return None

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

# ==================== FUNGSI VALIDASI RANGE HEX ====================
def validate_hex_range(min_hex, max_hex):
    """Validasi dan konversi range hex ke integer"""
    try:
        min_int = int(min_hex, 16)
        max_int = int(max_hex, 16)
        
        if min_int <= 0:
            print(f"⚠️ MIN_RANGE terlalu kecil, menggunakan nilai minimum 1")
            min_int = 1
        
        CURVE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8B0D1D0E8C
        if max_int >= CURVE_N:
            print(f"⚠️ MAX_RANGE terlalu besar, menggunakan nilai maksimum {hex(CURVE_N-1)}")
            max_int = CURVE_N - 1
        
        if min_int >= max_int:
            print(f"❌ MIN_RANGE harus lebih kecil dari MAX_RANGE")
            return None, None
        
        total_keys = max_int - min_int
        print(f"📊 Valid range: {hex(min_int)} to {hex(max_int)}")
        print(f"📊 Total keys to search: {total_keys:,} ({total_keys:#x})")
        
        return min_int, max_int
        
    except ValueError as e:
        print(f"❌ Format hex tidak valid: {e}")
        return None, None

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
    def __init__(self, gpu_id, min_key, max_key, target_pubkey_hex, result_queue):
        self.gpu_id = gpu_id
        self.min_key = min_key
        self.max_key = max_key
        self.target_pubkey_hex = target_pubkey_hex
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
            
            try:
                # Convert ke uncompressed bytes
                P = pubkey_to_uncompressed_bytes(self.target_pubkey_hex)
                
                # Hitung optimal BP_SIZE berdasarkan range
                total_keys = self.max_key - self.min_key
                bp_size = min(BT2_BP_TABLE_SIZE, max(1000, int(math.sqrt(total_keys))))
                
                # Generate P3 table
                P3 = generate_p3_table(P, bp_size)
                
                # Calculate optimal batch size
                batch_size = min(1000000, total_keys)  # Batasi batch size
                
                print(f"⚡ GPU {self.gpu_id}: Total keys: {total_keys:,}, Batch: {batch_size:,}, BP Size: {bp_size:,}")
                
                current_key = self.min_key
                total_checked = 0
                start_time = time.time()
                
                while current_key < self.max_key and not self.found:
                    batch_end = min(current_key + batch_size, self.max_key)
                    
                    # Lakukan pencarian dengan bt2
                    result = bsgs_search_with_bt2(
                        self.bt2_lib, P3, current_key, batch_end, 
                        bp_size, self.gpu_id
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
    
    def start_search(self, target_addr, min_hex, max_hex):
        print(f"\n{'='*60}")
        print(f"🎯 TARGET ADDRESS: {target_addr}")
        print(f"🔍 SEARCH RANGE: {min_hex} to {max_hex}")
        print(f"🔄 USING BT2 LIBRARY: {USE_BT2_LIBRARY}")
        print(f"{'='*60}")
        
        # Validasi range
        min_int, max_int = validate_hex_range(min_hex, max_hex)
        if min_int is None or max_int is None:
            print("❌ Invalid range specified")
            return
        
        # Cari public key dari target address
        print("\n🔍 Mencari public key dari address...")
        target_pubkey_hex = get_pubkey_from_address(target_addr)
        
        if not target_pubkey_hex:
            print("❌ Tidak dapat menemukan public key untuk address tersebut")
            print("⚠️ Pastikan file 'pubs.bin' tersedia dan berisi data yang benar")
            return
        
        print(f"✅ Menggunakan public key: {target_pubkey_hex}")
        
        total_keys = max_int - min_int
        
        gpu_ids = GPU_IDS if not USE_ALL_GPUS else list(range(self.num_gpus))
        if not gpu_ids:
            print("❌ No GPUs available")
            return
        
        print(f"\n🚀 Using {len(gpu_ids)} GPU(s): {gpu_ids}")
        print(f"⚙️ BT2 Config: {BT2_GPU_THREADS} threads, {BT2_GPU_BLOCKS} blocks")
        print(f"⚙️ BT2 Points: {BT2_GPU_POINTS}")
        
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
                args=(gpu_id, sub_min, sub_max, target_pubkey_hex, result_queue)
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
                print(f"\n❌ Key not found in range {min_hex}-{max_hex}")
            
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

def worker_wrapper_bt2(gpu_id, min_k, max_k, target_pubkey_hex, q):
    os.environ['CUDA_VISIBLE_DEVICES'] = str(gpu_id)
    worker = GPUWorkerBT2(gpu_id, min_k, max_k, target_pubkey_hex, q)
    worker.run()

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
        manager.start_search(TARGET_ADDR, MIN_RANGE, MAX_RANGE)
    elif USE_CUDA_KERNEL:
        print("🔧 Using custom CUDA kernel (backup mode)")
        # Implementasi CUDA backup bisa ditambahkan di sini
        print("⚠️ CUDA backup mode not fully implemented")
    else:
        print("❌ No valid search method selected")
