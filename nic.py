# -*- coding: utf-8 -*-
"""
btcshort.py - GPU Bitcoin Private Key Search dengan Integrasi bt2.so
Upgraded version untuk range besar/kecil dengan target public key
"""

import os
import sys
import time
import ctypes
import random
import math
import platform
import multiprocessing as mp
import argparse

# ==================== IMPORT LIBRARIES ====================
try:
    import bit
    BIT_AVAILABLE = True
except ImportError:
    print("⚠️ bit library not available, install: pip install bit")
    BIT_AVAILABLE = False

try:
    import secp256k1_lib as ice
    ICE_AVAILABLE = True
except ImportError:
    print("⚠️ secp256k1_lib not available")
    ICE_AVAILABLE = False

# ==================== KONFIGURASI ====================
# Target public key (compressed)
TARGET_PUBKEY = "033c4a45cbd643ff97d77f41ea37e843648d50fd894b864b0d52febc62f6454f7c"

# Range default (hex) - bisa disesuaikan
MIN_RANGE = "1"
MAX_RANGE = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140"

# Konfigurasi GPU
USE_ALL_GPUS = True
GPU_THREADS = 64
GPU_BLOCKS = 10
GPU_POINTS = 256
BP_TABLE_SIZE = 500000  # Untuk range besar, bisa ditingkatkan
RANDOM_MODE = True  # Mode random dalam range

# Output file
OUTPUT_FILE = "found_keys.txt"

# ==================== LOAD BT2 LIBRARY ====================
def load_bt2_library():
    """Load bt2.so library untuk operasi BSGS GPU"""
    if platform.system().lower().startswith('win'):
        libfile = 'bt2.dll'
    elif platform.system().lower().startswith('lin'):
        libfile = 'bt2.so'
    else:
        print('[-] Unsupported Platform')
        sys.exit(1)
    
    if not os.path.isfile(libfile):
        print(f'❌ File {libfile} not found')
        print(f'   Please ensure {libfile} is in the current directory')
        sys.exit(1)
    
    pathlib = os.path.realpath(libfile)
    bt2 = ctypes.CDLL(pathlib)
    
    # Define argument types untuk fungsi bsgsGPU (sesuai bxx.py)
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
    
    print(f"✅ Loaded {libfile} library for GPU BSGS operations")
    return bt2

# ==================== FUNGSI UTILITAS ====================
def pubkey_to_uncompressed(pubkey_hex):
    """Convert public key (compressed/uncompressed) ke format uncompressed bytes"""
    if len(pubkey_hex) == 130 and pubkey_hex.startswith('04'):
        # Already uncompressed
        return bytes.fromhex(pubkey_hex)
    elif len(pubkey_hex) == 66 and pubkey_hex.startswith(('02', '03')):
        # Compressed - menggunakan bit library untuk decompress
        if BIT_AVAILABLE:
            pubkey = bit.Key(pubkey_hex)
            uncompressed = pubkey._pk.public_key.format(compressed=False)
            return bytes.fromhex(uncompressed.hex())
        else:
            # Fallback manual decompression
            from ecdsa import SECP256k1, ellipticcurve
            curve = SECP256k1.curve
            p = curve.p()
            
            x = int(pubkey_hex[2:], 16)
            y_sq = (pow(x, 3, p) + 7) % p
            y = pow(y_sq, (p + 1) // 4, p)
            
            if (y % 2) != (int(pubkey_hex[:2], 16) % 2):
                y = p - y
            
            uncompressed = f"04{hex(x)[2:].zfill(64)}{hex(y)[2:].zfill(64)}"
            return bytes.fromhex(uncompressed)
    else:
        raise ValueError(f"Invalid public key format: {pubkey_hex}")

def generate_p3_table(pubkey_bytes, bp_size):
    """Generate P3 table untuk BSGS algorithm (sesuai bxx.py)"""
    print(f"Generating P3 table dengan {bp_size:,} points...")
    
    if ICE_AVAILABLE:
        # Menggunakan secp256k1_lib seperti di bxx.py
        G = ice.scalar_multiplication(1)
        P3 = ice.point_loop_addition(bp_size, pubkey_bytes, G)
        print(f"✅ P3 table generated: {len(P3)} bytes ({len(P3)//65} points)")
        return P3
    else:
        print("❌ secp256k1_lib not available. Please install it.")
        sys.exit(1)

def calculate_gpu_bits(bp_size):
    """Calculate gpu_bits dari bp_size"""
    return int(math.log2(bp_size))

def generate_random_range(min_val, max_val):
    """Generate random range untuk pencarian"""
    k1 = random.SystemRandom().randint(min_val, max_val)
    k2 = random.SystemRandom().randint(min_val, max_val)
    if k1 > k2:
        k1, k2 = k2, k1
    return k1, k2

# ==================== GPU WORKER CLASS ====================
class BSGSGPUWorker:
    def __init__(self, gpu_id, target_pubkey, min_range, max_range, 
                 output_file, random_mode=False):
        self.gpu_id = gpu_id
        self.target_pubkey = target_pubkey
        self.min_range = min_range
        self.max_range = max_range
        self.output_file = output_file
        self.random_mode = random_mode
        self.bt2_lib = None
        self.P3 = None
        self.bp_size = BP_TABLE_SIZE
        self.gpu_bits = calculate_gpu_bits(self.bp_size)
        
        # Konfigurasi GPU
        self.gpu_threads = GPU_THREADS
        self.gpu_blocks = GPU_BLOCKS
        self.gpu_points = GPU_POINTS
        
    def initialize(self):
        """Initialize GPU worker"""
        print(f"🔄 GPU {self.gpu_id}: Initializing...")
        
        # Load bt2 library
        self.bt2_lib = load_bt2_library()
        
        # Convert pubkey to uncompressed format
        pubkey_bytes = pubkey_to_uncompressed(self.target_pubkey)
        
        # Generate P3 table
        self.P3 = generate_p3_table(pubkey_bytes, self.bp_size)
        
        print(f"✅ GPU {self.gpu_id}: Initialized successfully")
        print(f"   Range: {hex(self.min_range)} - {hex(self.max_range)}")
        print(f"   Random mode: {self.random_mode}")
        
    def search_range(self, start_key, end_key):
        """Search dalam range tertentu menggunakan BSGS GPU"""
        # Format keyspace untuk bt2
        keyspace = f"{hex(start_key)[2:]}:{hex(end_key)[2:]}"
        
        # Panggil fungsi bsgsGPU dari library
        res_ptr = self.bt2_lib.bsgsGPU(
            ctypes.c_uint32(self.gpu_threads),
            ctypes.c_uint32(self.gpu_blocks),
            ctypes.c_uint32(self.gpu_points),
            ctypes.c_uint32(self.gpu_bits),
            ctypes.c_int(self.gpu_id),
            ctypes.c_char_p(self.P3),
            ctypes.c_uint32(len(self.P3) // 65),
            ctypes.c_char_p(keyspace.encode('utf8')),
            ctypes.c_char_p(str(self.bp_size).encode('utf8'))
        )
        
        # Decode hasil
        result = (ctypes.cast(res_ptr, ctypes.c_char_p).value)
        if result:
            result_str = result.decode('utf8')
        else:
            result_str = ""
        
        # Free memory
        self.bt2_lib.free_memory(res_ptr)
        
        return result_str
    
    def verify_and_save_key(self, found_pvk_hex):
        """Verify found private key dan simpan ke file"""
        if not found_pvk_hex:
            return False
            
        try:
            # Verifikasi private key menghasilkan public key yang sesuai
            if BIT_AVAILABLE:
                found_key = bit.Key.from_hex(found_pvk_hex)
                found_pubkey = found_key.public_key
                
                # Bandingkan dengan target pubkey (dalam format compressed)
                target_key = bit.Key(self.target_pubkey)
                
                if found_pubkey == target_key.public_key:
                    print(f"\n{'='*60}")
                    print(f"🎉 KEY FOUND! GPU {self.gpu_id} 🎉")
                    print(f"Private Key: {found_pvk_hex}")
                    print(f"Public Key: {found_pubkey}")
                    print(f"{'='*60}")
                    
                    # Save to file
                    with open(self.output_file, "a") as f:
                        f.write(f"Private Key: {found_pvk_hex}\n")
                        f.write(f"Public Key: {found_pubkey}\n")
                        f.write(f"Found by GPU: {self.gpu_id}\n")
                        f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"{'='*60}\n")
                    
                    return True
            else:
                # Fallback verification
                print(f"⚠️ bit library not available, skipping verification")
                print(f"Candidate key: {found_pvk_hex}")
                
                # Save candidate anyway
                with open(self.output_file, "a") as f:
                    f.write(f"Candidate Private Key: {found_pvk_hex}\n")
                    f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"{'='*60}\n")
                
                return True
                
        except Exception as e:
            print(f"❌ Error verifying key: {e}")
            
        return False
    
    def run_continuous_search(self, result_queue):
        """Run continuous search dalam loop"""
        total_keys_checked = 0
        start_time = time.time()
        
        try:
            self.initialize()
            
            print(f"🚀 GPU {self.gpu_id}: Starting search...")
            
            while True:
                # Tentukan range pencarian
                if self.random_mode:
                    start_key, end_key = generate_random_range(self.min_range, self.max_range)
                else:
                    # Sequential search dalam sub-range
                    range_size = 1000000  # Size per batch
                    current_batch = total_keys_checked // range_size
                    start_key = self.min_range + (current_batch * range_size)
                    end_key = min(start_key + range_size, self.max_range)
                    
                    if start_key >= self.max_range:
                        print(f"✅ GPU {self.gpu_id}: Completed full range")
                        break
                
                # Lakukan pencarian
                batch_start_time = time.time()
                found_pvk = self.search_range(start_key, end_key)
                batch_time = time.time() - batch_start_time
                
                # Hitung statistik
                batch_size = end_key - start_key
                if batch_time > 0:
                    speed = batch_size / batch_time
                else:
                    speed = 0
                
                total_keys_checked += batch_size
                
                # Tampilkan progress
                elapsed = time.time() - start_time
                if elapsed > 0:
                    avg_speed = total_keys_checked / elapsed
                    progress_pct = ((start_key - self.min_range) / 
                                   (self.max_range - self.min_range)) * 100
                    
                    print(f"GPU {self.gpu_id} | "
                          f"Range: {hex(start_key)[:12]}... - {hex(end_key)[:12]}... | "
                          f"Speed: {speed:,.0f} keys/s | "
                          f"Total: {total_keys_checked:,} | "
                          f"Progress: {min(progress_pct, 100):.2f}%")
                
                # Cek jika key ditemukan
                if found_pvk and found_pvk != '':
                    if self.verify_and_save_key(found_pvk):
                        result_queue.put({
                            'gpu_id': self.gpu_id,
                            'private_key': found_pvk,
                            'status': 'FOUND'
                        })
                        return
                
                # Kirim update progress
                result_queue.put({
                    'gpu_id': self.gpu_id,
                    'status': 'PROGRESS',
                    'keys_checked': total_keys_checked,
                    'speed': avg_speed if 'avg_speed' in locals() else 0
                })
                
                # Jika sequential mode dan sudah mencapai akhir
                if not self.random_mode and end_key >= self.max_range:
                    break
                    
                # Small delay untuk mencegah CPU overload
                time.sleep(0.1)
            
            # Jika selesai tanpa menemukan
            result_queue.put({
                'gpu_id': self.gpu_id,
                'status': 'COMPLETED',
                'keys_checked': total_keys_checked
            })
            
        except Exception as e:
            print(f"❌ GPU {self.gpu_id}: Error - {e}")
            import traceback
            traceback.print_exc()
            
            result_queue.put({
                'gpu_id': self.gpu_id,
                'status': 'ERROR',
                'error': str(e)
            })

# ==================== MULTI-GPU MANAGER ====================
class MultiGPUManager:
    def __init__(self, target_pubkey, min_range_hex, max_range_hex, 
                 output_file, random_mode=False):
        self.target_pubkey = target_pubkey
        self.min_range = int(min_range_hex, 16)
        self.max_range = int(max_range_hex, 16)
        self.output_file = output_file
        self.random_mode = random_mode
        
        # Detect available GPUs
        try:
            import pycuda.driver as cuda
            cuda.init()
            self.num_gpus = cuda.Device.count()
            print(f"🔧 Found {self.num_gpus} GPU(s)")
        except:
            print("⚠️ pycuda not available, assuming 1 GPU")
            self.num_gpus = 1
    
    def start_search(self):
        """Start multi-GPU search"""
        print(f"\n{'='*70}")
        print("BITCOIN PRIVATE KEY SEARCH - BSGS GPU VERSION")
        print(f"{'='*70}")
        print(f"🎯 Target Public Key: {self.target_pubkey}")
        print(f"🔍 Search Range: {hex(self.min_range)} - {hex(self.max_range)}")
        print(f"📊 Range Size: {self.max_range - self.min_range:,} keys")
        print(f"🔄 Random Mode: {self.random_mode}")
        print(f"💾 Output File: {self.output_file}")
        print(f"{'='*70}\n")
        
        # Validasi range
        if self.min_range >= self.max_range:
            print("❌ Invalid range: min must be less than max")
            return
        
        # Setup multiprocessing
        result_queue = mp.Queue()
        processes = []
        
        # Tentukan GPU IDs yang akan digunakan
        if USE_ALL_GPUS and self.num_gpus > 1:
            gpu_ids = list(range(self.num_gpus))
        else:
            gpu_ids = [0]
        
        print(f"🚀 Using {len(gpu_ids)} GPU(s): {gpu_ids}")
        
        # Hitung sub-range per GPU (untuk non-random mode)
        if not self.random_mode:
            range_per_gpu = (self.max_range - self.min_range) // len(gpu_ids)
        
        # Start worker processes
        for i, gpu_id in enumerate(gpu_ids):
            if self.random_mode:
                # Random mode: semua GPU search di seluruh range
                worker_min = self.min_range
                worker_max = self.max_range
            else:
                # Sequential mode: bagi range
                worker_min = self.min_range + (i * range_per_gpu)
                worker_max = worker_min + range_per_gpu if i < len(gpu_ids) - 1 else self.max_range
            
            # Create worker process
            worker = BSGSGPUWorker(
                gpu_id=gpu_id,
                target_pubkey=self.target_pubkey,
                min_range=worker_min,
                max_range=worker_max,
                output_file=self.output_file,
                random_mode=self.random_mode
            )
            
            p = mp.Process(
                target=worker_wrapper,
                args=(worker, result_queue)
            )
            p.daemon = True
            p.start()
            processes.append(p)
            
            print(f"✅ Started GPU {gpu_id} worker (PID: {p.pid})")
            time.sleep(1)  # Delay antar startup
        
        print(f"\n🔍 Search started at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("Press Ctrl+C to stop\n")
        
        # Monitor results
        self.monitor_results(processes, result_queue)
    
    def monitor_results(self, processes, result_queue):
        """Monitor hasil dari semua worker processes"""
        found = False
        completed = 0
        errors = 0
        start_time = time.time()
        last_update = time.time()
        
        # Statistics
        total_keys_checked = 0
        speeds = []
        
        try:
            while not found and (completed + errors) < len(processes):
                try:
                    # Check for results
                    if result_queue.empty():
                        time.sleep(0.5)
                        continue
                    
                    res = result_queue.get(timeout=1)
                    
                    if res['status'] == 'FOUND':
                        found = True
                        print(f"\n{'🎉'*30}")
                        print(f"KEY FOUND BY GPU {res['gpu_id']}!")
                        print(f"Private Key: {res['private_key']}")
                        print(f"{'🎉'*30}")
                        
                        # Terminate other processes
                        for p in processes:
                            if p.is_alive():
                                p.terminate()
                        break
                    
                    elif res['status'] == 'PROGRESS':
                        # Update statistics
                        total_keys_checked += res.get('keys_checked', 0)
                        if 'speed' in res and res['speed'] > 0:
                            speeds.append(res['speed'])
                        
                        # Periodic update display
                        if time.time() - last_update > 5:
                            elapsed = time.time() - start_time
                            if speeds:
                                avg_speed = sum(speeds) / len(speeds)
                            else:
                                avg_speed = 0
                            
                            print(f"\n📊 Overall Status:")
                            print(f"  Time elapsed: {elapsed:.1f}s")
                            print(f"  Total keys checked: {total_keys_checked:,}")
                            print(f"  Average speed: {avg_speed:,.0f} keys/s")
                            print(f"  Active workers: {len([p for p in processes if p.is_alive()])}")
                            print(f"  Completed: {completed}, Errors: {errors}")
                            
                            # Estimate time remaining
                            if avg_speed > 0 and not self.random_mode:
                                remaining_keys = (self.max_range - self.min_range) - total_keys_checked
                                if remaining_keys > 0:
                                    hours_remaining = remaining_keys / avg_speed / 3600
                                    print(f"  Estimated time remaining: {hours_remaining:.1f} hours")
                            
                            last_update = time.time()
                    
                    elif res['status'] == 'COMPLETED':
                        completed += 1
                        print(f"✅ GPU {res['gpu_id']}: Completed ({res.get('keys_checked', 0):,} keys checked)")
                    
                    elif res['status'] == 'ERROR':
                        errors += 1
                        print(f"❌ GPU {res['gpu_id']}: Error - {res.get('error', 'Unknown error')}")
                
                except KeyboardInterrupt:
                    print("\n⚠️ Interrupted by user")
                    break
                except:
                    # Timeout or other queue error
                    if not any(p.is_alive() for p in processes):
                        break
                    continue
            
            # Final statistics
            elapsed = time.time() - start_time
            
            print(f"\n{'='*70}")
            print("SEARCH COMPLETED")
            print(f"{'='*70}")
            
            if found:
                print("✅ KEY FOUND! Check output file for details.")
            else:
                print("❌ Key not found in the specified range")
            
            print(f"\n📊 Final Statistics:")
            print(f"  Total time: {elapsed:.1f} seconds")
            print(f"  Total keys checked: {total_keys_checked:,}")
            if elapsed > 0:
                print(f"  Overall speed: {total_keys_checked/elapsed:,.0f} keys/s")
            print(f"  GPUs completed: {completed}")
            print(f"  GPUs with errors: {errors}")
            
            # Cleanup
            for p in processes:
                if p.is_alive():
                    p.terminate()
                    p.join(timeout=2)
            
        except Exception as e:
            print(f"\n❌ Error in monitor: {e}")
            import traceback
            traceback.print_exc()

def worker_wrapper(worker, result_queue):
    """Wrapper untuk worker process"""
    worker.run_continuous_search(result_queue)

# ==================== MAIN PROGRAM ====================
if __name__ == "__main__":
    # Set multiprocessing start method
    mp.set_start_method('spawn', force=True)
    
    # Konfigurasi langsung (tanpa argparse)
    config = {
        'target_pubkey': TARGET_PUBKEY,
        'min_range': MIN_RANGE,
        'max_range': MAX_RANGE,
        'output_file': OUTPUT_FILE,
        'random_mode': RANDOM_MODE,
    }
    
    # Tampilkan informasi program
    print('\n' + '='*70)
    print('BITCOIN PRIVATE KEY SEARCH - BSGS GPU OPTIMIZED')
    print('='*70)
    print('Features:')
    print('  • BSGS algorithm dengan GPU acceleration')
    print('  • Support untuk range besar dan kecil')
    print('  • Multi-GPU support')
    print('  • Random atau sequential search mode')
    print('  • Real-time statistics dan progress tracking')
    print('='*70)
    
    # Check required libraries
    if not ICE_AVAILABLE:
        print("\n⚠️ Warning: secp256k1_lib not available")
        print("   Some features may not work properly")
    
    if not BIT_AVAILABLE:
        print("\n⚠️ Warning: bit library not available")
        print("   Key verification may be limited")
    
    # Start search
    manager = MultiGPUManager(
        target_pubkey=config['target_pubkey'],
        min_range_hex=config['min_range'],
        max_range_hex=config['max_range'],
        output_file=config['output_file'],
        random_mode=config['random_mode']
    )
    
    manager.start_search()
