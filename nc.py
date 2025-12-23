# -*- coding: utf-8 -*-
"""
HYBRID BSGS SEARCH - GPU dengan fallback ke CPU
Menggunakan algoritma BSGS (Baby-Step Giant-Step) untuk akselerasi GPU
"""

import secp256k1_lib as ice
import ctypes
import os
import sys
import platform
import time
import math
import random

# ==============================================================================
# KONFIGURASI
# ==============================================================================

# Target public key
PUBLIC_KEY = "033c4a45cbd643ff97d77f41ea37e843648d50fd894b864b0d52febc62f6454f7c"

# Range pencarian
START_KEY = 0x80000      # 524,288
END_KEY = 0xFFFFF        # 1,048,575

# Konfigurasi BSGS
BP_SIZE = 500000         # Baby-step table size (optimal untuk range 2^20)

# Konfigurasi GPU
GPU_DEVICE = 0
GPU_THREADS = 256
GPU_BLOCKS = 128
GPU_POINTS = 256

# ==============================================================================
# FUNGSI UTILITAS
# ==============================================================================

def pubkey_to_uncompressed(pubkey_hex):
    """Convert public key to uncompressed format"""
    if pubkey_hex.startswith('02') or pubkey_hex.startswith('03'):
        # Compressed format
        x = int(pubkey_hex[2:], 16)
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        y_sq = (pow(x, 3, p) + 7) % p
        y = pow(y_sq, (p + 1) // 4, p)
        
        if (pubkey_hex.startswith('02') and y % 2 == 1) or (pubkey_hex.startswith('03') and y % 2 == 0):
            y = p - y
        
        return bytes.fromhex('04' + format(x, '064x') + format(y, '064x'))
    
    elif pubkey_hex.startswith('04'):
        # Already uncompressed
        if len(pubkey_hex) == 130:
            return bytes.fromhex(pubkey_hex)
        else:
            return bytes.fromhex('04' + pubkey_hex[2:].zfill(128))
    
    else:
        # Assume uncompressed without prefix
        return bytes.fromhex('04' + pubkey_hex.zfill(128))

def verify_key(private_key_hex, target_pubkey_hex):
    """Verify that private key produces the target public key"""
    try:
        priv_int = int(private_key_hex, 16)
        computed_pub = ice.scalar_multiplication(priv_int)
        target_pub = pubkey_to_uncompressed(target_pubkey_hex)
        return computed_pub == target_pub
    except:
        return False

# ==============================================================================
# GPU BSGS IMPLEMENTATION
# ==============================================================================

class BSGS_GPU_Searcher:
    def __init__(self):
        self.bsgsgpu = None
        self.load_library()
    
    def load_library(self):
        """Load GPU library"""
        if platform.system().lower().startswith('win'):
            lib_files = ['bt2.dll', 'bsgs_gpu.dll']
        else:
            lib_files = ['bt2.so', 'bsgs_gpu.so']
        
        for lib_file in lib_files:
            if os.path.exists(lib_file):
                try:
                    print(f"[+] Loading GPU library: {lib_file}")
                    self.bsgsgpu = ctypes.CDLL(os.path.realpath(lib_file))
                    
                    # Setup function prototypes
                    self.bsgsgpu.bsgsGPU.argtypes = [
                        ctypes.c_uint32,  # threads
                        ctypes.c_uint32,  # blocks
                        ctypes.c_uint32,  # points
                        ctypes.c_uint32,  # bits
                        ctypes.c_int,     # device
                        ctypes.c_char_p,  # upubs
                        ctypes.c_uint32,  # size
                        ctypes.c_char_p,  # keyspace
                        ctypes.c_char_p   # bp size
                    ]
                    self.bsgsgpu.bsgsGPU.restype = ctypes.c_void_p
                    self.bsgsgpu.free_memory.argtypes = [ctypes.c_void_p]
                    
                    print("[+] GPU library loaded successfully")
                    return True
                    
                except Exception as e:
                    print(f"[-] Failed to load {lib_file}: {e}")
        
        print("[-] No GPU library found")
        return False
    
    def prepare_bsgs_data(self, target_pubkey_hex, bp_size):
        """Prepare data for BSGS algorithm"""
        print(f"[+] Preparing BSGS data (BP_SIZE={bp_size})...")
        
        # Convert target public key
        P = pubkey_to_uncompressed(target_pubkey_hex)
        
        # Generate base point G
        G = ice.scalar_multiplication(1)
        
        # Generate P3 table = P + i*G for i=0..bp_size-1
        print(f"[+] Generating P3 table with {bp_size} points...")
        P3 = ice.point_loop_addition(bp_size, P, G)
        
        if len(P3) != bp_size * 65:
            print(f"[-] P3 table size mismatch: {len(P3)} bytes, expected {bp_size * 65}")
            return None, None
        
        print(f"[+] P3 table generated: {len(P3):,} bytes")
        return P, P3
    
    def search_range(self, start_key, end_key, bp_size=BP_SIZE):
        """Search range using GPU BSGS"""
        if start_key > end_key:
            start_key, end_key = end_key, start_key
        
        print(f"[GPU] Searching range: {hex(start_key)} - {hex(end_key)}")
        print(f"[GPU] Range size: {end_key - start_key + 1:,} keys")
        
        # Prepare data
        P, P3 = self.prepare_bsgs_data(PUBLIC_KEY, bp_size)
        if P3 is None:
            return None, 0
        
        # Format keyspace string (without 0x prefix)
        keyspace_str = f"{start_key:x}:{end_key:x}"
        
        # Calculate bits for bloom filter
        gpu_bits = int(math.log2(bp_size)) if bp_size > 0 else 19
        
        start_time = time.time()
        
        try:
            # Call GPU function
            result_ptr = self.bsgsgpu.bsgsGPU(
                GPU_THREADS,
                GPU_BLOCKS,
                GPU_POINTS,
                gpu_bits,
                GPU_DEVICE,
                P3,
                len(P3) // 65,
                keyspace_str.encode('utf8'),
                str(bp_size).encode('utf8')
            )
            
            elapsed = time.time() - start_time
            
            if result_ptr:
                # Get result string
                result = ctypes.cast(result_ptr, ctypes.c_char_p).value
                if result:
                    private_key_hex = result.decode('utf8').strip()
                    self.bsgsgpu.free_memory(result_ptr)
                    
                    print(f"[GPU] Search completed in {elapsed:.2f}s")
                    
                    if private_key_hex:
                        return private_key_hex, elapsed
                    else:
                        print("[GPU] Key not found in this range")
                        return None, elapsed
                else:
                    self.bsgsgpu.free_memory(result_ptr)
                    print("[GPU] No result returned")
                    return None, elapsed
            else:
                print("[GPU] GPU returned NULL")
                return None, elapsed
                
        except Exception as e:
            elapsed = time.time() - start_time
            print(f"[GPU] Error: {e}")
            return None, elapsed

# ==============================================================================
# CPU BSGS IMPLEMENTATION (Fallback)
# ==============================================================================

def bsgs_cpu_search(start_key, end_key, target_pubkey_hex, bp_size=65536):
    """CPU implementation of BSGS algorithm"""
    print(f"\n[CPU BSGS] Starting BSGS search from {hex(start_key)} to {hex(end_key)}")
    print(f"[CPU BSGS] BP_SIZE: {bp_size}")
    
    # Prepare target public key
    target_pub = pubkey_to_uncompressed(target_pubkey_hex)
    
    # Generate P3 table
    P = target_pub
    G = ice.scalar_multiplication(1)
    P3 = ice.point_loop_addition(bp_size, P, G)
    
    # Create lookup dictionary for baby steps
    print(f"[CPU BSGS] Creating lookup table...")
    lookup_table = {}
    
    for i in range(bp_size):
        start_idx = i * 65
        if start_idx + 65 <= len(P3):
            point = P3[start_idx:start_idx+65]
            # Store only x-coordinate (32 bytes)
            x_coord = point[1:33]
            lookup_table[x_coord] = i
    
    print(f"[CPU BSGS] Lookup table created with {len(lookup_table)} entries")
    
    # Calculate giant step
    m = bp_size
    w = (end_key - start_key + 1 + m - 1) // m  # Ceiling division
    
    print(f"[CPU BSGS] Giant steps (w): {w}")
    print(f"[CPU BSGS] Searching...")
    
    start_time = time.time()
    
    # Giant steps
    for j in range(w):
        # Calculate R = target_pub - j*m*G
        jmG = ice.scalar_multiplication(j * m)
        R = ice.point_subtraction(P, jmG)
        
        # Check if R is in baby-step table
        r_x = R[1:33]
        
        if r_x in lookup_table:
            i = lookup_table[r_x]
            private_key = i + j * m
            
            # Verify it's within range
            if start_key <= private_key <= end_key:
                elapsed = time.time() - start_time
                print(f"[CPU BSGS] Potential match found: {hex(private_key)}")
                
                # Verify
                test_pub = ice.scalar_multiplication(private_key)
                if test_pub == target_pub:
                    print(f"[CPU BSGS] Verification passed!")
                    return hex(private_key), elapsed
                else:
                    print(f"[CPU BSGS] Verification failed, continuing...")
        
        # Progress indicator
        if (j + 1) % 100 == 0:
            elapsed = time.time() - start_time
            progress = (j + 1) / w * 100
            speed = (j + 1) / elapsed if elapsed > 0 else 0
            print(f"[CPU BSGS] Progress: {progress:.1f}% - Speed: {speed:.0f} steps/sec", end='\r')
    
    elapsed = time.time() - start_time
    print(f"\n[CPU BSGS] Search completed in {elapsed:.2f}s")
    return None, elapsed

# ==============================================================================
# HYBRID SEARCH MANAGER
# ==============================================================================

class HybridSearcher:
    def __init__(self):
        self.gpu_searcher = BSGS_GPU_Searcher()
        self.use_gpu = self.gpu_searcher.bsgsgpu is not None
    
    def search(self, start_key, end_key):
        """Hybrid search using GPU with CPU fallback"""
        print("\n" + "="*70)
        print("HYBRID BSGS SEARCH")
        print("="*70)
        print(f"Target: {PUBLIC_KEY[:20]}...{PUBLIC_KEY[-20:]}")
        print(f"Range: {hex(start_key)} - {hex(end_key)}")
        print(f"Total keys: {end_key - start_key + 1:,}")
        print(f"GPU Available: {'Yes' if self.use_gpu else 'No'}")
        print("="*70)
        
        total_keys = end_key - start_key + 1
        
        if self.use_gpu:
            print("\n[+] Attempting GPU BSGS search...")
            
            # Try different BP sizes if needed
            bp_sizes = [BP_SIZE, 65536, 32768, 100000]
            
            for bp_size in bp_sizes:
                print(f"\n[+] Trying BP_SIZE = {bp_size}")
                
                result, elapsed = self.gpu_searcher.search_range(
                    start_key, end_key, bp_size
                )
                
                if result:
                    if verify_key(result, PUBLIC_KEY):
                        print(f"\n✅ GPU BSGS FOUND KEY: {result}")
                        print(f"   Time: {elapsed:.2f} seconds")
                        print(f"   Speed: {total_keys/elapsed:,.0f} keys/sec")
                        return result, elapsed
                    else:
                        print("[-] Key verification failed")
                
                if elapsed > 0:
                    print(f"[GPU] Speed: {total_keys/elapsed:,.0f} keys/sec")
            
            print("\n[-] GPU BSGS search failed, falling back to CPU...")
        
        # CPU BSGS fallback
        print("\n[+] Starting CPU BSGS search...")
        
        # Choose optimal BP_SIZE for CPU
        cpu_bp_size = min(65536, total_keys // 10)
        if cpu_bp_size < 1000:
            cpu_bp_size = 1000
        
        result, elapsed = bsgs_cpu_search(
            start_key, end_key, PUBLIC_KEY, cpu_bp_size
        )
        
        if result:
            if verify_key(result, PUBLIC_KEY):
                print(f"\n✅ CPU BSGS FOUND KEY: {result}")
                print(f"   Time: {elapsed:.2f} seconds")
                print(f"   Speed: {total_keys/elapsed:,.0f} keys/sec")
                return result, elapsed
            else:
                print("[-] Key verification failed")
        
        # If BSGS fails, use simple brute force as last resort
        print("\n[+] BSGS failed, using CPU brute force as last resort...")
        return self.brute_force_cpu(start_key, end_key)
    
    def brute_force_cpu(self, start_key, end_key):
        """Simple CPU brute force as fallback"""
        print(f"[CPU Brute] Starting brute force...")
        
        target_bytes = pubkey_to_uncompressed(PUBLIC_KEY)
        total_keys = end_key - start_key + 1
        
        start_time = time.time()
        
        for k in range(start_key, end_key + 1):
            pub = ice.scalar_multiplication(k)
            
            if pub == target_bytes:
                elapsed = time.time() - start_time
                print(f"\n✅ CPU BRUTE FORCE FOUND KEY: {hex(k)}")
                print(f"   Time: {elapsed:.2f} seconds")
                print(f"   Speed: {total_keys/elapsed:,.0f} keys/sec")
                return hex(k), elapsed
            
            if (k - start_key) % 50000 == 0 and k > start_key:
                elapsed = time.time() - start_time
                progress = (k - start_key + 1) / total_keys * 100
                speed = (k - start_key + 1) / elapsed
                print(f"[CPU Brute] Progress: {progress:.1f}% - Speed: {speed:,.0f} keys/sec", end='\r')
        
        elapsed = time.time() - start_time
        print(f"\n❌ Key not found in range")
        return None, elapsed

# ==============================================================================
# MAIN PROGRAM
# ==============================================================================

def main():
    print("\n" + "="*70)
    print("BITCOIN PRIVATE KEY SEARCH - HYBRID BSGS")
    print("="*70)
    
    # Create searcher
    searcher = HybridSearcher()
    
    # Start search
    start_time = time.time()
    result, search_time = searcher.search(START_KEY, END_KEY)
    
    total_time = time.time() - start_time
    
    print("\n" + "="*70)
    print("SEARCH COMPLETE")
    print("="*70)
    
    if result:
        priv_int = int(result, 16)
        
        print(f"✅ PRIVATE KEY FOUND!")
        print(f"   Private Key (hex): {result}")
        print(f"   Private Key (decimal): {priv_int}")
        print(f"   Search Time: {search_time:.2f} seconds")
        print(f"   Total Time: {total_time:.2f} seconds")
        
        # Save to file
        with open("bsgs_found_key.txt", "w") as f:
            f.write("BSGS SEARCH - PRIVATE KEY FOUND\n")
            f.write("="*60 + "\n")
            f.write(f"Time: {time.ctime()}\n")
            f.write(f"Method: {'GPU' if searcher.use_gpu else 'CPU'} BSGS\n")
            f.write(f"Private Key (hex): {result}\n")
            f.write(f"Private Key (decimal): {priv_int}\n")
            f.write(f"Public Key: {PUBLIC_KEY}\n")
            f.write(f"Search Range: {hex(START_KEY)} - {hex(END_KEY)}\n")
            f.write(f"Search Time: {search_time:.2f}s\n")
            f.write(f"Total Time: {total_time:.2f}s\n")
        
        print(f"\n[+] Results saved to 'bsgs_found_key.txt'")
        
        # Generate Bitcoin addresses
        try:
            from bit import Key
            key = Key.from_int(priv_int)
            
            print(f"\n[+] Bitcoin Addresses:")
            print(f"   Compressed: {key.address}")
            print(f"   SegWit: {key.segwit_address}")
            
            with open("bsgs_found_key.txt", "a") as f:
                f.write(f"\nBitcoin Addresses:\n")
                f.write(f"Compressed: {key.address}\n")
                f.write(f"SegWit: {key.segwit_address}\n")
                
        except:
            print("\n[!] Could not generate Bitcoin addresses")
    
    else:
        print(f"❌ KEY NOT FOUND IN SPECIFIED RANGE")
        print(f"   Search Time: {search_time:.2f} seconds")
        print(f"   Total Time: {total_time:.2f} seconds")
        
        if search_time > 0:
            total_keys = END_KEY - START_KEY + 1
            print(f"   Average Speed: {total_keys/search_time:,.0f} keys/sec")
    
    print("="*70)

# ==============================================================================
# TEST FUNCTION FOR BSGS ALGORITHM
# ==============================================================================

def test_bsgs_algorithm():
    """Test the BSGS algorithm with a known key"""
    print("\n" + "="*70)
    print("BSGS ALGORITHM TEST")
    print("="*70)
    
    # Generate a test keypair
    test_priv = 0xD2C55  # The key we know is in range
    test_pub = ice.scalar_multiplication(test_priv)
    
    # Convert to compressed format
    x = int(test_pub[1:33].hex(), 16)
    y = int(test_pub[33:].hex(), 16)
    prefix = '02' if y % 2 == 0 else '03'
    test_pub_compressed = prefix + format(x, '064x')
    
    print(f"[+] Test Private Key: {hex(test_priv)}")
    print(f"[+] Test Public Key: {test_pub_compressed[:20]}...")
    
    # Test BSGS CPU implementation
    print(f"\n[+] Testing BSGS CPU implementation...")
    
    # Search in a small range around the known key
    test_start = test_priv - 1000
    test_end = test_priv + 1000
    
    result, elapsed = bsgs_cpu_search(
        test_start, test_end, test_pub_compressed, bp_size=1000
    )
    
    if result and int(result, 16) == test_priv:
        print(f"[+] ✅ BSGS CPU test PASSED!")
        print(f"[+] Found key: {result} in {elapsed:.2f}s")
        return True
    else:
        print(f"[+] ❌ BSGS CPU test FAILED")
        return False

# ==============================================================================
# RUN PROGRAM
# ==============================================================================

if __name__ == "__main__":
    print("\n" + "="*70)
    print("BITCOIN PRIVATE KEY SEARCH - HYBRID SYSTEM")
    print("="*70)
    
    # Run test first
    test_option = input("\nRun BSGS algorithm test first? (y/n): ").strip().lower()
    
    if test_option == 'y':
        if not test_bsgs_algorithm():
            print("\n[!] BSGS test failed. Proceeding anyway...")
    
    # Run main search
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Search interrupted by user")
    except Exception as e:
        print(f"\n[-] Error: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n[+] Program finished.")
