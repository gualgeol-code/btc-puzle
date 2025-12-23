# -*- coding: utf-8 -*-
"""
GPU BSGS Search Tool - Complete Solution
"""

import secp256k1_lib as ice
import ctypes
import os
import sys
import platform
import time
import math
import signal

# ==============================================================================
# KONFIGURASI
# ==============================================================================

# Target public key (contoh)
PUBLIC_KEY = "033c4a45cbd643ff97d77f41ea37e843648d50fd894b864b0d52febc62f6454f7c"

# Range yang akan dicari (small untuk testing)
KEYSPACE_MIN = 0x80000      # 524,288
KEYSPACE_MAX = 0xFFFFF      # 1,048,575

# Konfigurasi GPU
GPU_DEVICE = 0
GPU_THREADS = 256
GPU_BLOCKS = 128
GPU_POINTS = 256
BP_SIZE = 500000

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
    else:
        # Already uncompressed or invalid
        return bytes.fromhex(pubkey_hex)

# ==============================================================================
# GPU LIBRARY WRAPPER
# ==============================================================================

class GPUSearcher:
    def __init__(self):
        self.bsgsgpu = None
        self.load_library()
        
    def load_library(self):
        """Load GPU library"""
        if platform.system().lower().startswith('win'):
            lib_files = ['bt2.dll', 'bsgs_gpu.dll', 'gpu_bsgs.dll']
        else:
            lib_files = ['bt2.so', 'libbsgs.so', 'bsgs_gpu.so', 'libbt2.so']
        
        for lib_file in lib_files:
            if os.path.exists(lib_file):
                try:
                    print(f"[+] Loading library: {lib_file}")
                    self.bsgsgpu = ctypes.CDLL(os.path.realpath(lib_file))
                    
                    # Setup function signatures
                    self.setup_functions()
                    print(f"[+] Library loaded successfully")
                    return True
                except Exception as e:
                    print(f"[-] Failed to load {lib_file}: {e}")
        
        print("[-] No GPU library found")
        return False
    
    def setup_functions(self):
        """Setup function prototypes"""
        # bsgsGPU function
        self.bsgsgpu.bsgsGPU.argtypes = [
            ctypes.c_uint32,  # threads
            ctypes.c_uint32,  # blocks
            ctypes.c_uint32,  # points
            ctypes.c_uint32,  # bits
            ctypes.c_int,     # device
            ctypes.c_char_p,  # upubs (P3 table)
            ctypes.c_uint32,  # size (number of points)
            ctypes.c_char_p,  # keyspace (start:end)
            ctypes.c_char_p   # bp_size
        ]
        self.bsgsgpu.bsgsGPU.restype = ctypes.c_void_p
        
        # Free memory function
        self.bsgsgpu.free_memory.argtypes = [ctypes.c_void_p]
        
        # Optional: Check if init function exists
        try:
            self.bsgsgpu.init_gpu()
        except:
            pass
    
    def search(self, target_pubkey, start_key, end_key, bp_size=BP_SIZE):
        """Search for private key using GPU"""
        print(f"\n[+] Preparing search from {hex(start_key)} to {hex(end_key)}")
        
        # Prepare data
        P = pubkey_to_uncompressed(target_pubkey)
        G = ice.scalar_multiplication(1)
        
        print(f"[+] Generating P3 table with {bp_size} points...")
        P3 = ice.point_loop_addition(bp_size, P, G)
        
        if len(P3) != bp_size * 65:
            print(f"[-] P3 table size incorrect: {len(P3)} bytes, expected {bp_size * 65}")
            return None
        
        print(f"[+] P3 table ready: {len(P3)} bytes")
        
        # Calculate bits for bloom filter
        gpu_bits = int(math.log2(bp_size)) if bp_size > 0 else 19
        
        # Format keyspace
        keyspace_str = f"{start_key:x}:{end_key:x}"
        
        print(f"[+] Starting GPU search...")
        print(f"    Threads: {GPU_THREADS}, Blocks: {GPU_BLOCKS}, Points: {GPU_POINTS}")
        print(f"    Keyspace: {keyspace_str}")
        
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
            keys_searched = end_key - start_key + 1
            
            if result_ptr:
                # Get result string
                result = ctypes.cast(result_ptr, ctypes.c_char_p).value
                if result:
                    private_key_hex = result.decode('utf8').strip()
                    self.bsgsgpu.free_memory(result_ptr)
                    
                    print(f"[+] GPU returned: {private_key_hex}")
                    print(f"[+] Search time: {elapsed:.2f}s")
                    print(f"[+] Speed: {keys_searched/elapsed:,.0f} keys/sec")
                    
                    # Verify the result
                    if self.verify_key(private_key_hex, target_pubkey):
                        return private_key_hex
                    else:
                        print("[-] Key verification failed")
                else:
                    print("[-] GPU returned empty result")
                    self.bsgsgpu.free_memory(result_ptr)
            else:
                print("[-] GPU returned NULL")
            
        except Exception as e:
            print(f"[-] GPU search error: {e}")
            import traceback
            traceback.print_exc()
        
        return None
    
    def verify_key(self, private_key_hex, target_pubkey):
        """Verify that private key produces the target public key"""
        try:
            priv_int = int(private_key_hex, 16)
            computed_pub = ice.scalar_multiplication(priv_int)
            
            # Convert both to uncompressed for comparison
            computed_uncompressed = computed_pub
            target_uncompressed = pubkey_to_uncompressed(target_pubkey)
            
            return computed_uncompressed == target_uncompressed
        except:
            return False

# ==============================================================================
# ALTERNATIVE: SIMPLE GPU TEST
# ==============================================================================

def simple_gpu_test():
    """Simple test to verify GPU functionality"""
    print("\n" + "="*70)
    print("GPU FUNCTIONALITY TEST")
    print("="*70)
    
    # Create a test keypair
    test_priv = 0xABCDE  # 703,710 (within our range)
    test_pub = ice.scalar_multiplication(test_priv)
    
    # Convert to compressed format
    x = int(test_pub[1:33].hex(), 16)
    y = int(test_pub[33:].hex(), 16)
    prefix = '02' if y % 2 == 0 else '03'
    test_pub_compressed = prefix + format(x, '064x')
    
    print(f"[+] Test Private Key: {hex(test_priv)}")
    print(f"[+] Test Public Key: {test_pub_compressed}")
    
    # Initialize GPU searcher
    searcher = GPUSearcher()
    if not searcher.bsgsgpu:
        print("[-] Cannot test without GPU library")
        return False
    
    # Test with small range around the test key
    test_start = test_priv - 1000
    test_end = test_priv + 1000
    
    print(f"\n[+] Testing GPU with known key in range {hex(test_start)}-{hex(test_end)}")
    
    found = searcher.search(test_pub_compressed, test_start, test_end, bp_size=10000)
    
    if found:
        print(f"[+] GPU TEST PASSED! Found key: {found}")
        return True
    else:
        print("[-] GPU TEST FAILED")
        return False

# ==============================================================================
# HYBRID SEARCH APPROACH
# ==============================================================================

def hybrid_search(target_pubkey, start_key, end_key):
    """Hybrid search using multiple strategies"""
    print("\n" + "="*70)
    print("HYBRID SEARCH STRATEGY")
    print("="*70)
    
    total_keys = end_key - start_key + 1
    print(f"[+] Total keys to search: {total_keys:,}")
    
    # Strategy 1: Try GPU with default settings
    print("\n[Strategy 1] GPU BSGS with default settings")
    searcher = GPUSearcher()
    
    if searcher.bsgsgpu:
        result = searcher.search(target_pubkey, start_key, end_key)
        if result:
            return result
    
    # Strategy 2: Try GPU with different BP sizes
    print("\n[Strategy 2] Trying different BP sizes")
    bp_sizes = [100000, 65536, 32768, 16384]
    
    for bp_size in bp_sizes:
        if searcher.bsgsgpu:
            print(f"\n[+] Trying BP_SIZE = {bp_size}")
            result = searcher.search(target_pubkey, start_key, end_key, bp_size)
            if result:
                return result
    
    # Strategy 3: Divide and conquer with GPU
    print("\n[Strategy 3] Divide and conquer")
    chunk_size = 100000
    current = start_key
    
    while current <= end_key:
        chunk_end = min(current + chunk_size - 1, end_key)
        
        print(f"\n[+] Searching chunk: {hex(current)}-{hex(chunk_end)}")
        
        if searcher.bsgsgpu:
            result = searcher.search(target_pubkey, current, chunk_end, bp_size=65536)
            if result:
                return result
        
        current = chunk_end + 1
    
    print("\n[-] All GPU strategies failed")
    return None

# ==============================================================================
# MANUAL VERIFICATION AND DEBUGGING
# ==============================================================================

def manual_verification():
    """Manual verification of key conversion and calculations"""
    print("\n" + "="*70)
    print("MANUAL VERIFICATION")
    print("="*70)
    
    # Test with a known key in range
    test_keys = [
        0x80000,  # Start of range
        0xABCDE,  # Middle of range
        0xFFFFF,  # End of range
        0x90000,  # Random point
        0xF0000,  # Another random point
    ]
    
    print("[+] Testing public key generation for various private keys:")
    for priv in test_keys:
        pub = ice.scalar_multiplication(priv)
        
        # Convert to compressed
        x = int(pub[1:33].hex(), 16)
        y = int(pub[33:].hex(), 16)
        prefix = '02' if y % 2 == 0 else '03'
        compressed = prefix + format(x, '064x')
        
        print(f"  Private: {hex(priv)} -> Public: {compressed[:20]}...")
    
    # Convert target public key
    target_uncompressed = pubkey_to_uncompressed(PUBLIC_KEY)
    print(f"\n[+] Target public key (uncompressed): {target_uncompressed.hex()[:20]}...")
    
    # Check if target is valid point
    if len(target_uncompressed) == 65 and target_uncompressed[0] == 4:
        print("[+] Target public key format: VALID")
    else:
        print("[-] Target public key format: INVALID")

# ==============================================================================
# MAIN PROGRAM
# ==============================================================================

def main():
    print("\n" + "="*70)
    print("BITCOIN PRIVATE KEY SEARCH - GPU OPTIMIZED")
    print("="*70)
    
    # Display configuration
    print(f"[+] Target Public Key: {PUBLIC_KEY}")
    print(f"[+] Search Range: {hex(KEYSPACE_MIN)} - {hex(KEYSPACE_MAX)}")
    print(f"[+] Total Keys: {KEYSPACE_MAX - KEYSPACE_MIN + 1:,}")
    
    # First, run manual verification
    manual_verification()
    
    # Run GPU test
    if simple_gpu_test():
        print("\n[+] GPU is working, proceeding with main search...")
    else:
        print("\n[!] GPU test failed, but continuing anyway...")
    
    # Run hybrid search
    print("\n" + "="*70)
    print("STARTING MAIN SEARCH")
    print("="*70)
    
    start_time = time.time()
    result = hybrid_search(PUBLIC_KEY, KEYSPACE_MIN, KEYSPACE_MAX)
    
    total_time = time.time() - start_time
    
    if result:
        print(f"\n✅ SUCCESS! Private key found: {result}")
        
        # Save result
        with open("found_key.txt", "w") as f:
            f.write(f"Private Key: {result}\n")
            f.write(f"Public Key: {PUBLIC_KEY}\n")
            f.write(f"Search Range: {hex(KEYSPACE_MIN)}-{hex(KEYSPACE_MAX)}\n")
            f.write(f"Search Time: {total_time:.2f}s\n")
        
        print(f"[+] Result saved to found_key.txt")
        
        # Generate addresses
        try:
            from bit import Key
            key = Key.from_int(int(result, 16))
            print(f"\n[+] Bitcoin Addresses:")
            print(f"   Compressed: {key.address}")
            print(f"   SegWit: {key.segwit_address}")
        except:
            print("[!] Could not generate addresses")
    else:
        print(f"\n❌ Key not found in range {hex(KEYSPACE_MIN)}-{hex(KEYSPACE_MAX)}")
        print(f"   Search Time: {total_time:.2f}s")
        
        # Suggest next steps
        print("\n[+] Suggestions:")
        print("   1. Verify the public key is correct")
        print("   2. Verify the private key is actually in the specified range")
        print("   3. Try a different GPU library")
        print("   4. Use CPU brute force for this small range")

# ==============================================================================
# DIRECT GPU CALL WITH DEBUGGING
# ==============================================================================

def direct_gpu_debug():
    """Direct GPU call with maximum debugging"""
    print("\n" + "="*70)
    print("DIRECT GPU DEBUGGING")
    print("="*70)
    
    # Load library manually
    try:
        bsgsgpu = ctypes.CDLL("./bt2.so")
        print("[+] Library loaded directly")
    except Exception as e:
        print(f"[-] Failed to load library: {e}")
        return
    
    # Try to find function names
    print("\n[+] Available functions:")
    for name in dir(bsgsgpu):
        if not name.startswith('_'):
            print(f"  - {name}")
    
    # Try different function names
    func_names = ['bsgsGPU', 'bsgs_gpu', 'gpu_bsgs', 'search_key']
    
    for func_name in func_names:
        try:
            func = getattr(bsgsgpu, func_name)
            print(f"\n[+] Found function: {func_name}")
            
            # Try to call it with minimal parameters
            print(f"[+] Testing {func_name}...")
            break
        except:
            continue

# ==============================================================================
# ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    try:
        # First try direct debugging
        if os.path.exists("bt2.so"):
            direct_gpu_debug()
        
        # Then run main program
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Search interrupted by user")
    except Exception as e:
        print(f"\n[-] Fatal error: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "="*70)
    print("SEARCH COMPLETE")
    print("="*70)
