# -*- coding: utf-8 -*-
"""
BSGS GPU Tool - Fixed Version with CPU Fallback
"""

import secp256k1_lib as ice
import bit
import ctypes
import os
import sys
import platform
import random
import math
import signal
import time
import hashlib
import threading
from queue import Queue

# ==============================================================================
# KONFIGURASI PARAMETER
# ==============================================================================

# Public Key target
PUBLIC_KEY = "033c4a45cbd643ff97d77f41ea37e843648d50fd894b864b0d52febc62f6454f7c"

# Range keyspace untuk pencarian
KEYSPACE_MIN = 0x80000      # 524,288
KEYSPACE_MAX = 0xFFFFF      # 1,048,575

# Private key yang SEBENARNYA (untuk verifikasi saja, HAPUS setelah testing!)
# Ganti dengan private key yang sesuai dengan PUBLIC_KEY di atas
KNOWN_PRIVATE_KEY = 0xd2c55  # Contoh: 703,710

# Konfigurasi GPU (di-disable sementara karena error)
USE_GPU = False  # Set ke False untuk menggunakan CPU brute force
GPU_DEVICE = 0
GPU_THREADS = 32
GPU_BLOCKS = 8
GPU_POINTS = 128
BP_SIZE = 65536

# Konfigurasi CPU
CPU_THREADS = 8  # Jumlah thread untuk CPU brute force
BATCH_SIZE = 1000  # Ukuran batch per thread

# Output file
OUTPUT_FILE = "found_keys.txt"

# ==============================================================================
# FUNGSI UTILITAS
# ==============================================================================

def pub2upub(pub_hex):
    """Convert compressed/uncompressed public key to uncompressed format"""
    # Pastikan panjang hex genap
    pub_hex = pub_hex.strip()
    
    if pub_hex.startswith('02') or pub_hex.startswith('03'):
        # Compressed format
        x = int(pub_hex[2:], 16)
        # Hitung y dari x menggunakan kurva secp256k1: y² = x³ + 7
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        a = 0
        b = 7
        
        # Hitung y² = x³ + ax + b mod p
        y_sq = (pow(x, 3, p) + a * x + b) % p
        
        # Hitung y = sqrt(y²) mod p (p ≡ 3 mod 4, so use Euler's criterion)
        y = pow(y_sq, (p + 1) // 4, p)
        
        # Sesuaikan dengan prefix (02 untuk y genap, 03 untuk y ganjil)
        if (pub_hex.startswith('02') and y % 2 == 1) or (pub_hex.startswith('03') and y % 2 == 0):
            y = p - y
        
        return bytes.fromhex('04' + format(x, '064x') + format(y, '064x'))
    
    elif pub_hex.startswith('04'):
        # Uncompressed format
        if len(pub_hex) == 130:
            return bytes.fromhex(pub_hex)
        elif len(pub_hex) == 128:
            return bytes.fromhex('04' + pub_hex)
        else:
            # Pad if necessary
            return bytes.fromhex('04' + pub_hex[2:].zfill(128))
    
    # Jika tanpa prefix, asumsi compressed
    else:
        x = int(pub_hex, 16)
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        y_sq = (pow(x, 3, p) + 7) % p
        y = pow(y_sq, (p + 1) // 4, p)
        # Default to even y
        if y % 2 == 1:
            y = p - y
        return bytes.fromhex('04' + format(x, '064x') + format(y, '064x'))

def verify_key_pair(private_key_hex, target_pubkey_hex):
    """Verifikasi bahwa private key menghasilkan public key yang sesuai"""
    try:
        priv_int = int(private_key_hex, 16)
        
        # Hitung public key dari private key
        computed_pub = ice.scalar_multiplication(priv_int)
        
        # Konversi target ke uncompressed
        target_pub = pub2upub(target_pubkey_hex)
        
        # Bandingkan
        return computed_pub == target_pub
    except Exception as e:
        print(f"Verification error: {e}")
        return False

def generate_test_keypair():
    """Generate test keypair untuk debugging"""
    test_priv = random.randint(KEYSPACE_MIN, KEYSPACE_MAX)
    test_pub = ice.scalar_multiplication(test_priv)
    
    # Konversi ke compressed format
    x = int(test_pub[1:33].hex(), 16)
    y = int(test_pub[33:].hex(), 16)
    prefix = '02' if y % 2 == 0 else '03'
    
    compressed_pub = prefix + format(x, '064x')
    
    return test_priv, compressed_pub

# ==============================================================================
# CPU BRUTE FORCE IMPLEMENTATION
# ==============================================================================

def cpu_worker(start, end, target_pub, result_queue, thread_id):
    """Worker thread untuk CPU brute force"""
    try:
        print(f"[Thread {thread_id}] Starting from {hex(start)} to {hex(end)}")
        
        # Konversi target pubkey ke bytes sekali saja
        target_bytes = pub2upub(target_pub)
        
        batch_count = 0
        start_time = time.time()
        
        for k in range(start, end + 1):
            # Hitung public key
            pub = ice.scalar_multiplication(k)
            
            # Bandingkan dengan target
            if pub == target_bytes:
                elapsed = time.time() - start_time
                speed = (k - start + 1) / elapsed if elapsed > 0 else 0
                
                result_queue.put({
                    'found': True,
                    'private_key': k,
                    'thread_id': thread_id,
                    'keys_checked': k - start + 1,
                    'time': elapsed,
                    'speed': speed
                })
                return
            
            # Progress reporting
            batch_count += 1
            if batch_count >= 10000:
                elapsed = time.time() - start_time
                speed = (k - start + 1) / elapsed if elapsed > 0 else 0
                progress = (k - start + 1) / (end - start + 1) * 100
                
                print(f"[Thread {thread_id}] Progress: {progress:.1f}%, Speed: {speed:,.0f} keys/sec", end='\r')
                batch_count = 0
        
        # Jika tidak ditemukan
        elapsed = time.time() - start_time
        keys_checked = end - start + 1
        speed = keys_checked / elapsed if elapsed > 0 else 0
        
        result_queue.put({
            'found': False,
            'thread_id': thread_id,
            'keys_checked': keys_checked,
            'time': elapsed,
            'speed': speed
        })
        
    except Exception as e:
        print(f"[Thread {thread_id}] Error: {e}")
        result_queue.put({
            'found': False,
            'thread_id': thread_id,
            'error': str(e)
        })

def cpu_bruteforce_range(start_range, end_range, target_pubkey, num_threads=4):
    """Brute force range menggunakan multiple CPU threads"""
    print(f"\n[CPU] Starting brute force from {hex(start_range)} to {hex(end_range)}")
    print(f"[CPU] Total keys: {end_range - start_range + 1:,}")
    print(f"[CPU] Using {num_threads} threads")
    
    total_keys = end_range - start_range + 1
    keys_per_thread = total_keys // num_threads
    
    result_queue = Queue()
    threads = []
    
    # Create threads
    for i in range(num_threads):
        thread_start = start_range + i * keys_per_thread
        thread_end = thread_start + keys_per_thread - 1
        
        # Untuk thread terakhir, pastikan mencakup sisa keys
        if i == num_threads - 1:
            thread_end = end_range
        
        thread = threading.Thread(
            target=cpu_worker,
            args=(thread_start, thread_end, target_pubkey, result_queue, i)
        )
        threads.append(thread)
    
    # Start all threads
    start_time = time.time()
    for thread in threads:
        thread.start()
    
    # Monitor results
    total_checked = 0
    completed_threads = 0
    found_key = None
    
    while completed_threads < num_threads and found_key is None:
        try:
            result = result_queue.get(timeout=1)
            completed_threads += 1
            
            if result.get('found', False):
                found_key = result['private_key']
                print(f"\n[CPU] Thread {result['thread_id']} found key: {hex(found_key)}")
                print(f"[CPU] Checked {result['keys_checked']:,} keys in {result['time']:.2f}s")
                print(f"[CPU] Speed: {result['speed']:,.0f} keys/sec")
                
                # Stop other threads
                for thread in threads:
                    if thread.is_alive():
                        thread.join(timeout=0.1)
                break
            else:
                total_checked += result['keys_checked']
                print(f"[CPU] Thread {result['thread_id']} completed: {result['keys_checked']:,} keys")
        
        except Exception as e:
            # Timeout, check if threads are still alive
            alive_threads = sum(1 for t in threads if t.is_alive())
            if alive_threads == 0:
                break
    
    # Wait for all threads to finish
    for thread in threads:
        thread.join(timeout=1)
    
    total_time = time.time() - start_time
    
    if found_key is not None:
        return found_key, total_time, total_checked
    else:
        # Count any remaining keys
        while not result_queue.empty():
            result = result_queue.get_nowait()
            if result.get('found', False):
                found_key = result['private_key']
                return found_key, total_time, total_checked
            total_checked += result.get('keys_checked', 0)
        
        return None, total_time, total_checked

# ==============================================================================
# GPU IMPLEMENTATION (Optional)
# ==============================================================================

def initialize_gpu():
    """Initialize GPU library if available"""
    if not USE_GPU:
        return None
    
    try:
        if platform.system().lower().startswith('win'):
            dllfile = 'bt2.dll'
        elif platform.system().lower().startswith('lin'):
            dllfile = 'bt2.so'
        else:
            return None
        
        if os.path.isfile(dllfile):
            bsgsgpu = ctypes.CDLL(os.path.realpath(dllfile))
            
            # Setup function prototypes
            bsgsgpu.bsgsGPU.argtypes = [
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
            bsgsgpu.bsgsGPU.restype = ctypes.c_void_p
            bsgsgpu.free_memory.argtypes = [ctypes.c_void_p]
            
            return bsgsgpu
    except Exception as e:
        print(f"[GPU] Initialization failed: {e}")
    
    return None

# ==============================================================================
# MAIN PROGRAM
# ==============================================================================

def main():
    print('\n' + '='*70)
    print('BITCOIN PRIVATE KEY SEARCH TOOL')
    print('='*70)
    
    # Konversi keyspace
    a, b = KEYSPACE_MIN, KEYSPACE_MAX
    if a > b:
        a, b = b, a
    
    total_keys = b - a + 1
    
    # Display configuration
    print(f"[+] Target Public Key: {PUBLIC_KEY}")
    print(f"[+] Search Range: {hex(a)} - {hex(b)}")
    print(f"[+] Total Keys: {total_keys:,}")
    print(f"[+] Expected Bit Length: {int(math.log2(total_keys)) + 1} bits")
    
    # Verify public key format
    try:
        target_pub_bytes = pub2upub(PUBLIC_KEY)
        print(f"[+] Public key decoded successfully")
        print(f"[+] Public key (uncompressed): {target_pub_bytes.hex()[:20]}...")
    except Exception as e:
        print(f"[-] Error decoding public key: {e}")
        return
    
    # OPTIONAL: Generate test keypair for verification
    print("\n[DEBUG] Generating test keypair for verification...")
    test_priv, test_pub = generate_test_keypair()
    print(f"[DEBUG] Test Private Key: {hex(test_priv)}")
    print(f"[DEBUG] Test Public Key: {test_pub}")
    
    # Verify our conversion works
    test_pub_bytes = pub2upub(test_pub)
    computed_from_test = ice.scalar_multiplication(test_priv)
    if test_pub_bytes == computed_from_test:
        print("[DEBUG] ✓ Keypair verification PASSED")
    else:
        print("[DEBUG] ✗ Keypair verification FAILED")
        print(f"[DEBUG] Expected: {test_pub_bytes.hex()[:50]}...")
        print(f"[DEBUG] Got: {computed_from_test.hex()[:50]}...")
    
    # Ask user for mode selection
    print("\n" + "="*70)
    print("SELECT SEARCH METHOD:")
    print("1. CPU Brute Force (Recommended for small ranges)")
    print("2. GPU BSGS (Experimental, may fail)")
    print("3. Hybrid (CPU first, then GPU)")
    print("="*70)
    
    choice = input("Enter choice (1-3): ").strip()
    
    found_key = None
    search_time = 0
    keys_checked = 0
    
    # OPTION 1: CPU Brute Force
    if choice == "1":
        print("\n[+] Starting CPU Brute Force...")
        
        # Determine optimal thread count
        num_threads = min(CPU_THREADS, os.cpu_count() or 4)
        print(f"[+] Using {num_threads} CPU threads")
        
        # Start brute force
        found_key, search_time, keys_checked = cpu_bruteforce_range(
            a, b, PUBLIC_KEY, num_threads
        )
    
    # OPTION 2: GPU BSGS
    elif choice == "2":
        print("\n[+] Attempting GPU BSGS search...")
        
        # Initialize GPU
        bsgsgpu = initialize_gpu()
        if bsgsgpu:
            print("[GPU] Library loaded successfully")
            # GPU search implementation would go here
            # (Currently disabled due to library issues)
            print("[GPU] Search functionality temporarily disabled")
            print("[GPU] Falling back to CPU brute force...")
            
            # Fallback to CPU
            found_key, search_time, keys_checked = cpu_bruteforce_range(
                a, b, PUBLIC_KEY, min(4, os.cpu_count() or 2)
            )
        else:
            print("[-] GPU library not found or failed to load")
            print("[+] Falling back to CPU brute force...")
            
            found_key, search_time, keys_checked = cpu_bruteforce_range(
                a, b, PUBLIC_KEY, min(4, os.cpu_count() or 2)
            )
    
    # OPTION 3: Hybrid
    elif choice == "3":
        print("\n[+] Starting Hybrid Search...")
        
        # First try CPU for quick results
        print("[Phase 1] Quick CPU scan...")
        found_key, search_time, keys_checked = cpu_bruteforce_range(
            a, min(a + 100000, b), PUBLIC_KEY, 2
        )
        
        # If not found, try GPU if available
        if not found_key and USE_GPU:
            print("\n[Phase 2] GPU BSGS search...")
            # GPU implementation would go here
            print("[GPU] Not implemented in this version")
    
    else:
        print("[-] Invalid choice. Defaulting to CPU Brute Force...")
        found_key, search_time, keys_checked = cpu_bruteforce_range(
            a, b, PUBLIC_KEY, min(4, os.cpu_count() or 2)
        )
    
    # ==========================================================================
    # RESULTS
    # ==========================================================================
    
    print('\n' + '='*70)
    print('SEARCH RESULTS')
    print('='*70)
    
    if found_key is not None:
        # Verify the found key
        is_valid = verify_key_pair(hex(found_key), PUBLIC_KEY)
        
        if is_valid:
            print(f"✅ PRIVATE KEY FOUND!")
            print(f"   Private Key: {hex(found_key)}")
            print(f"   Private Key (decimal): {found_key}")
            print(f"   WIF Format: To be calculated")
            
            # Save to file
            with open(OUTPUT_FILE, "w") as f:
                f.write(f"Private Key Found!\n")
                f.write(f"Time: {time.ctime()}\n")
                f.write(f"Public Key: {PUBLIC_KEY}\n")
                f.write(f"Private Key (hex): {hex(found_key)}\n")
                f.write(f"Private Key (decimal): {found_key}\n")
                f.write(f"Search Range: {hex(a)} - {hex(b)}\n")
                f.write(f"Keys Checked: {keys_checked:,}\n")
                f.write(f"Search Time: {search_time:.2f} seconds\n")
                f.write(f"Speed: {keys_checked/search_time:,.0f} keys/sec\n")
            
            print(f"\n[+] Results saved to {OUTPUT_FILE}")
            
            # Calculate Bitcoin address
            try:
                # Compressed address
                from bit import Key
                key_obj = Key.from_int(found_key)
                print(f"\n[+] Bitcoin Addresses:")
                print(f"   Compressed: {key_obj.address}")
                print(f"   Uncompressed: {key_obj._pk.address(uncompressed=True)}")
                print(f"   SegWit (Bech32): {key_obj.segwit_address}")
                
                # Add addresses to file
                with open(OUTPUT_FILE, "a") as f:
                    f.write(f"\nBitcoin Addresses:\n")
                    f.write(f"Compressed: {key_obj.address}\n")
                    f.write(f"Uncompressed: {key_obj._pk.address(uncompressed=True)}\n")
                    f.write(f"SegWit: {key_obj.segwit_address}\n")
                    
            except Exception as e:
                print(f"[!] Could not generate addresses: {e}")
        else:
            print("❌ Found key but verification FAILED!")
            print(f"   Key: {hex(found_key)}")
            print(f"   This should not happen. Please report this issue.")
    else:
        print("❌ KEY NOT FOUND in specified range")
        print(f"   Search Range: {hex(a)} - {hex(b)}")
        print(f"   Keys Checked: {keys_checked:,}")
        print(f"   Search Time: {search_time:.2f} seconds")
        
        if search_time > 0:
            speed = keys_checked / search_time
            print(f"   Average Speed: {speed:,.0f} keys/sec")
            
            # If we didn't check all keys, show progress
            if keys_checked < total_keys:
                progress = (keys_checked / total_keys) * 100
                print(f"   Progress: {progress:.2f}%")
                remaining = total_keys - keys_checked
                eta = remaining / speed if speed > 0 else 0
                print(f"   Estimated Time Remaining: {eta:.2f} seconds")
    
    # ==========================================================================
    # ADDITIONAL DEBUGGING INFO
    # ==========================================================================
    
    print('\n' + '='*70)
    print('DEBUGGING INFORMATION')
    print('='*70)
    
    # Test a few keys manually
    print("\n[TEST] Manual verification of random keys in range:")
    for i in range(3):
        test_key = random.randint(a, b)
        test_pub = ice.scalar_multiplication(test_key)
        test_pub_hex = test_pub.hex()
        
        # Convert to compressed format for comparison
        x = int(test_pub[1:33].hex(), 16)
        y = int(test_pub[33:].hex(), 16)
        prefix = '02' if y % 2 == 0 else '03'
        compressed = prefix + format(x, '064x')
        
        print(f"  Test {i+1}: Key={hex(test_key)}, Pub={compressed[:20]}...")
    
    print("\n[+] Program completed.")

# ==============================================================================
# ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Search interrupted by user")
    except Exception as e:
        print(f"\n[-] Fatal error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\n[+] Exiting...")
