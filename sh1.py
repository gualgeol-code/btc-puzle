# -*- coding: utf-8 -*-
"""
Upgraded BSGS GPU Tool dengan G-Table Precomputation
Search 1 pubkey dengan BSGS algorithm menggunakan GPU
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
import numpy as np
import ecdsa
from ecdsa.curves import SECP256k1

# ==================== KONFIGURASI ====================
PUBKEY_HEX = "031a746c78f72754e0be046186df8a20cdce5c79b2eda76013c647af08d306e49e"  # Public Key target
SEARCH_RANGE_START = 0x100000  # Start range (hex) - Diperkecil untuk testing
SEARCH_RANGE_END = 0x1FFFFF    # End range (hex) - Diperkecil untuk testing
GPU_DEVICE = 0                  # GPU Device ID
GPU_THREADS = 64                # GPU Threads
GPU_BLOCKS = 10                 # GPU Blocks  
GPU_POINTS = 256                # GPU Points per Thread
BP_TABLE_SIZE = 50000           # bP Table Elements untuk range kecil
OUTPUT_FILE = "found_keys.txt"  # Output file
RANDOM_SEARCH = True            # Search in random mode
DEBUG_MODE = True               # Enable debug output

# ==================== FUNGSI HELPER ====================
def hex_to_u256(hex_str):
    """Convert hex string to uint256_t array format"""
    hex_str = hex_str.zfill(64)
    parts = [int(hex_str[i:i+8], 16) for i in range(0, 64, 8)]
    parts.reverse()  # Little-endian for GPU
    return np.array(parts, dtype=np.uint32)

def print_debug(msg):
    """Print debug message jika DEBUG_MODE aktif"""
    if DEBUG_MODE:
        print(f"[DEBUG] {msg}")

def precompute_g_table():
    """Precompute G lookup table untuk optimasi CPU"""
    print("⚙️ Precomputing G-Table for CPU optimization...")
    
    table_x = []
    table_y = []
    
    # Entry 0 (point at infinity)
    table_x.append(np.zeros(8, dtype=np.uint32))
    table_y.append(np.zeros(8, dtype=np.uint32))
    
    # Compute G * i for i = 1..15 menggunakan library secp256k1_lib
    for i in range(1, 16):
        pubkey_bytes = ice.scalar_multiplication(i)
        
        # Parse uncompressed pubkey (65 bytes): 04 + X(32) + Y(32)
        x_hex = pubkey_bytes[1:33].hex()
        y_hex = pubkey_bytes[33:65].hex()
        
        # Convert ke format GPU
        table_x.append(hex_to_u256(x_hex))
        table_y.append(hex_to_u256(y_hex))
        
        if i <= 3:
            print(f"  G[{i}] = ({x_hex[:16]}..., {y_hex[:16]}...)")
    
    print(f"  ✓ G-Table computed: 16 entries")
    return np.array(table_x).flatten(), np.array(table_y).flatten()

def load_bsgs_gpu_library():
    """Load BSGS GPU library"""
    if platform.system().lower().startswith('win'):
        dllfile = 'bt2.dll'
    elif platform.system().lower().startswith('lin'):
        dllfile = 'bt2.so'
    else:
        print('[-] Unsupported Platform. Only Windows and Linux are supported')
        sys.exit()
    
    if not os.path.isfile(dllfile):
        print(f'File {dllfile} not found')
        sys.exit()
    
    pathdll = os.path.realpath(dllfile)
    bsgsgpu = ctypes.CDLL(pathdll)
    
    # Define argument types untuk fungsi original bsgsGPU
    bsgsgpu.bsgsGPU.argtypes = [
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
    bsgsgpu.bsgsGPU.restype = ctypes.c_void_p
    bsgsgpu.free_memory.argtypes = [ctypes.c_void_p]
    
    # Coba dapatkan fungsi tambahan untuk debugging
    try:
        bsgsgpu.get_gpu_info = bsgsgpu.get_gpu_info
        bsgsgpu.get_gpu_info.argtypes = [ctypes.c_int]
        bsgsgpu.get_gpu_info.restype = ctypes.c_char_p
        print(f"   ✓ Loaded library with debug functions")
    except:
        print(f"   ✓ Loaded basic library")
    
    print(f"   ✓ Library: {dllfile}")
    return bsgsgpu

def decompress_pubkey(compressed_pubkey_hex):
    """Decompress compressed public key (02/03 prefix)"""
    if not compressed_pubkey_hex.startswith(('02', '03')):
        raise ValueError("Not a compressed public key")
    
    # Parse x coordinate
    x_hex = compressed_pubkey_hex[2:]  # Remove prefix
    x = int(x_hex, 16)
    
    # Curve parameters
    curve = SECP256k1.curve
    p = curve.p()
    
    # Calculate y^2 = x^3 + 7 (untuk secp256k1, a=0, b=7)
    y_sq = (pow(x, 3, p) + 7) % p
    
    # Calculate square root mod p (p ≡ 3 mod 4)
    y = pow(y_sq, (p + 1) // 4, p)
    
    # Check parity
    if (y % 2) != (int(compressed_pubkey_hex[:2], 16) % 2):
        y = p - y
    
    return x, y

def pub2upub(pub_hex):
    """Convert compressed/uncompressed pubkey to uncompressed bytes"""
    print_debug(f"Converting pubkey: {pub_hex[:20]}...")
    
    if len(pub_hex) == 130 and pub_hex.startswith('04'):
        # Already uncompressed
        x = int(pub_hex[2:66], 16)
        y = int(pub_hex[66:], 16)
        print_debug("Public key is already uncompressed")
    elif len(pub_hex) == 66 and pub_hex.startswith(('02', '03')):
        # Compressed - decompress manually
        print_debug("Decompressing compressed public key...")
        x, y = decompress_pubkey(pub_hex)
    else:
        raise ValueError(f"Invalid public key format. Length: {len(pub_hex)}, Prefix: {pub_hex[:2]}")
    
    # Format output sebagai uncompressed (04 + x + y)
    x_hex = hex(x)[2:].zfill(64)
    y_hex = hex(y)[2:].zfill(64)
    uncompressed_hex = '04' + x_hex + y_hex
    
    print_debug(f"X: {x_hex[:16]}...")
    print_debug(f"Y: {y_hex[:16]}...")
    print_debug(f"Uncompressed length: {len(uncompressed_hex)//2} bytes")
    
    return bytes.fromhex(uncompressed_hex)

def validate_bsgs_parameters(P, bp_size):
    """Validasi parameter sebelum memanggil GPU"""
    print("\n[4] Validating BSGS parameters...")
    
    # 1. Validasi public key
    try:
        # Parse public key untuk memastikan valid
        pub_bytes = P
        if len(pub_bytes) != 65:
            raise ValueError(f"Invalid public key length: {len(pub_bytes)}")
        if pub_bytes[0] != 0x04:
            raise ValueError(f"Invalid public key prefix: {hex(pub_bytes[0])}")
        
        x = int(pub_bytes[1:33].hex(), 16)
        y = int(pub_bytes[33:].hex(), 16)
        
        # Verifikasi point ada di curve
        curve = SECP256k1.curve
        p = curve.p()
        left = (y * y) % p
        right = (pow(x, 3, p) + 7) % p
        
        if left != right:
            raise ValueError("Point is not on the secp256k1 curve")
        
        print(f"   ✓ Public key is valid and on curve")
    except Exception as e:
        print(f"   ✗ Public key validation failed: {e}")
        return False
    
    # 2. Validasi bp_size
    if bp_size < 1000:
        print(f"   ⚠️ Warning: bp_size ({bp_size}) might be too small for efficient BSGS")
    elif bp_size > 1000000:
        print(f"   ⚠️ Warning: bp_size ({bp_size}) might be too large for GPU memory")
    
    # 3. Validasi range
    range_size = SEARCH_RANGE_END - SEARCH_RANGE_START
    if range_size < bp_size * 10:
        print(f"   ⚠️ Warning: Range size ({range_size:,}) is small compared to bp_size")
        print(f"   ℹ️  For optimal BSGS: range_size should be >> bp_size^2")
    
    print(f"   ✓ Range: {hex(SEARCH_RANGE_START)} to {hex(SEARCH_RANGE_END)}")
    print(f"   ✓ Range size: {range_size:,} keys")
    
    return True

def calculate_optimal_bp_size(range_size):
    """Hitung optimal bp_size berdasarkan range size"""
    # Rule of thumb untuk BSGS: bp_size ≈ sqrt(range_size)
    optimal = int(math.sqrt(range_size))
    
    # Batasan praktis
    optimal = max(1000, min(optimal, 500000))
    
    # Bulatkan ke kelipatan 1000
    optimal = (optimal // 1000) * 1000
    
    print(f"   ℹ️  Recommended bp_size for range {range_size:,}: {optimal:,}")
    return optimal

# ==================== MAIN PROGRAM ====================
def main():
    print('\n' + '='*70)
    print('BSGS GPU SEARCH (Optimized) - DEBUG MODE')
    print('='*70)
    
    # Load GPU library
    print("\n[1] Loading GPU library...")
    bsgsgpu = load_bsgs_gpu_library()
    
    # Convert target public key
    print("\n[2] Processing target public key...")
    try:
        P = pub2upub(PUBKEY_HEX)
        print(f"   ✓ Target pubkey loaded: {PUBKEY_HEX[:20]}...")
        print(f"   ✓ Public key length: {len(P)} bytes")
    except Exception as e:
        print(f"   ✗ Error processing public key: {e}")
        return
    
    # Setup BSGS parameters
    print("\n[3] Setting up BSGS parameters...")
    
    # Hitung range size dan optimal bp_size
    range_size = SEARCH_RANGE_END - SEARCH_RANGE_START
    print(f"   ✓ Search range: {hex(SEARCH_RANGE_START)} to {hex(SEARCH_RANGE_END)}")
    print(f"   ✓ Range size: {range_size:,} keys")
    print(f"   ✓ Range bits: {range_size.bit_length()} bits")
    
    # Adjust bp_size berdasarkan range
    optimal_bp = calculate_optimal_bp_size(range_size)
    if BP_TABLE_SIZE != optimal_bp:
        print(f"   ⚠️  Adjusting bp_size from {BP_TABLE_SIZE:,} to {optimal_bp:,}")
        bp_size = optimal_bp
    else:
        bp_size = BP_TABLE_SIZE
    
    # Validasi parameter
    if not validate_bsgs_parameters(P, bp_size):
        print("❌ Parameter validation failed. Exiting.")
        return
    
    # Generate P3 table
    print(f"\n[5] Generating P3 table (bp_size = {bp_size:,})...")
    G = ice.scalar_multiplication(1)
    
    try:
        P3 = ice.point_loop_addition(bp_size, P, G)
        print(f"   ✓ P3 table generated: {len(P3)} bytes ({len(P3)//65} points)")
        
        # Verifikasi beberapa point pertama
        if DEBUG_MODE and len(P3) >= 130:
            print_debug(f"First point in P3: {P3[0:65].hex()[:40]}...")
            print_debug(f"Second point in P3: {P3[65:130].hex()[:40]}...")
    except Exception as e:
        print(f"   ✗ Error generating P3 table: {e}")
        # Coba dengan bp_size yang lebih kecil
        bp_size = min(bp_size, 10000)
        print(f"   ⚠️  Retrying with smaller bp_size: {bp_size}")
        P3 = ice.point_loop_addition(bp_size, P, G)
        print(f"   ✓ P3 table generated: {len(P3)} bytes ({len(P3)//65} points)")
    
    gpu_bits = int(math.log2(bp_size))
    print(f"   ✓ GPU bits: {gpu_bits}")
    
    # Konfigurasi GPU
    print(f"\n[6] GPU Configuration:")
    print(f"   ✓ Device: {GPU_DEVICE}")
    print(f"   ✓ Threads: {GPU_THREADS}")
    print(f"   ✓ Blocks: {GPU_BLOCKS}")
    print(f"   ✓ Points per thread: {GPU_POINTS}")
    
    if RANDOM_SEARCH:
        print(f"   ✓ Search mode: Random")
    else:
        print(f"   ✓ Search mode: Sequential")
    
    print("\n" + '='*70)
    print("🚀 STARTING SEARCH...")
    print('='*70)
    
    # Main search loop
    search_count = 0
    total_keys_checked = 0
    start_total_time = time.time()
    
    try:
        while True:
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            
            # Generate search range
            if RANDOM_SEARCH:
                k1 = random.SystemRandom().randint(SEARCH_RANGE_START, SEARCH_RANGE_END)
                k2 = random.SystemRandom().randint(SEARCH_RANGE_START, SEARCH_RANGE_END)
                if k1 > k2:
                    k1, k2 = k2, k1
            else:
                k1 = SEARCH_RANGE_START
                k2 = SEARCH_RANGE_END
            
            # Pastikan range tidak terlalu kecil
            if abs(k2 - k1) < bp_size:
                k2 = k1 + bp_size * 10
                k2 = min(k2, SEARCH_RANGE_END)
            
            st_en = hex(k1)[2:].zfill(16) + ':' + hex(k2)[2:].zfill(16)
            search_count += 1
            
            print(f"\n🔍 Search #{search_count}")
            print(f"   Start: {hex(k1)} ({k1.bit_length()} bits)")
            print(f"   End:   {hex(k2)} ({k2.bit_length()} bits)")
            print(f"   Range size: {abs(k2 - k1):,} keys")
            
            # Start timer for this search
            start_time = time.time()
            
            # Debug: print parameter yang akan dikirim ke GPU
            print_debug(f"Calling bsgsGPU with:")
            print_debug(f"  threads={GPU_THREADS}, blocks={GPU_BLOCKS}, points={GPU_POINTS}")
            print_debug(f"  gpu_bits={gpu_bits}, device={GPU_DEVICE}")
            print_debug(f"  P3 size={len(P3)}, num_points={len(P3)//65}")
            print_debug(f"  keyspace={st_en}")
            print_debug(f"  bp_size={bp_size}")
            
            # Call GPU kernel
            try:
                res = bsgsgpu.bsgsGPU(
                    ctypes.c_uint32(GPU_THREADS),
                    ctypes.c_uint32(GPU_BLOCKS),
                    ctypes.c_uint32(GPU_POINTS),
                    ctypes.c_uint32(gpu_bits),
                    ctypes.c_int(GPU_DEVICE),
                    ctypes.c_char_p(P3),
                    ctypes.c_uint32(len(P3) // 65),
                    ctypes.c_char_p(st_en.encode('utf8')),
                    ctypes.c_char_p(str(bp_size).encode('utf8'))
                )
                
                print(f"   ✅ GPU kernel called successfully")
                
            except Exception as e:
                print(f"   ❌ Error calling GPU kernel: {e}")
                print(f"   ⚠️  Trying with different parameters...")
                
                # Coba dengan parameter yang lebih konservatif
                try:
                    res = bsgsgpu.bsgsGPU(
                        ctypes.c_uint32(32),  # Kurangi threads
                        ctypes.c_uint32(5),   # Kurangi blocks
                        ctypes.c_uint32(128), # Kurangi points
                        ctypes.c_uint32(gpu_bits),
                        ctypes.c_int(GPU_DEVICE),
                        ctypes.c_char_p(P3),
                        ctypes.c_uint32(len(P3) // 65),
                        ctypes.c_char_p(st_en.encode('utf8')),
                        ctypes.c_char_p(str(bp_size).encode('utf8'))
                    )
                    print(f"   ✅ GPU kernel called with conservative parameters")
                except Exception as e2:
                    print(f"   ❌ Still failing: {e2}")
                    print(f"   ⚠️  Skipping this range...")
                    continue
            
            end_time = time.time()
            elapsed_time = end_time - start_time
            
            # Get result
            pvk = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
            bsgsgpu.free_memory(res)
            
            # Calculate speed
            keys_this_search = abs(k2 - k1)
            total_keys_checked += keys_this_search
            total_elapsed = time.time() - start_total_time
            
            if elapsed_time > 0:
                speed = keys_this_search / elapsed_time
                print(f"   ⚡ Speed: {speed:,.0f} keys/sec")
                print(f"   ⏱️  Time: {elapsed_time:.2f} seconds")
            
            if pvk != '':
                print(f"\n🎯 POTENTIAL MATCH FOUND!")
                print(f"   Candidate: {pvk}")
                
                try:
                    # Verify the candidate
                    foundpub = bit.Key.from_int(int(pvk, 16)).public_key
                    
                    # Cari di P3 table
                    found_bytes = bytes.fromhex(foundpub[2:])
                    idx = P3.find(found_bytes[0:32])
                    
                    if idx >= 0 and idx % 65 == 1:
                        BSGS_Key = int(pvk, 16) - (((idx - 1) // 65) + 1)
                        private_key_hex = hex(BSGS_Key)
                        
                        print('\n' + '='*60)
                        print('🎉 KEY FOUND! 🎉')
                        print('='*60)
                        print(f'Private Key: {private_key_hex}')
                        print(f'Public Key: {foundpub}')
                        print('='*60)
                        
                        # Verify dengan library ice
                        verify_pub = ice.scalar_multiplication(BSGS_Key)
                        if verify_pub[1:] == found_bytes:
                            print("✅ Verification: PASSED")
                            with open(OUTPUT_FILE, "a") as f:
                                f.write(f"Private Key: {private_key_hex}\n")
                                f.write(f"Public Key: {foundpub}\n")
                                f.write(f"Found at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                                f.write('=' * 50 + '\n')
                            print(f"✅ Key saved to {OUTPUT_FILE}")
                            break
                        else:
                            print("⚠️ Verification: FAILED - false positive")
                    else:
                        print("⚠️ Candidate not found in bP table - false positive")
                        
                except Exception as e:
                    print(f"⚠️ Error verifying candidate: {e}")
            
            # Print progress summary
            if total_elapsed > 0:
                avg_speed = total_keys_checked / total_elapsed
                print(f"\n📊 PROGRESS:")
                print(f"   Total searches: {search_count}")
                print(f"   Total keys checked: {total_keys_checked:,}")
                print(f"   Total time: {total_elapsed:.1f} seconds")
                print(f"   Average speed: {avg_speed:,.0f} keys/sec")
                
                # Estimasi waktu tersisa
                remaining_keys = (SEARCH_RANGE_END - SEARCH_RANGE_START) - total_keys_checked
                if avg_speed > 0 and remaining_keys > 0:
                    remaining_time = remaining_keys / avg_speed
                    print(f"   Estimated time remaining: {remaining_time:.1f} seconds")
            
            # Jeda singkat antara searches
            time.sleep(0.1)
            
    except KeyboardInterrupt:
        print("\n\n⚠️ Search interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
    
    print('\n' + '='*70)
    print("SEARCH COMPLETED")
    print('='*70)
    
    if total_elapsed > 0:
        print(f"Final Statistics:")
        print(f"  Total searches: {search_count}")
        print(f"  Total keys checked: {total_keys_checked:,}")
        print(f"  Total time: {total_elapsed:.1f} seconds ({total_elapsed/60:.1f} minutes)")
        print(f"  Average speed: {total_keys_checked/total_elapsed:,.0f} keys/sec")
        print(f"  Coverage: {(total_keys_checked/(SEARCH_RANGE_END-SEARCH_RANGE_START)*100):.1f}% of range")
    
    print("\nExiting program.")

if __name__ == "__main__":
    main()
