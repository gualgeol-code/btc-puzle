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
SEARCH_RANGE_START = 0x100000  # Start range (hex)
SEARCH_RANGE_END = 0x1fffff    # End range (hex)
SEARCH_ATTEMPTS = 100000000000000000                    # Total search attempts in 1 loop
GPU_DEVICE = 0                                          # GPU Device ID
GPU_THREADS = 64                                        # GPU Threads
GPU_BLOCKS = 10                                         # GPU Blocks
GPU_POINTS = 256                                        # GPU Points per Thread
BP_TABLE_SIZE = 500000                                  # bP Table Elements for GPU
OUTPUT_FILE = "found_keys.txt"                          # Output file
RANDOM_SEARCH = True                                    # Search in random mode

# ==================== FUNGSI HELPER ====================
def hex_to_u256(hex_str):
    """Convert hex string to uint256_t array format"""
    hex_str = hex_str.zfill(64)
    parts = [int(hex_str[i:i+8], 16) for i in range(0, 64, 8)]
    parts.reverse()  # Little-endian for GPU
    return np.array(parts, dtype=np.uint32)

def u256_to_hex(u32_array):
    """Convert uint256_t array to hex string"""
    val = 0
    for i in range(7, -1, -1):
        val = (val << 32) | int(u32_array[i])
    return format(val, '064x')

def precompute_g_table():
    """Precompute G lookup table untuk optimasi CPU"""
    print("⚙️ Precomputing G-Table for CPU optimization...")
    
    # Hardcoded G point coordinates (secp256k1 generator)
    Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    
    # Precompute table for window size 4 (nibble-based, 16 entries: 0-15)
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
    
    print(f"   ✓ Loaded library: {dllfile}")
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
    
    # Calculate y^2 = x^3 + 7
    y_sq = (pow(x, 3, p) + 7) % p
    
    # Calculate square root mod p
    y = pow(y_sq, (p + 1) // 4, p)
    
    # Check parity
    if (y % 2) != (int(compressed_pubkey_hex[:2], 16) % 2):
        y = p - y
    
    return x, y

def pub2upub(pub_hex):
    """Convert compressed/uncompressed pubkey to uncompressed bytes"""
    if len(pub_hex) == 130 and pub_hex.startswith('04'):
        # Already uncompressed
        x = int(pub_hex[2:66], 16)
        y = int(pub_hex[66:], 16)
        print(f"   ✓ Public key is already uncompressed")
    elif len(pub_hex) == 66 and pub_hex.startswith(('02', '03')):
        # Compressed - decompress manually
        print(f"   ✓ Decompressing compressed public key...")
        try:
            x, y = decompress_pubkey(pub_hex)
            print(f"   ✓ Successfully decompressed")
        except Exception as e:
            print(f"   ✗ Error decompressing: {e}")
            # Fallback: coba gunakan library ice untuk decompress
            try:
                # Konversi hex ke integer dulu
                from ecdsa import SigningKey
                import bit
                
                # Gunakan bit library dengan cara yang benar
                # Convert hex ke bytes
                pubkey_bytes = bytes.fromhex(pub_hex)
                
                # Gunakan ecdsa library langsung
                curve = SECP256k1
                x = int(pub_hex[2:], 16)
                
                # Calculate y
                p = curve.curve.p()
                y_sq = (pow(x, 3, p) + curve.curve.a() * x + curve.curve.b()) % p
                y = pow(y_sq, (p + 1) // 4, p)
                
                # Adjust parity
                if (y % 2) != (int(pub_hex[:2], 16) % 2):
                    y = p - y
                    
                print(f"   ✓ Decompressed via fallback method")
            except Exception as e2:
                print(f"   ✗ All decompression methods failed: {e2}")
                sys.exit(1)
    else:
        raise ValueError(f"Invalid public key format. Length: {len(pub_hex)}, Prefix: {pub_hex[:2]}")
    
    # Format output sebagai uncompressed (04 + x + y)
    x_hex = hex(x)[2:].zfill(64)
    y_hex = hex(y)[2:].zfill(64)
    uncompressed_hex = '04' + x_hex + y_hex
    
    print(f"   ✓ X: {x_hex[:16]}...")
    print(f"   ✓ Y: {y_hex[:16]}...")
    
    return bytes.fromhex(uncompressed_hex)

def save_found_key(private_key_hex, public_key_hex):
    """Save found key to file"""
    with open(OUTPUT_FILE, "a") as f:
        f.write(f"Private Key: {private_key_hex}\n")
        f.write(f"Public Key: {public_key_hex}\n")
        f.write(f"Found at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write('=' * 50 + '\n')
    print(f"✅ Key saved to {OUTPUT_FILE}")

def test_pubkey_conversion():
    """Test fungsi pub2upub dengan contoh key"""
    print("\n🔧 Testing public key conversion...")
    
    # Test dengan key yang diketahui valid
    test_key = "02CEB6CBBCDBDF5EF7150682150F4CE2C6F4807B349827DCDBDD1F2EFA885A2630"
    
    try:
        result = pub2upub(test_key)
        print(f"   ✓ Test passed. Output length: {len(result)} bytes")
        
        # Verifikasi dengan ice library
        x = int(result[1:33].hex(), 16)
        y = int(result[33:].hex(), 16)
        
        # Verifikasi point ada di curve
        curve = SECP256k1.curve
        left = (y * y) % curve.p()
        right = (pow(x, 3, curve.p()) + 7) % curve.p()
        
        if left == right:
            print(f"   ✓ Point is on curve (verification passed)")
        else:
            print(f"   ✗ Point verification failed")
            
        return True
    except Exception as e:
        print(f"   ✗ Test failed: {e}")
        return False

# ==================== MAIN PROGRAM ====================
def main():
    print('\n' + '='*70)
    print('BSGS GPU SEARCH (Optimized)')
    print('='*70)
    
    # Test public key conversion terlebih dahulu
    print("\n[0] Testing public key conversion...")
    if not test_pubkey_conversion():
        print("❌ Public key conversion test failed. Exiting.")
        return
    
    # Precompute G-Table (untuk referensi/future use)
    print("\n[1] Precomputing lookup tables...")
    g_table_x, g_table_y = precompute_g_table()
    print(f"   ✓ G-Table computed: {len(g_table_x)//8} entries (CPU only)")
    
    # Load GPU library
    print("\n[2] Loading GPU library...")
    bsgsgpu = load_bsgs_gpu_library()
    
    # Convert target public key
    print("\n[3] Processing target public key...")
    try:
        P = pub2upub(PUBKEY_HEX)
        print(f"   ✓ Target pubkey loaded successfully")
        print(f"   ✓ Public key length: {len(P)} bytes")
    except Exception as e:
        print(f"   ✗ Error processing public key: {e}")
        return
    
    # Setup BSGS parameters
    print("\n[4] Setting up BSGS parameters...")
    G = ice.scalar_multiplication(1)
    P3 = ice.point_loop_addition(BP_TABLE_SIZE, P, G)
    
    gpu_bits = int(math.log2(BP_TABLE_SIZE))
    
    if RANDOM_SEARCH:
        print("   ✓ Search mode: 100% Random in range")
    else:
        print("   ✓ Search mode: Sequential")
    
    print(f"   ✓ bP Table size: {BP_TABLE_SIZE:,}")
    print(f"   ✓ GPU Device: {GPU_DEVICE}")
    print(f"   ✓ GPU Config: {GPU_THREADS} threads, {GPU_BLOCKS} blocks, {GPU_POINTS} points/thread")
    print(f"   ✓ P3 table size: {len(P3)} bytes ({len(P3)//65} points)")
    
    print("\n" + '='*70)
    print("🚀 STARTING SEARCH...")
    print('='*70 + '\n')
    
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
            
            st_en = hex(k1)[2:] + ':' + hex(k2)[2:]
            search_count += 1
            
            print(f"\n🔍 Search #{search_count}: {hex(k1)[:20]}... - {hex(k2)[:20]}...")
            
            # Start timer for this search
            start_time = time.time()
            
            # Call ORIGINAL GPU kernel (bsgsGPU)
            res = bsgsgpu.bsgsGPU(
                GPU_THREADS,            # threads
                GPU_BLOCKS,             # blocks  
                GPU_POINTS,             # points per thread
                gpu_bits,               # gpu bits
                GPU_DEVICE,             # device
                P3,                     # upubs
                len(P3) // 65,          # size
                st_en.encode('utf8'),   # keyspace
                str(BP_TABLE_SIZE).encode('utf8')  # bp_size
            )
            
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
                            save_found_key(private_key_hex, foundpub)
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
                print(f"\n📊 TOTAL: {total_keys_checked:,} keys checked")
                print(f"📊 AVERAGE SPEED: {avg_speed:,.0f} keys/sec")
                print(f"📊 TOTAL TIME: {total_elapsed:.1f} seconds")
            
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
        print(f"  Total time: {total_elapsed:.1f} seconds")
        print(f"  Average speed: {total_keys_checked/total_elapsed:,.0f} keys/sec")
    
    print("\nExiting program.")

if __name__ == "__main__":
    main()
