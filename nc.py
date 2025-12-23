# -*- coding: utf-8 -*-
"""
BSGS GPU Tool - Fixed GPU Version
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
import struct

# ==============================================================================
# KONFIGURASI PARAMETER UNTUK GPU
# ==============================================================================

# Public Key target
PUBLIC_KEY = "033c4a45cbd643ff97d77f41ea37e843648d50fd894b864b0d52febc62f6454f7c"

# Range keyspace untuk pencarian
KEYSPACE_MIN = 0x80000      # 524,288
KEYSPACE_MAX = 0xFFFFF      # 1,048,575

# Konfigurasi GPU - OPTIMAL UNTUK TESLA T4
GPU_DEVICE = 0
GPU_THREADS = 256          # Optimal untuk T4
GPU_BLOCKS = 128           # Optimal untuk T4
GPU_POINTS = 256           # Points per thread
BP_SIZE = 500000           # bP table elements

# Output file
OUTPUT_FILE = "found_keys.txt"

# ==============================================================================
# FUNGSI UTILITAS
# ==============================================================================

def pub2upub(pub_hex):
    """Convert compressed/uncompressed public key to uncompressed format"""
    pub_hex = pub_hex.strip()
    
    if pub_hex.startswith('02') or pub_hex.startswith('03'):
        # Compressed format
        x = int(pub_hex[2:], 16)
        
        # Hitung y dari x menggunakan kurva secp256k1: y² = x³ + 7
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        y_sq = (pow(x, 3, p) + 7) % p
        
        # Hitung y = sqrt(y²) mod p
        y = pow(y_sq, (p + 1) // 4, p)
        
        # Sesuaikan dengan prefix
        if (pub_hex.startswith('02') and y % 2 == 1) or (pub_hex.startswith('03') and y % 2 == 0):
            y = p - y
        
        return bytes.fromhex('04' + format(x, '064x') + format(y, '064x'))
    
    elif pub_hex.startswith('04'):
        # Uncompressed format
        if len(pub_hex) == 130:
            return bytes.fromhex(pub_hex)
        else:
            return bytes.fromhex('04' + pub_hex[2:].zfill(128))
    
    else:
        # Assume uncompressed without prefix
        return bytes.fromhex('04' + pub_hex.zfill(128))

def verify_key(private_key_hex, target_pubkey_hex):
    """Verifikasi bahwa private key menghasilkan public key yang sesuai"""
    try:
        priv_int = int(private_key_hex, 16)
        computed_pub = ice.scalar_multiplication(priv_int)
        target_pub = pub2upub(target_pubkey_hex)
        return computed_pub == target_pub
    except:
        return False

# ==============================================================================
# INISIALISASI GPU LIBRARY
# ==============================================================================

def initialize_gpu_library():
    """Initialize GPU library dengan error handling"""
    print("[+] Initializing GPU library...")
    
    if platform.system().lower().startswith('win'):
        lib_files = ['bt2.dll', 'bsgs.dll', 'gpu_search.dll']
    elif platform.system().lower().startswith('lin'):
        lib_files = ['bt2.so', 'bsgs.so', 'libbt2.so', 'libbsgs.so']
    else:
        print("[-] Unsupported platform")
        return None
    
    # Cari file library
    for lib_file in lib_files:
        if os.path.exists(lib_file):
            try:
                print(f"[+] Found library: {lib_file}")
                bsgsgpu = ctypes.CDLL(os.path.realpath(lib_file))
                
                # Coba setup function prototypes
                try:
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
                    
                    print("[+] GPU library initialized successfully")
                    return bsgsgpu
                except Exception as e:
                    print(f"[-] Error setting up function prototypes: {e}")
                    continue
                    
            except Exception as e:
                print(f"[-] Failed to load {lib_file}: {e}")
                continue
    
    print("[-] No valid GPU library found")
    return None

# ==============================================================================
# PREPARE DATA UNTUK GPU
# ==============================================================================

def prepare_gpu_data(target_pubkey):
    """Siapkan data yang diperlukan untuk GPU"""
    print("[+] Preparing data for GPU...")
    
    try:
        # Convert public key
        P = pub2upub(target_pubkey)
        if P is None or len(P) != 65:
            print("[-] Invalid public key format")
            return None, None
        
        print(f"[+] Public key converted (65 bytes)")
        
        # Generate base point G
        G = ice.scalar_multiplication(1)
        if G is None or len(G) != 65:
            print("[-] Failed to generate base point")
            return None, None
        
        print(f"[+] Base point generated")
        
        # Generate P3 table = P + i*G for i=0..BP_SIZE-1
        print(f"[+] Generating P3 table ({BP_SIZE} points)...")
        P3 = ice.point_loop_addition(BP_SIZE, P, G)
        
        if P3 is None or len(P3) != BP_SIZE * 65:
            print(f"[-] P3 table generation failed. Expected {BP_SIZE*65} bytes, got {len(P3) if P3 else 0}")
            return None, None
        
        print(f"[+] P3 table generated: {len(P3):,} bytes")
        print(f"[+] P3 table points: {len(P3)//65:,}")
        
        return P, P3
        
    except Exception as e:
        print(f"[-] Error preparing GPU data: {e}")
        import traceback
        traceback.print_exc()
        return None, None

# ==============================================================================
# GPU SEARCH FUNCTION
# ==============================================================================

def gpu_search_range(bsgsgpu, P3, start_key, end_key):
    """Search range menggunakan GPU"""
    if start_key > end_key:
        start_key, end_key = end_key, start_key
    
    # Format keyspace string (tanpa 0x)
    keyspace_str = f"{start_key:x}:{end_key:x}"
    
    print(f"[GPU] Searching range: {hex(start_key)} to {hex(end_key)}")
    print(f"[GPU] Keyspace string: {keyspace_str}")
    
    # Hitung bits untuk bloom filter
    gpu_bits = int(math.log2(BP_SIZE)) if BP_SIZE > 0 else 19
    
    start_time = time.time()
    
    try:
        # Panggil fungsi GPU
        res = bsgsgpu.bsgsGPU(
            GPU_THREADS,
            GPU_BLOCKS,
            GPU_POINTS,
            gpu_bits,
            GPU_DEVICE,
            P3,
            len(P3) // 65,
            keyspace_str.encode('utf8'),
            str(BP_SIZE).encode('utf8')
        )
        
        elapsed = time.time() - start_time
        
        if res:
            # Decode result
            pvk_ptr = ctypes.cast(res, ctypes.c_char_p)
            if pvk_ptr.value:
                pvk = pvk_ptr.value.decode('utf8').strip()
            else:
                pvk = ""
            bsgsgpu.free_memory(res)
            
            return pvk, elapsed
        else:
            return "", elapsed
            
    except Exception as e:
        elapsed = time.time() - start_time
        print(f"[GPU] Error during search: {e}")
        return None, elapsed

# ==============================================================================
# MAIN SEARCH FUNCTION
# ==============================================================================

def main():
    print('\n' + '='*70)
    print('BSGS GPU SEARCH TOOL - FIXED VERSION')
    print('='*70)
    
    # Load GPU library
    bsgsgpu = initialize_gpu_library()
    if bsgsgpu is None:
        print("[-] Cannot continue without GPU library")
        return
    
    # Prepare GPU data
    P, P3 = prepare_gpu_data(PUBLIC_KEY)
    if P is None or P3 is None:
        print("[-] Failed to prepare GPU data")
        return
    
    # Set keyspace
    a, b = KEYSPACE_MIN, KEYSPACE_MAX
    if a > b:
        a, b = b, a
    
    total_keys = b - a + 1
    
    print(f"\n[+] Search Configuration:")
    print(f"    Target Public Key: {PUBLIC_KEY[:20]}...{PUBLIC_KEY[-20:]}")
    print(f"    Keyspace Range: {hex(a)} - {hex(b)}")
    print(f"    Total Keys: {total_keys:,}")
    print(f"    GPU Threads: {GPU_THREADS}")
    print(f"    GPU Blocks: {GPU_BLOCKS}")
    print(f"    Points/Thread: {GPU_POINTS}")
    print(f"    BP Size: {BP_SIZE}")
    print('='*70)
    
    # Mulai pencarian
    print("\n[+] Starting GPU search... (Press Ctrl+C to stop)\n")
    
    search_count = 0
    keys_searched = 0
    found_key = None
    start_total_time = time.time()
    
    try:
        # Mode sequential untuk range kecil
        current = a
        chunk_size = BP_SIZE * 4  # Ukuran chunk optimal
        
        while current <= b and found_key is None:
            search_count += 1
            
            # Hitung end untuk chunk ini
            chunk_end = min(current + chunk_size - 1, b)
            if chunk_end < current:
                break
            
            chunk_keys = chunk_end - current + 1
            
            print(f"\n[Search #{search_count}]")
            print(f"    Range: {hex(current)} - {hex(chunk_end)}")
            print(f"    Chunk size: {chunk_keys:,} keys")
            print(f"    Progress: {((current - a) / total_keys * 100):.2f}%")
            
            # Pencarian dengan GPU
            result, elapsed = gpu_search_range(bsgsgpu, P3, current, chunk_end)
            
            if result is None:
                print("[-] GPU search failed, stopping...")
                break
            
            if result and result.strip():
                print(f"[!] GPU returned potential key: {result}")
                
                # Verifikasi key
                if verify_key(result, PUBLIC_KEY):
                    found_key = int(result, 16)
                    print(f"\n✅ KEY FOUND AND VERIFIED!")
                    print(f"   Private Key: {hex(found_key)}")
                    break
                else:
                    print("[-] False positive, continuing...")
            
            # Update statistics
            keys_searched += chunk_keys
            
            if elapsed > 0:
                speed = chunk_keys / elapsed
                total_time = time.time() - start_total_time
                avg_speed = keys_searched / total_time if total_time > 0 else 0
                
                print(f"[Stats] This search: {speed:,.0f} keys/sec")
                print(f"[Stats] Average: {avg_speed:,.0f} keys/sec")
                
                # Estimasi waktu tersisa
                if avg_speed > 0:
                    remaining = total_keys - keys_searched
                    eta = remaining / avg_speed
                    print(f"[Stats] ETA: {eta:.1f} seconds")
            
            # Pindah ke chunk berikutnya
            current = chunk_end + 1
            
            # Checkpoint setiap 5 pencarian
            if search_count % 5 == 0:
                print(f"\n[Checkpoint] Searches: {search_count}, Keys checked: {keys_searched:,}")
    
    except KeyboardInterrupt:
        print("\n\n[!] Search interrupted by user")
    except Exception as e:
        print(f"\n[-] Error during search: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Tampilkan hasil
        total_time = time.time() - start_total_time
        
        print('\n' + '='*70)
        print('SEARCH COMPLETE')
        print('='*70)
        
        if found_key is not None:
            print(f"✅ SUCCESS: Private key found!")
            print(f"   Private Key: {hex(found_key)}")
            print(f"   Search Time: {total_time:.2f} seconds")
            print(f"   Keys Checked: {keys_searched:,}")
            
            # Save to file
            with open(OUTPUT_FILE, "w") as f:
                f.write(f"Private Key Found!\n")
                f.write(f"Time: {time.ctime()}\n")
                f.write(f"Public Key: {PUBLIC_KEY}\n")
                f.write(f"Private Key (hex): {hex(found_key)}\n")
                f.write(f"Private Key (decimal): {found_key}\n")
                f.write(f"Search Range: {hex(a)} - {hex(b)}\n")
                f.write(f"Keys Checked: {keys_searched:,}\n")
                f.write(f"Search Time: {total_time:.2f} seconds\n")
                f.write(f"Speed: {keys_searched/total_time:,.0f} keys/sec\n")
            
            print(f"\n[+] Results saved to {OUTPUT_FILE}")
            
            # Generate Bitcoin addresses
            try:
                from bit import Key
                key_obj = Key.from_int(found_key)
                print(f"\n[+] Bitcoin Addresses:")
                print(f"   Compressed: {key_obj.address}")
                print(f"   SegWit (Bech32): {key_obj.segwit_address}")
                
                with open(OUTPUT_FILE, "a") as f:
                    f.write(f"\nBitcoin Addresses:\n")
                    f.write(f"Compressed: {key_obj.address}\n")
                    f.write(f"SegWit: {key_obj.segwit_address}\n")
                    
            except Exception as e:
                print(f"[!] Could not generate addresses: {e}")
                
        else:
            print(f"❌ Key not found in specified range")
            print(f"   Search Range: {hex(a)} - {hex(b)}")
            print(f"   Keys Checked: {keys_searched:,}")
            print(f"   Search Time: {total_time:.2f} seconds")
            
            if total_time > 0:
                print(f"   Average Speed: {keys_searched/total_time:,.0f} keys/sec")
            
            if keys_searched < total_keys:
                progress = (keys_searched / total_keys) * 100
                print(f"   Progress: {progress:.2f}%")
        
        print('='*70)

# ==============================================================================
# TROUBLESHOOTING FUNCTION
# ==============================================================================

def test_gpu_library():
    """Test fungsi GPU library dengan parameter sederhana"""
    print("\n" + "="*70)
    print("GPU LIBRARY DIAGNOSTIC TEST")
    print("="*70)
    
    # Load library
    bsgsgpu = initialize_gpu_library()
    if bsgsgpu is None:
        return False
    
    # Coba test dengan parameter minimal
    print("\n[+] Testing GPU library with minimal parameters...")
    
    # Buat data test sederhana
    test_priv = 0x12345
    test_pub = ice.scalar_multiplication(test_priv)
    G = ice.scalar_multiplication(1)
    
    # Buat P3 kecil untuk testing
    test_bp_size = 1000
    test_P3 = ice.point_loop_addition(test_bp_size, test_pub, G)
    
    if test_P3 is None:
        print("[-] Failed to create test P3 table")
        return False
    
    # Coba panggil dengan range kecil
    start_key = 0x10000
    end_key = 0x20000
    keyspace_str = f"{start_key:x}:{end_key:x}"
    
    print(f"[Test] Range: {hex(start_key)} - {hex(end_key)}")
    print(f"[Test] Keyspace: {keyspace_str}")
    print(f"[Test] BP Size: {test_bp_size}")
    
    try:
        # Hitung bits
        gpu_bits = int(math.log2(test_bp_size)) if test_bp_size > 0 else 10
        
        # Panggil dengan parameter minimal
        res = bsgsgpu.bsgsGPU(
            16,  # threads
            8,   # blocks
            64,  # points
            gpu_bits,
            0,   # device
            test_P3,
            len(test_P3) // 65,
            keyspace_str.encode('utf8'),
            str(test_bp_size).encode('utf8')
        )
        
        if res:
            pvk_ptr = ctypes.cast(res, ctypes.c_char_p)
            if pvk_ptr.value:
                result = pvk_ptr.value.decode('utf8').strip()
                print(f"[Test] GPU returned: {result}")
            else:
                print("[Test] GPU returned empty result")
            bsgsgpu.free_memory(res)
        else:
            print("[Test] GPU returned NULL")
        
        print("[+] GPU library test completed")
        return True
        
    except Exception as e:
        print(f"[-] GPU library test failed: {e}")
        return False

# ==============================================================================
# ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    print("\n" + "="*70)
    print("BITCOIN PRIVATE KEY SEARCH - GPU VERSION")
    print("="*70)
    
    # Jalankan diagnostic test terlebih dahulu
    if not test_gpu_library():
        print("\n[!] GPU library diagnostic test failed.")
        print("[!] Trying to continue anyway...\n")
    
    # Jalankan pencarian utama
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Program interrupted by user")
    except Exception as e:
        print(f"\n[-] Fatal error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\n[+] Program terminated")
