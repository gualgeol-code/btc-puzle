# -*- coding: utf-8 -*-
"""
BSGS GPU Tool - Optimized Version
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

# ==============================================================================
# KONFIGURASI PARAMETER - OPTIMIZED FOR SMALL RANGE
# ==============================================================================

# Public Key target (format hex compressed/uncompressed)
PUBLIC_KEY = "033c4a45cbd643ff97d77f41ea37e843648d50fd894b864b0d52febc62f6454f7c"

# Private key yang diketahui untuk testing (jika ada)
# Hapus atau comment jika tidak diketahui
# KNOWN_PRIVATE_KEY = 0xABCD1234

# Range keyspace (hex) untuk pencarian - KECIL untuk testing
KEYSPACE_MIN = 0x80000      # 524,288
KEYSPACE_MAX = 0xFFFFF      # 1,048,575

# Konfigurasi GPU - OPTIMIZED FOR SMALL RANGE
GPU_DEVICE = 0
GPU_THREADS = 32           # Reduced for small range
GPU_BLOCKS = 8             # Reduced for small range
GPU_POINTS = 128           # Reduced for small range
BP_SIZE = 65536            # Power of 2: 2^16 = 65536

# Mode pencarian
RANDOM_MODE = False        # Sequential untuk range kecil

# Chunk size - sesuaikan dengan BP_SIZE
CHUNK_SIZE = BP_SIZE * 4   # 4x BP_SIZE untuk optimal

# Output file
OUTPUT_FILE = "found_keys.txt"

# ==============================================================================
# FUNGSI UTILITAS
# ==============================================================================

def randk(a, b):
    """Generate random key dalam range [a, b]"""
    return random.SystemRandom().randint(a, b)

def pub2upub(pub_hex):
    """Convert compressed/uncompressed public key to uncompressed format"""
    # Pastikan prefix ada
    if not pub_hex.startswith(('02', '03', '04')):
        # Tambahkan prefix 02 jika tidak ada (asumsi compressed even)
        pub_hex = '02' + pub_hex
    
    if pub_hex.startswith('02') or pub_hex.startswith('03'):
        # Compressed format
        x = int(pub_hex[2:], 16)
        # Hitung y dari x
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        y_sq = (pow(x, 3, p) + 7) % p
        y = pow(y_sq, (p + 1) // 4, p)
        
        # Sesuaikan dengan prefix
        if (pub_hex.startswith('02') and y % 2 == 1) or (pub_hex.startswith('03') and y % 2 == 0):
            y = p - y
        
        return bytes.fromhex('04' + format(x, '064x') + format(y, '064x'))
    
    elif pub_hex.startswith('04'):
        # Uncompressed format
        if len(pub_hex) == 130:  # 2 + 64 + 64
            return bytes.fromhex(pub_hex)
        else:
            # Pad jika perlu
            data = pub_hex[2:]  # Remove '04'
            if len(data) < 128:
                data = data.zfill(128)
            return bytes.fromhex('04' + data)
    
    return None

def get_pubkey_hash(pubkey_bytes):
    """Get SHA256 hash of public key"""
    return hashlib.sha256(pubkey_bytes).hexdigest()

# ==============================================================================
# INISIALISASI PROGRAM
# ==============================================================================

print('\n' + '='*70)
print('BSGS GPU Tool - Optimized for Small Range')
print('='*70)

# Konversi keyspace
a, b = KEYSPACE_MIN, KEYSPACE_MAX
if a > b:
    a, b = b, a

# Hitung total keys
total_keys = b - a + 1

# Hitung GPU bits (harus log2 dari BP_SIZE)
gpu_bits = int(math.log2(BP_SIZE))

# Tampilkan konfigurasi
print(f'[+] Public Key Target: {PUBLIC_KEY[:20]}...{PUBLIC_KEY[-20:]}')
print(f'[+] Keyspace Range: {hex(a)} - {hex(b)}')
print(f'[+] Range Size: {total_keys:,} keys ({int(math.log2(total_keys))} bits)')
print(f'[+] Search Mode: {"Random" if RANDOM_MODE else "Sequential"}')
print(f'[+] Chunk Size: {CHUNK_SIZE:,} keys')
print(f'[+] GPU Config: Device={GPU_DEVICE}, Threads={GPU_THREADS}, Blocks={GPU_BLOCKS}, Points={GPU_POINTS}')
print(f'[+] BP Size: {BP_SIZE:,} (2^{gpu_bits})')
print(f'[+] Expected P3 table size: {BP_SIZE * 65:,} bytes ({BP_SIZE} points)')
print('='*70)

# ==============================================================================
# LOAD DAN INISIALISASI LIBRARY GPU
# ==============================================================================

print('[1/4] Loading GPU library...')

# Cari file library
library_files = []
for f in os.listdir('.'):
    if f.endswith(('.dll', '.so')):
        library_files.append(f)

print(f'    Found library files: {library_files}')

if platform.system().lower().startswith('win'):
    target_lib = 'bt2.dll'
    alt_libs = [f for f in library_files if f.endswith('.dll') and 'bt' in f.lower()]
elif platform.system().lower().startswith('lin'):
    target_lib = 'bt2.so'
    alt_libs = [f for f in library_files if f.endswith('.so') and 'bt' in f.lower()]
else:
    print('[-] Unsupported platform')
    sys.exit(1)

# Pilih library
if os.path.isfile(target_lib):
    lib_path = os.path.realpath(target_lib)
    print(f'    Using primary library: {target_lib}')
elif alt_libs:
    lib_path = os.path.realpath(alt_libs[0])
    print(f'    Using alternative library: {alt_libs[0]}')
else:
    print(f'[-] No GPU library found. Looking for: {target_lib}')
    print(f'    Available files: {library_files}')
    sys.exit(1)

try:
    bsgsgpu = ctypes.CDLL(lib_path)
    print(f'    Successfully loaded: {lib_path}')
except Exception as e:
    print(f'[-] Failed to load library: {e}')
    sys.exit(1)

# Setup function prototypes
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
    print('    Function prototypes set')
except Exception as e:
    print(f'[-] Error setting function prototypes: {e}')
    sys.exit(1)

# ==============================================================================
# PREPARE DATA UNTUK GPU
# ==============================================================================

print('[2/4] Preparing data for GPU...')

try:
    # Konversi public key ke uncompressed
    P = pub2upub(PUBLIC_KEY)
    if P is None:
        print('[-] Failed to convert public key')
        sys.exit(1)
    
    print(f'    Public key converted: {P.hex()[:20]}...')
    print(f'    Public key length: {len(P)} bytes')
    
    # Generate base point G
    G = ice.scalar_multiplication(1)
    print(f'    Base point G generated: {G.hex()[:20]}...')
    
    # Generate P3 table = P + i*G for i=0..BP_SIZE-1
    print(f'    Generating P3 table ({BP_SIZE} points)...')
    P3 = ice.point_loop_addition(BP_SIZE, P, G)
    
    print(f'    P3 table generated: {len(P3):,} bytes')
    print(f'    P3 table points: {len(P3)//65:,}')
    
    # Verifikasi P3 table
    if len(P3) != BP_SIZE * 65:
        print(f'[!] Warning: P3 size mismatch. Expected {BP_SIZE*65}, got {len(P3)}')
    
    # Simpan P3 ke file untuk verifikasi
    with open('p3_table.bin', 'wb') as f:
        f.write(P3)
    print(f'    P3 table saved to p3_table.bin')
    
except Exception as e:
    print(f'[-] Error preparing data: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)

# ==============================================================================
# TEST BSGS ALGORITHM DENGAN RANGE KECIL
# ==============================================================================

print('[3/4] Testing BSGS algorithm...')

def test_small_range_bsgs():
    """Test BSGS dengan range kecil menggunakan Python murni"""
    print('    Testing with Python implementation...')
    
    # Buat dictionary untuk P3 table
    p3_dict = {}
    for i in range(min(1000, BP_SIZE)):  # Test dengan 1000 point pertama
        start_idx = i * 65
        if start_idx + 65 <= len(P3):
            point = P3[start_idx:start_idx+65]
            # Ambil x-coordinate saja (byte 1-33)
            x = point[1:33]
            p3_dict[x] = i
    
    print(f'    Created lookup table with {len(p3_dict)} points')
    
    # Test dengan beberapa private key
    test_keys = [0x80000, 0x90000, 0xA0000, 0xB0000, 0xC0000, 0xD0000, 0xE0000, 0xF0000]
    
    for test_key in test_keys:
        # Hitung public key dari test key
        test_pub = ice.scalar_multiplication(test_key)
        test_x = test_pub[1:33]
        
        if test_x in p3_dict:
            idx = p3_dict[test_x]
            print(f'    Found match! Key={hex(test_key)}, idx={idx}')
            return True
    
    print('    No matches found in test')
    return False

# Jalankan test
test_small_range_bsgs()

# ==============================================================================
# FUNGSI PENCARIAN UTAMA
# ==============================================================================

print('[4/4] Setting up search functions...')

def search_range_gpu(k1, k2):
    """Search in range [k1, k2] using GPU"""
    if k1 > k2:
        k1, k2 = k2, k1
    
    # Format keyspace string
    st_en = f"{k1:0x}:{k2:x}"
    
    print(f'    GPU Search: {hex(k1)} to {hex(k2)}')
    print(f'    Range size: {k2 - k1 + 1:,} keys')
    print(f'    Keyspace string: {st_en}')
    
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
            st_en.encode('utf8'),
            str(BP_SIZE).encode('utf8')
        )
        
        elapsed = time.time() - start_time
        
        if res:
            # Decode result
            pvk_ptr = ctypes.cast(res, ctypes.c_char_p)
            if pvk_ptr.value:
                pvk = pvk_ptr.value.decode('utf8')
            else:
                pvk = ''
            bsgsgpu.free_memory(res)
            
            return pvk, elapsed
        else:
            return '', elapsed
            
    except Exception as e:
        elapsed = time.time() - start_time
        print(f'    GPU Error: {e}')
        return None, elapsed

# ==============================================================================
# LOOP PENCARIAN UTAMA
# ==============================================================================

print('\n' + '='*70)
print('STARTING SEARCH...')
print('='*70)
print('Press Ctrl+C to stop at any time\n')

search_count = 0
keys_searched = 0
found = False
start_total_time = time.time()

try:
    if RANDOM_MODE:
        # MODE RANDOM
        print('[+] Random search mode')
        while not found and search_count < 100:  # Batasi untuk testing
            search_count += 1
            
            # Generate random range
            range_size = min(CHUNK_SIZE, total_keys)
            k1 = randk(a, b - range_size)
            k2 = k1 + range_size - 1
            
            print(f'\n[Search #{search_count}] Random range')
            result, elapsed = search_range_gpu(k1, k2)
            
            if result and result.strip():
                print(f'[!] Possible key found: {result}')
                # Verifikasi sederhana
                try:
                    test_pub = ice.scalar_multiplication(int(result, 16))
                    if test_pub == P:
                        print('✅ KEY VERIFIED!')
                        found = True
                        break
                    else:
                        print('[-] False positive')
                except:
                    print('[-] Invalid key format')
            
            if elapsed > 0:
                speed = range_size / elapsed
                print(f'[Stats] Speed: {speed:,.0f} keys/sec')
    
    else:
        # MODE SEQUENTIAL
        print('[+] Sequential search mode')
        current = a
        
        while current <= b and not found:
            search_count += 1
            
            # Hitung end untuk chunk ini
            chunk_end = min(current + CHUNK_SIZE - 1, b)
            
            # Pastikan chunk tidak kosong
            if chunk_end < current:
                break
            
            print(f'\n[Search #{search_count}]')
            print(f'    Current: {hex(current)} ({(current - a) / total_keys * 100:.2f}%)')
            print(f'    Chunk: {hex(current)} - {hex(chunk_end)}')
            print(f'    Chunk size: {chunk_end - current + 1:,} keys')
            
            # Pencarian dengan GPU
            result, elapsed = search_range_gpu(current, chunk_end)
            
            # Update statistics
            chunk_keys = chunk_end - current + 1
            keys_searched += chunk_keys
            
            if result and result.strip():
                print(f'[!] GPU returned: {result}')
                
                # Verifikasi key
                try:
                    result_int = int(result, 16)
                    test_pub = ice.scalar_multiplication(result_int)
                    
                    # Bandingkan dengan target
                    if test_pub == P:
                        print('\n' + '='*60)
                        print('✅ KEY FOUND AND VERIFIED!')
                        print('='*60)
                        print(f'Private Key: 0x{result}')
                        print(f'Public Key: {PUBLIC_KEY}')
                        print(f'Found in range: {hex(current)} - {hex(chunk_end)}')
                        print('='*60)
                        
                        # Simpan ke file
                        with open(OUTPUT_FILE, "a") as f:
                            f.write(f"Private Key: 0x{result}\n")
                            f.write(f"Public Key: {PUBLIC_KEY}\n")
                            f.write(f"Range: {hex(current)} - {hex(chunk_end)}\n")
                            f.write(f"Time: {time.ctime()}\n")
                            f.write('='*60 + '\n\n')
                        
                        found = True
                        break
                    else:
                        print('[-] False positive - public key mismatch')
                except Exception as e:
                    print(f'[-] Verification error: {e}')
            
            # Tampilkan statistik
            if elapsed > 0:
                speed = chunk_keys / elapsed
                total_time = time.time() - start_total_time
                avg_speed = keys_searched / total_time if total_time > 0 else 0
                
                print(f'[Stats] This search: {speed:,.0f} keys/sec')
                print(f'[Stats] Average: {avg_speed:,.0f} keys/sec')
                print(f'[Stats] Progress: {keys_searched/total_keys*100:.2f}%')
                
                # Estimasi waktu tersisa
                remaining = total_keys - keys_searched
                if avg_speed > 0:
                    eta = remaining / avg_speed
                    print(f'[Stats] ETA: {eta/60:.1f} minutes')
            
            # Pindah ke chunk berikutnya
            current = chunk_end + 1
            
            # Checkpoint
            if search_count % 5 == 0:
                print(f'\n[Checkpoint] Searches: {search_count}, Keys: {keys_searched:,}')

except KeyboardInterrupt:
    print('\n\n[!] Search interrupted by user')
except Exception as e:
    print(f'\n[-] Error: {e}')
    import traceback
    traceback.print_exc()
finally:
    # Tampilkan statistik akhir
    total_time = time.time() - start_total_time
    
    print('\n' + '='*70)
    print('SEARCH COMPLETE')
    print('='*70)
    print(f'Searches performed: {search_count}')
    print(f'Total keys checked: {keys_searched:,}')
    print(f'Total time: {total_time:.2f} seconds')
    
    if total_time > 0:
        avg_speed = keys_searched / total_time
        print(f'Average speed: {avg_speed:,.0f} keys/sec')
    
    if found:
        print(f'✅ SUCCESS: Key found and saved to {OUTPUT_FILE}')
    else:
        print('❌ Key not found in specified range')
        print('\n[Debug Info]')
        print(f'  - Target Public Key: {PUBLIC_KEY}')
        print(f'  - Range: {hex(a)} - {hex(b)}')
        print(f'  - P3 table points: {len(P3)//65}')
        print(f'  - Last position: {hex(current) if "current" in locals() else "N/A"}')
    
    print('='*70)

# ==============================================================================
# ALTERNATIVE: BRUTE FORCE PYTHON UNTUK RANGE SANGAT KECIL
# ==============================================================================

def brute_force_small_range():
    """Brute force dengan Python untuk range sangat kecil"""
    print('\n' + '='*70)
    print('ATTEMPTING BRUTE FORCE (Python)')
    print('='*70)
    
    start = a
    end = min(a + 10000, b)  # Coba 10,000 keys pertama
    
    print(f'Brute forcing range: {hex(start)} - {hex(end)}')
    print(f'Keys to check: {end - start + 1:,}')
    
    start_time = time.time()
    
    for k in range(start, end + 1):
        # Hitung public key
        pub = ice.scalar_multiplication(k)
        
        # Bandingkan dengan target
        if pub == P:
            elapsed = time.time() - start_time
            speed = (k - start + 1) / elapsed if elapsed > 0 else 0
            
            print(f'\n✅ KEY FOUND VIA BRUTE FORCE!')
            print(f'Private Key: {hex(k)}')
            print(f'Time: {elapsed:.2f}s')
            print(f'Speed: {speed:,.0f} keys/sec')
            
            with open(OUTPUT_FILE, "a") as f:
                f.write(f"\n[Brute Force Result]\n")
                f.write(f"Private Key: {hex(k)}\n")
                f.write(f"Time: {elapsed:.2f}s\n")
                f.write(f"Keys checked: {k - start + 1}\n")
            
            return True
        
        # Progress indicator
        if (k - start) % 1000 == 0:
            elapsed = time.time() - start_time
            speed = (k - start + 1) / elapsed if elapsed > 0 else 0
            print(f'  Checked {k - start + 1:,} keys ({speed:,.0f} keys/sec)', end='\r')
    
    elapsed = time.time() - start_time
    print(f'\nBrute force completed in {elapsed:.2f}s')
    return False

# Jika GPU gagal, coba brute force untuk range kecil
if not found and total_keys <= 100000:
    print('\n[+] Attempting Python brute force as fallback...')
    brute_force_small_range()

print('\n[+] Program finished.')
