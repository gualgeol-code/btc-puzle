# -*- coding: utf-8 -*-
"""
BSGS GPU Tool - Simple Version
Usage: Jalankan langsung tanpa parameter command line
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

# ==============================================================================
# KONFIGURASI PARAMETER (SIMPAN DI SINI)
# ==============================================================================

# Public Key target (format hex compressed/uncompressed)
PUBLIC_KEY = "033c4a45cbd643ff97d77f41ea37e843648d50fd894b864b0d52febc62f6454f7c"

# Total random search attempts per loop
N_ATTEMPTS = 100000000000000000  # 100 Quintillion

# Konfigurasi GPU
GPU_DEVICE = 0
GPU_THREADS = 64
GPU_BLOCKS = 10
GPU_POINTS = 256
BP_SIZE = 500000  # bP Table Elements for GPU

# Range keyspace (hex) untuk pencarian
KEYSPACE_MIN = 0x80000
KEYSPACE_MAX = 0xfffff

# Mode pencarian (True untuk random 100%)
RANDOM_MODE = True

# Output file
OUTPUT_FILE = "found_keys.txt"

# ==============================================================================
# FUNGSI UTILITAS (TIDAK DIUBAH)
# ==============================================================================

# Function to generate a random key within the range
def randk(a, b):
    return random.SystemRandom().randint(a, b)

def pub2upub(pub_hex):
    """Convert compressed/uncompressed public key to uncompressed format"""
    x = int(pub_hex[2:66], 16)
    if len(pub_hex) < 70:
        y = bit.format.x_to_y(x, int(pub_hex[:2], 16) % 2)
    else:
        y = int(pub_hex[66:], 16)
    return bytes.fromhex('04' + hex(x)[2:].zfill(64) + hex(y)[2:].zfill(64))

# ==============================================================================
# INISIALISASI PROGRAM
# ==============================================================================

print('\n' + '='*60)
print('BSGS GPU Tool - Simple Configuration')
print('='*60)

# Konversi keyspace
a, b = KEYSPACE_MIN, KEYSPACE_MAX
if a > b:
    a, b = b, a  # Pastikan a < b

# Hitung GPU bits
gpu_bits = int(math.log2(BP_SIZE)) if BP_SIZE > 0 else 20

# Tampilkan konfigurasi
print(f'[+] Public Key Target: {PUBLIC_KEY[:20]}...{PUBLIC_KEY[-20:]}')
print(f'[+] Keyspace Range: {hex(a)} - {hex(b)}')
print(f'[+] Range Size: {(b - a):,} keys')
print(f'[+] Search Mode: {"100% Random" if RANDOM_MODE else "Sequential"}')
print(f'[+] GPU Device: {GPU_DEVICE}, Threads: {GPU_THREADS}, Blocks: {GPU_BLOCKS}')
print(f'[+] Attempts per Loop: {N_ATTEMPTS:,}')
print('='*60)
print('[+] Starting Program.... Please Wait!\n')

# ==============================================================================
# LOAD LIBRARY GPU (TIDAK DIUBAH)
# ==============================================================================

if platform.system().lower().startswith('win'):
    dllfile = 'bt2.dll'
    if os.path.isfile(dllfile):
        pathdll = os.path.realpath(dllfile)
        bsgsgpu = ctypes.CDLL(pathdll)
    else:
        print(f'[-] ERROR: File {dllfile} not found')
        sys.exit(1)
elif platform.system().lower().startswith('lin'):
    dllfile = 'bt2.so'
    if os.path.isfile(dllfile):
        pathdll = os.path.realpath(dllfile)
        bsgsgpu = ctypes.CDLL(pathdll)
    else:
        print(f'[-] ERROR: File {dllfile} not found')
        sys.exit(1)
else:
    print('[-] Unsupported Platform. Only Windows and Linux are supported')
    sys.exit(1)

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

# ==============================================================================
# PREPARE DATA UNTUK GPU
# ==============================================================================

try:
    P = pub2upub(PUBLIC_KEY)
    G = ice.scalar_multiplication(1)
    P3 = ice.point_loop_addition(BP_SIZE, P, G)
except Exception as e:
    print(f'[-] ERROR preparing data: {e}')
    sys.exit(1)

# ==============================================================================
# FUNGSI PENCARIAN UTAMA
# ==============================================================================

def search_range(k1, k2):
    """Search in a specific range and return result"""
    if k1 > k2:
        k1, k2 = k2, k1
    
    st_en = hex(k1)[2:] + ':' + hex(k2)[2:]
    start_time = time.time()
    
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
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    # Decode result
    pvk = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
    bsgsgpu.free_memory(res)
    
    return pvk, elapsed_time

# ==============================================================================
# LOOP PENCARIAN UTAMA
# ==============================================================================

search_count = 0
total_keys_searched = 0
start_total_time = time.time()

try:
    while True:
        # Handle Ctrl+C
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        
        # Tentukan range untuk pencarian
        if RANDOM_MODE:
            # Mode random: pilih range acak dalam keyspace
            k1 = randk(a, b)
            k2 = randk(a, b)
        else:
            # Mode sequential: lanjut dari posisi terakhir
            # (Implementasi dasar, bisa dikembangkan lebih lanjut)
            k1 = a + (search_count * N_ATTEMPTS)
            k2 = k1 + N_ATTEMPTS
            if k2 > b:
                k2 = b
        
        print(f'\n[+] Searching range {search_count + 1}:')
        print(f'    Start: {hex(k1)}')
        print(f'    End:   {hex(k2)}')
        
        # Lakukan pencarian
        pvk, elapsed = search_range(k1, k2)
        
        # Hitung statistik
        search_count += 1
        keys_this_search = k2 - k1 if k2 > k1 else k1 - k2
        total_keys_searched += keys_this_search
        keys_per_sec = keys_this_search / elapsed if elapsed > 0 else 0
        
        print(f'    Time: {elapsed:.2f} seconds')
        print(f'    Speed: {keys_per_sec:,.0f} keys/sec')
        
        # Periksa hasil
        if pvk and pvk != '':
            print(f'\n[!] Possible key found: {pvk}')
            
            try:
                # Verifikasi key
                foundpub = bit.Key.from_int(int(pvk, 16)).public_key
                
                # Cari di P3 table
                if isinstance(P3, bytes):
                    idx = P3.find(foundpub[1:33])
                else:
                    idx = P3.find(foundpub[1:33].encode('utf-8'))
                
                if idx >= 0:
                    BSGS_Key = int(pvk, 16) - (((idx - 1) // 65) + 1)
                    
                    print('\n' + '='*60)
                    print('✅ KEY FOUND!')
                    print('='*60)
                    print(f'Private Key: {hex(BSGS_Key)}')
                    print(f'Public Key:  {foundpub}')
                    print('='*60)
                    
                    # Simpan ke file
                    with open(OUTPUT_FILE, "a") as f:
                        f.write(f"Private Key: {hex(BSGS_Key)}\n")
                        f.write(f"Public Key: {foundpub}\n")
                        f.write(f"Found at: {time.ctime()}\n")
                        f.write('='*60 + '\n\n')
                    
                    print(f'[+] Result saved to {OUTPUT_FILE}')
                    break
                else:
                    print(f'[-] False positive, continuing search...')
            except Exception as e:
                print(f'[-] Error verifying key: {e}')
        
        # Tampilkan statistik berkala
        if search_count % 5 == 0:
            total_time = time.time() - start_total_time
            avg_speed = total_keys_searched / total_time if total_time > 0 else 0
            
            print('\n' + '-'*50)
            print('📊 SEARCH STATISTICS:')
            print(f'   Total ranges searched: {search_count}')
            print(f'   Total keys checked: {total_keys_searched:,}')
            print(f'   Total time: {total_time:.2f} seconds')
            print(f'   Average speed: {avg_speed:,.0f} keys/sec')
            print(f'   Progress: {(total_keys_searched/(b-a)*100):.10f}%')
            print('-'*50)
            
            # Auto-save checkpoint
            with open("checkpoint.txt", "w") as f:
                f.write(f"Last range: {hex(k1)} - {hex(k2)}\n")
                f.write(f"Total searched: {total_keys_searched:,}\n")
                f.write(f"Time: {time.ctime()}\n")

except KeyboardInterrupt:
    print('\n\n[!] Search interrupted by user')
except Exception as e:
    print(f'\n[-] Unexpected error: {e}')
finally:
    # Tampilkan statistik akhir
    total_time = time.time() - start_total_time
    print('\n' + '='*60)
    print('SEARCH FINISHED')
    print('='*60)
    print(f'Total ranges searched: {search_count}')
    print(f'Total keys checked: {total_keys_searched:,}')
    print(f'Total time: {total_time:.2f} seconds')
    
    if total_time > 0:
        avg_speed = total_keys_searched / total_time
        print(f'Average speed: {avg_speed:,.0f} keys/sec')
        print(f'Estimated time remaining: {((b-a - total_keys_searched)/avg_speed/3600):.2f} hours')
    
    print('='*60)
    print('[+] Program finished. Goodbye!')
