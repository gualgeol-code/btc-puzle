# -*- coding: utf-8 -*-
"""
BSGS GPU Tool - Simple Version (FIXED)
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

# Private Key yang diketahui untuk testing (HANYA UNTUK TESTING!)
# Ganti dengan private key yang sesuai dengan PUBLIC_KEY di atas
KNOWN_PRIVATE_KEY = 0xd2c55  # Contoh, ganti dengan yang sesuai

# Range keyspace (hex) untuk pencarian
KEYSPACE_MIN = 0x80000
KEYSPACE_MAX = 0xFFFFF

# Konfigurasi GPU
GPU_DEVICE = 0
GPU_THREADS = 64
GPU_BLOCKS = 10
GPU_POINTS = 256
BP_SIZE = 500000  # bP Table Elements for GPU

# Mode pencarian (False untuk sequential, True untuk random)
RANDOM_MODE = False  # Untuk testing, gunakan sequential

# Ukuran chunk untuk setiap pencarian (disesuaikan dengan BP_SIZE)
CHUNK_SIZE = 1000000  # 1 juta keys per chunk

# Output file
OUTPUT_FILE = "found_keys.txt"

# ==============================================================================
# FUNGSI UTILITAS (TIDAK DIUBAH)
# ==============================================================================

def randk(a, b):
    """Generate random key dalam range [a, b]"""
    return random.SystemRandom().randint(a, b)

def pub2upub(pub_hex):
    """Convert compressed/uncompressed public key to uncompressed format"""
    # Pastikan panjang hex genap
    if len(pub_hex) % 2 != 0:
        pub_hex = '0' + pub_hex
    
    # Handle compressed key (02 atau 03)
    if pub_hex.startswith('02') or pub_hex.startswith('03'):
        x = int(pub_hex[2:], 16)
        try:
            # Gunakan library bit untuk mendapatkan y dari x
            y = bit.format.x_to_y(x, int(pub_hex[:2], 16) % 2)
            return bytes.fromhex('04' + hex(x)[2:].zfill(64) + hex(y)[2:].zfill(64))
        except:
            # Fallback: coba hitung y manual
            # y² = x³ + 7 (mod p)
            p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
            y_sq = (pow(x, 3, p) + 7) % p
            y = pow(y_sq, (p + 1) // 4, p)
            if int(pub_hex[:2], 16) % 2 != y % 2:
                y = p - y
            return bytes.fromhex('04' + hex(x)[2:].zfill(64) + hex(y)[2:].zfill(64))
    # Handle uncompressed key (04)
    elif pub_hex.startswith('04'):
        if len(pub_hex) < 130:
            pub_hex = pub_hex[2:]  # Hapus 04
            pub_hex = pub_hex.zfill(128)
        return bytes.fromhex(pub_hex)
    else:
        # Asumsi compressed tanpa prefix
        x = int(pub_hex, 16)
        y = bit.format.x_to_y(x, 0)  # Default even
        return bytes.fromhex('04' + hex(x)[2:].zfill(64) + hex(y)[2:].zfill(64))

# ==============================================================================
# INISIALISASI PROGRAM
# ==============================================================================

print('\n' + '='*70)
print('BSGS GPU Tool - Fixed Version')
print('='*70)

# Konversi keyspace
a, b = KEYSPACE_MIN, KEYSPACE_MAX
if a > b:
    a, b = b, a

# Hitung GPU bits
gpu_bits = int(math.log2(BP_SIZE)) if BP_SIZE > 0 else 20

# Hitung ukuran total keyspace
total_keys = b - a + 1

# Tampilkan konfigurasi
print(f'[+] Public Key Target: {PUBLIC_KEY}')
print(f'[+] Keyspace Range: {hex(a)} - {hex(b)}')
print(f'[+] Range Size: {total_keys:,} keys')
print(f'[+] Search Mode: {"Random" if RANDOM_MODE else "Sequential"}')
print(f'[+] Chunk Size: {CHUNK_SIZE:,} keys per search')
print(f'[+] GPU Device: {GPU_DEVICE}, Threads: {GPU_THREADS}, Blocks: {GPU_BLOCKS}')
print(f'[+] BP Size: {BP_SIZE:,}')
print('='*70)

# ==============================================================================
# LOAD LIBRARY GPU (TIDAK DIUBAH)
# ==============================================================================

print('[+] Loading GPU library...')

if platform.system().lower().startswith('win'):
    dllfile = 'bt2.dll'
    if os.path.isfile(dllfile):
        pathdll = os.path.realpath(dllfile)
        bsgsgpu = ctypes.CDLL(pathdll)
        print(f'[+] Loaded Windows DLL: {dllfile}')
    else:
        print(f'[-] ERROR: File {dllfile} not found')
        # Cari alternatif
        for f in os.listdir('.'):
            if f.endswith('.dll') and 'bt' in f.lower():
                dllfile = f
                pathdll = os.path.realpath(dllfile)
                bsgsgpu = ctypes.CDLL(pathdll)
                print(f'[+] Loaded alternative DLL: {dllfile}')
                break
        else:
            print('[-] No suitable DLL found')
            sys.exit(1)
            
elif platform.system().lower().startswith('lin'):
    dllfile = 'bt2.so'
    if os.path.isfile(dllfile):
        pathdll = os.path.realpath(dllfile)
        bsgsgpu = ctypes.CDLL(pathdll)
        print(f'[+] Loaded Linux SO: {dllfile}')
    else:
        print(f'[-] ERROR: File {dllfile} not found')
        sys.exit(1)
else:
    print('[-] Unsupported Platform')
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

print('[+] GPU library initialized')

# ==============================================================================
# PREPARE DATA UNTUK GPU
# ==============================================================================

print('[+] Preparing data for GPU...')

try:
    P = pub2upub(PUBLIC_KEY)
    print(f'[+] Public key converted: {P.hex()[:20]}...')
    
    # Generate base point G (1*G)
    G = ice.scalar_multiplication(1)
    print(f'[+] Base point generated')
    
    # Generate P3 table = P + i*G for i=0..BP_SIZE-1
    P3 = ice.point_loop_addition(BP_SIZE, P, G)
    print(f'[+] P3 table generated: {len(P3)} bytes ({len(P3)//65} points)')
    
except Exception as e:
    print(f'[-] ERROR preparing data: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)

# ==============================================================================
# FUNGSI PENCARIAN UTAMA
# ==============================================================================

def search_range(k1, k2):
    """Search in a specific range [k1, k2] and return result"""
    if k1 > k2:
        k1, k2 = k2, k1
    
    # Format: start:end
    st_en = f"{hex(k1)[2:]}:{hex(k2)[2:]}"
    
    print(f'[GPU] Searching range: {hex(k1)} to {hex(k2)}')
    print(f'[GPU] Range size: {k2 - k1 + 1:,} keys')
    
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
    except Exception as e:
        print(f'[-] GPU Error: {e}')
        return None, 0
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    # Decode result
    if res:
        pvk_ptr = ctypes.cast(res, ctypes.c_char_p)
        if pvk_ptr.value:
            pvk = pvk_ptr.value.decode('utf8')
        else:
            pvk = ''
        bsgsgpu.free_memory(res)
    else:
        pvk = ''
    
    return pvk, elapsed_time

# ==============================================================================
# FUNGSI VERIFIKASI
# ==============================================================================

def verify_private_key(pvk_hex, target_pubkey):
    """Verifikasi bahwa private key menghasilkan public key yang sesuai"""
    try:
        pvk_int = int(pvk_hex, 16)
        
        # Hitung public key dari private key
        computed_pub = ice.scalar_multiplication(pvk_int)
        
        # Konversi target pubkey ke uncompressed
        target_pub = pub2upub(target_pubkey)
        
        # Bandingkan
        return computed_pub == target_pub
    except:
        return False

# ==============================================================================
# LOOP PENCARIAN UTAMA
# ==============================================================================

print('\n[+] Starting search... Press Ctrl+C to stop\n')

search_count = 0
keys_searched = 0
found = False
start_total_time = time.time()

try:
    if RANDOM_MODE:
        # MODE RANDOM
        while not found:
            search_count += 1
            
            # Generate random range
            range_size = min(CHUNK_SIZE, total_keys)
            k1 = randk(a, b - range_size + 1)
            k2 = k1 + range_size - 1
            
            print(f'\n[Search #{search_count}]')
            result, elapsed = search_range(k1, k2)
            
            if result and result.strip():
                print(f'[!] Possible match found: {result}')
                
                # Verifikasi
                if verify_private_key(result, PUBLIC_KEY):
                    print('\n' + '='*60)
                    print('✅ KEY FOUND AND VERIFIED!')
                    print('='*60)
                    print(f'Private Key: 0x{result}')
                    print(f'Range: {hex(k1)} - {hex(k2)}')
                    print('='*60)
                    
                    # Simpan ke file
                    with open(OUTPUT_FILE, "a") as f:
                        f.write(f"Private Key: 0x{result}\n")
                        f.write(f"Public Key: {PUBLIC_KEY}\n")
                        f.write(f"Found in range: {hex(k1)} - {hex(k2)}\n")
                        f.write(f"Time: {time.ctime()}\n")
                        f.write('='*60 + '\n\n')
                    
                    found = True
                    break
                else:
                    print('[-] False positive, continuing...')
            
            # Update statistics
            if elapsed > 0:
                speed = range_size / elapsed
                print(f'[Stats] Speed: {speed:,.0f} keys/sec')
            
            # Checkpoint setiap 10 pencarian
            if search_count % 10 == 0:
                total_elapsed = time.time() - start_total_time
                print(f'\n[Checkpoint] Searches: {search_count}, Total time: {total_elapsed:.1f}s')
    
    else:
        # MODE SEQUENTIAL
        current_start = a
        
        while current_start <= b and not found:
            search_count += 1
            
            # Hitung end untuk chunk ini
            current_end = min(current_start + CHUNK_SIZE - 1, b)
            
            print(f'\n[Search #{search_count}]')
            print(f'Progress: {((current_start - a) / total_keys * 100):.2f}%')
            
            result, elapsed = search_range(current_start, current_end)
            
            if result and result.strip():
                print(f'[!] Possible match found: {result}')
                
                # Verifikasi
                if verify_private_key(result, PUBLIC_KEY):
                    print('\n' + '='*60)
                    print('✅ KEY FOUND AND VERIFIED!')
                    print('='*60)
                    print(f'Private Key: 0x{result}')
                    print(f'Range: {hex(current_start)} - {hex(current_end)}')
                    print('='*60)
                    
                    # Simpan ke file
                    with open(OUTPUT_FILE, "a") as f:
                        f.write(f"Private Key: 0x{result}\n")
                        f.write(f"Public Key: {PUBLIC_KEY}\n")
                        f.write(f"Found in range: {hex(current_start)} - {hex(current_end)}\n")
                        f.write(f"Time: {time.ctime()}\n")
                        f.write('='*60 + '\n\n')
                    
                    found = True
                    break
                else:
                    print('[-] False positive, continuing...')
            
            # Update statistics
            keys_this_search = current_end - current_start + 1
            keys_searched += keys_this_search
            
            if elapsed > 0:
                speed = keys_this_search / elapsed
                total_elapsed = time.time() - start_total_time
                avg_speed = keys_searched / total_elapsed if total_elapsed > 0 else 0
                
                print(f'[Stats] This search: {speed:,.0f} keys/sec')
                print(f'[Stats] Average: {avg_speed:,.0f} keys/sec')
                print(f'[Stats] Total searched: {keys_searched:,} keys')
                
                # Estimasi waktu tersisa
                remaining_keys = total_keys - keys_searched
                if avg_speed > 0:
                    eta_seconds = remaining_keys / avg_speed
                    eta_hours = eta_seconds / 3600
                    print(f'[Stats] ETA: {eta_hours:.2f} hours')
            
            # Pindah ke chunk berikutnya
            current_start = current_end + 1
            
            # Checkpoint setiap 5 pencarian
            if search_count % 5 == 0:
                total_elapsed = time.time() - start_total_time
                progress = (keys_searched / total_keys * 100)
                print(f'\n[Checkpoint] Progress: {progress:.2f}%, Total time: {total_elapsed:.1f}s')
                
                # Save checkpoint
                with open("checkpoint.txt", "w") as f:
                    f.write(f"Last position: {hex(current_start)}\n")
                    f.write(f"Keys searched: {keys_searched:,}\n")
                    f.write(f"Progress: {progress:.2f}%\n")
                    f.write(f"Time: {time.ctime()}\n")

except KeyboardInterrupt:
    print('\n\n[!] Search interrupted by user')
except Exception as e:
    print(f'\n[-] Unexpected error: {e}')
    import traceback
    traceback.print_exc()
finally:
    # Tampilkan statistik akhir
    total_time = time.time() - start_total_time
    
    print('\n' + '='*70)
    print('SEARCH SUMMARY')
    print('='*70)
    print(f'Total searches: {search_count}')
    print(f'Total keys checked: {keys_searched:,}')
    print(f'Total time: {total_time:.2f} seconds')
    
    if total_time > 0:
        avg_speed = keys_searched / total_time
        print(f'Average speed: {avg_speed:,.0f} keys/sec')
        
        if not found:
            remaining_keys = total_keys - keys_searched
            if avg_speed > 0:
                eta_seconds = remaining_keys / avg_speed
                print(f'Remaining keys: {remaining_keys:,}')
                print(f'Estimated time remaining: {eta_seconds/3600:.2f} hours')
    
    if found:
        print(f'[+] SUCCESS: Key found and saved to {OUTPUT_FILE}')
    else:
        print('[-] Key not found in the specified range')
    
    print('='*70)
    print('[+] Program finished')

# ==============================================================================
# TEST FUNCTION - Untuk verifikasi
# ==============================================================================

def test_key_in_range():
    """Test apakah key target berada dalam range"""
    print('\n' + '='*70)
    print('VERIFICATION TEST')
    print('='*70)
    
    # Generate public key dari private key yang diketahui
    test_priv = KNOWN_PRIVATE_KEY
    test_pub = ice.scalar_multiplication(test_priv)
    test_pub_hex = test_pub.hex()
    
    print(f'Test Private Key: {hex(test_priv)}')
    print(f'Generated Public Key: {test_pub_hex[:20]}...')
    print(f'Target Public Key: {PUBLIC_KEY[:20]}...')
    
    # Cek apakah dalam range
    if a <= test_priv <= b:
        print(f'✅ Test key IS in range {hex(a)} - {hex(b)}')
    else:
        print(f'❌ Test key is NOT in range')
    
    print('='*70)

# Jalankan test jika diinginkan
# test_key_in_range()
