# -*- coding: utf-8 -*-
"""
BTC Puzzle Private Key Search
Target Public Key: 033c4a45cbd643ff97d77f41ea37e843648d50fd894b864b0d52febc62f6454f7c
Key Range: 80000:fffff (hex)
Menggunakan algoritma BSGS dengan akselerasi GPU
"""

import secp256k1_lib as ice
import bit
import ctypes
import os
import sys
import platform
import math
import time

# ==============================================================================
# Konfigurasi Public Key dan Range Target
# ==============================================================================
TARGET_PUBKEY = "033c4a45cbd643ff97d77f41ea37e843648d50fd894b864b0d52febc62f6454f7c"
KEYSPACE_MIN = 0x80000  # 524288 dalam decimal
KEYSPACE_MAX = 0xfffff  # 1048575 dalam decimal

# Konfigurasi GPU (disesuaikan dengan hardware Anda)
GPU_DEVICE = 0
GPU_THREADS = 64
GPU_BLOCKS = 10
GPU_POINTS = 256
BP_SIZE = 50000  # Baby-step table size (disesuaikan dengan range)

# ==============================================================================
# Fungsi Konversi dan Helper
# ==============================================================================

def pubkey_to_uncompressed(pub_hex):
    """
    Konversi public key compressed/uncompressed ke format uncompressed 65-byte
    """
    if pub_hex.startswith('04'):  # Already uncompressed
        if len(pub_hex) == 130:  # 2 + 64 + 64
            return bytes.fromhex(pub_hex)
    
    # Compressed format (02/03)
    x = int(pub_hex[2:66], 16)
    prefix = int(pub_hex[:2], 16)
    
    # Gunakan library bit untuk mendapatkan y dari x
    y_parity = prefix % 2
    y = bit.format.x_to_y(x, y_parity)
    
    return bytes.fromhex('04' + hex(x)[2:].zfill(64) + hex(y)[2:].zfill(64))

def print_banner():
    """Menampilkan informasi program"""
    print("\n" + "="*70)
    print("BTC PUZZLE PRIVATE KEY SEARCH")
    print("="*70)
    print(f"Public Key Target: {TARGET_PUBKEY[:20]}...{TARGET_PUBKEY[-20:]}")
    print(f"Key Range: {hex(KEYSPACE_MIN)} - {hex(KEYSPACE_MAX)}")
    print(f"Range Size: {KEYSPACE_MAX - KEYSPACE_MIN + 1:,} keys")
    print(f"GPU Device: {GPU_DEVICE}")
    print(f"GPU Threads: {GPU_THREADS}, Blocks: {GPU_BLOCKS}")
    print(f"Baby-Step Table Size: {BP_SIZE:,}")
    print("="*70 + "\n")

def load_gpu_library():
    """Memuat library GPU (bt2.so)"""
    if platform.system().lower().startswith('win'):
        dllfile = 'bt2.dll'
    elif platform.system().lower().startswith('lin'):
        dllfile = 'bt2.so'
    else:
        print('[-] Unsupported Platform. Only Windows and Linux are supported.')
        sys.exit(1)
    
    if not os.path.isfile(dllfile):
        print(f'[-] File {dllfile} not found!')
        print('Please ensure bt2.so (Linux) or bt2.dll (Windows) is in the current directory.')
        sys.exit(1)
    
    pathdll = os.path.realpath(dllfile)
    bsgsgpu = ctypes.CDLL(pathdll)
    
    # Setup function signatures
    bsgsgpu.bsgsGPU.argtypes = [
        ctypes.c_uint32,  # threads
        ctypes.c_uint32,  # blocks
        ctypes.c_uint32,  # points
        ctypes.c_uint32,  # gpu_bits
        ctypes.c_int,     # device
        ctypes.c_char_p,  # upubs
        ctypes.c_uint32,  # size
        ctypes.c_char_p,  # keyspace
        ctypes.c_char_p   # bp
    ]
    bsgsgpu.bsgsGPU.restype = ctypes.c_void_p
    bsgsgpu.free_memory.argtypes = [ctypes.c_void_p]
    
    return bsgsgpu

def search_range(bsgsgpu, P3, start_key, end_key, bp_size, attempt_num):
    """Melakukan pencarian dalam satu range menggunakan GPU"""
    # Konversi keyspace ke string hex
    st_en = hex(start_key)[2:] + ':' + hex(end_key)[2:]
    
    print(f"\n[+] Attempt {attempt_num}")
    print(f"[+] Searching range: {hex(start_key)} - {hex(end_key)}")
    print(f"[+] Range size: {end_key - start_key + 1:,} keys")
    
    # Hitung gpu_bits dari bp_size
    gpu_bits = int(math.log2(bp_size))
    
    # Waktu mulai
    start_time = time.time()
    
    # Panggil fungsi BSGS GPU
    res_ptr = bsgsgpu.bsgsGPU(
        GPU_THREADS,
        GPU_BLOCKS,
        GPU_POINTS,
        gpu_bits,
        GPU_DEVICE,
        P3,
        len(P3) // 65,
        st_en.encode('utf8'),
        str(bp_size).encode('utf8')
    )
    
    # Ekstrak hasil
    pvk_hex = (ctypes.cast(res_ptr, ctypes.c_char_p).value).decode('utf8')
    
    # Waktu selesai
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    # Bebaskan memori
    bsgsgpu.free_memory(res_ptr)
    
    # Hitung kecepatan (keys per second)
    keys_searched = end_key - start_key + 1
    if elapsed_time > 0:
        keys_per_sec = keys_searched / elapsed_time
        print(f"[+] Speed: {keys_per_sec:,.2f} keys/second")
        print(f"[+] Time elapsed: {elapsed_time:.2f} seconds")
    
    return pvk_hex

def verify_and_save_key(pvk_hex, P3, output_file="found_key.txt"):
    """Verifikasi private key dan simpan ke file"""
    if not pvk_hex:
        return False
    
    print(f"\n[+] Potential key found: {pvk_hex}")
    
    try:
        # Buat public key dari private key untuk verifikasi
        pvk_int = int(pvk_hex, 16)
        found_pubkey = bit.Key.from_int(pvk_int).public_key
        
        # Cari dalam P3 untuk mendapatkan offset yang benar
        # P3 adalah array dari P + i*G untuk i=0..bp_size-1
        pubkey_bytes = bytes.fromhex(found_pubkey)
        
        # Cari index dalam P3 (format: array of 65-byte uncompressed pubkeys)
        # Kita perlu mencari public key yang sesuai
        idx = -1
        for i in range(0, len(P3), 65):
            if P3[i:i+65] == pubkey_bytes:
                idx = i // 65
                break
        
        if idx >= 0:
            # Hitung private key yang sebenarnya
            # BSGS_Key = found_key - idx
            BSGS_Key = pvk_int - idx
            
            # Verifikasi ulang
            verify_pubkey = bit.Key.from_int(BSGS_Key).public_key
            if verify_pubkey == found_pubkey:
                print("\n" + "="*60)
                print("SUCCESS! PRIVATE KEY FOUND!")
                print("="*60)
                print(f"Private Key (hex): {hex(BSGS_Key)}")
                print(f"Private Key (decimal): {BSGS_Key}")
                print(f"Public Key: {TARGET_PUBKEY}")
                print("="*60)
                
                # Simpan ke file
                with open(output_file, "w") as f:
                    f.write("="*60 + "\n")
                    f.write("BTC PUZZLE SOLUTION\n")
                    f.write("="*60 + "\n")
                    f.write(f"Target Public Key: {TARGET_PUBKEY}\n")
                    f.write(f"Private Key (hex): {hex(BSGS_Key)}\n")
                    f.write(f"Private Key (decimal): {BSGS_Key}\n")
                    f.write(f"Key Range: {hex(KEYSPACE_MIN)} - {hex(KEYSPACE_MAX)}\n")
                    f.write(f"Found at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("="*60 + "\n")
                
                print(f"[+] Result saved to {output_file}")
                return True
            else:
                print("[-] Verification failed!")
                return False
        else:
            print("[-] Key not found in P3 table. False positive?")
            return False
            
    except Exception as e:
        print(f"[-] Error verifying key: {e}")
        return False

def main():
    """Program utama"""
    print_banner()
    
    # 1. Load GPU library
    print("[+] Loading GPU library...")
    bsgsgpu = load_gpu_library()
    print("[+] GPU library loaded successfully")
    
    # 2. Konversi public key target ke uncompressed
    print("[+] Converting target public key...")
    P = pubkey_to_uncompressed(TARGET_PUBKEY)
    print(f"[+] Public key converted (65 bytes)")
    
    # 3. Dapatkan titik generator G
    print("[+] Getting generator point G...")
    G = ice.scalar_multiplication(1)
    print("[+] Generator point obtained")
    
    # 4. Buat P3 = P + i*G untuk i=0..bp_size-1
    print(f"[+] Creating baby-step table with {BP_SIZE:,} elements...")
    start_time = time.time()
    P3 = ice.point_loop_addition(BP_SIZE, P, G)
    table_time = time.time() - start_time
    print(f"[+] Table created in {table_time:.2f} seconds")
    print(f"[+] P3 table size: {len(P3)} bytes ({len(P3)//65} points)")
    
    # 5. Tentukan strategi pencarian
    # Karena range kecil (0x80000-0xfffff = 524288 keys), kita bisa bagi menjadi beberapa bagian
    # jika diperlukan untuk monitoring progress
    total_keys = KEYSPACE_MAX - KEYSPACE_MIN + 1
    print(f"\n[+] Total keys to search: {total_keys:,}")
    
    # Kita bisa coba satu range langsung atau bagi menjadi sub-ranges
    # Untuk range kecil ini, kita bisa coba sekaligus
    
    attempt = 1
    print(f"\n[+] Starting search...")
    
    # Lakukan pencarian
    found_key = search_range(
        bsgsgpu, 
        P3, 
        KEYSPACE_MIN, 
        KEYSPACE_MAX, 
        BP_SIZE, 
        attempt
    )
    
    # Verifikasi jika ditemukan
    if found_key:
        success = verify_and_save_key(found_key, P3)
        if success:
            return
    
    print(f"\n[-] Key not found in the specified range.")
    print(f"[+] You may want to:")
    print(f"    1. Double-check the public key")
    print(f"    2. Verify the key range")
    print(f"    3. Adjust GPU parameters for better performance")
    print(f"    4. Try increasing the baby-step table size")
    
    # Simpa progress/log
    with open("search_log.txt", "a") as log:
        log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - ")
        log.write(f"Range: {hex(KEYSPACE_MIN)}-{hex(KEYSPACE_MAX)} - ")
        log.write(f"Not found\n")

# ==============================================================================
# Jalankan program
# ==============================================================================
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[-] Search interrupted by user.")
    except Exception as e:
        print(f"\n[-] Error: {e}")
        import traceback
        traceback.print_exc()
