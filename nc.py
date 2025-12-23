# -*- coding: utf-8 -*-
"""
BTC Puzzle Private Key Search - Optimized Version
Target Public Key: 033c4a45cbd643ff97d77f41ea37e843648d50fd894b864b0d52febc62f6454f7c
Key Range: 80000:fffff (hex)
"""

import secp256k1_lib as ice
import bit
import ctypes
import os
import sys
import platform
import math
import time
import random

# ==============================================================================
# KONFIGURASI TARGET
# ==============================================================================
TARGET_PUBKEY = "033c4a45cbd643ff97d77f41ea37e843648d50fd894b864b0d52febc62f6454f7c"
KEYSPACE_MIN = 0x80000  # 524288
KEYSPACE_MAX = 0xfffff  # 1048575

# ==============================================================================
# KONFIGURASI GPU (SESUAIKAN DENGAN HARDWARE ANDA)
# ==============================================================================
GPU_DEVICE = 0
GPU_THREADS = 64
GPU_BLOCKS = 10
GPU_POINTS = 256
BP_SIZE = 65536  # Harus power of 2 untuk BSGS (2^16 = 65536)

# ==============================================================================
# FUNGSI UTILITAS
# ==============================================================================

def pubkey_to_uncompressed(pub_hex):
    """Konversi public key ke format uncompressed 65-byte"""
    if pub_hex.startswith('04'):
        return bytes.fromhex(pub_hex)
    
    # Compressed format
    x = int(pub_hex[2:66], 16)
    prefix = int(pub_hex[:2], 16)
    
    # Gunakan bit library untuk menghitung y
    y_parity = prefix % 2
    y = bit.format.x_to_y(x, y_parity)
    
    return bytes.fromhex('04' + format(x, '064x') + format(y, '064x'))

def print_banner():
    print("\n" + "="*70)
    print("BTC PUZZLE PRIVATE KEY SEARCH - BSGS GPU")
    print("="*70)
    print(f"Target Public Key: {TARGET_PUBKEY}")
    print(f"Search Range: {hex(KEYSPACE_MIN)} to {hex(KEYSPACE_MAX)}")
    print(f"Total Keys: {KEYSPACE_MAX - KEYSPACE_MIN + 1:,}")
    print(f"Baby-Step Table Size: {BP_SIZE:,}")
    print(f"GPU: Device {GPU_DEVICE}, Threads {GPU_THREADS}, Blocks {GPU_BLOCKS}")
    print("="*70 + "\n")

def load_gpu_library():
    """Load GPU library (bt2.so/bt2.dll)"""
    if platform.system().lower().startswith('win'):
        lib_name = 'bt2.dll'
    elif platform.system().lower().startswith('lin'):
        lib_name = 'bt2.so'
    else:
        print("[-] Platform tidak didukung")
        sys.exit(1)
    
    if not os.path.exists(lib_name):
        print(f"[-] File {lib_name} tidak ditemukan!")
        sys.exit(1)
    
    try:
        bsgsgpu = ctypes.CDLL(os.path.realpath(lib_name))
        
        # Definisi fungsi
        bsgsgpu.bsgsGPU.argtypes = [
            ctypes.c_uint32,  # threads
            ctypes.c_uint32,  # blocks
            ctypes.c_uint32,  # points
            ctypes.c_uint32,  # gpu_bits
            ctypes.c_int,     # device
            ctypes.c_char_p,  # upubs (P3 table)
            ctypes.c_uint32,  # size (number of points in P3)
            ctypes.c_char_p,  # keyspace "start:end"
            ctypes.c_char_p   # bp (table size as string)
        ]
        bsgsgpu.bsgsGPU.restype = ctypes.c_void_p
        bsgsgpu.free_memory.argtypes = [ctypes.c_void_p]
        
        print(f"[+] GPU library {lib_name} loaded successfully")
        return bsgsgpu
    except Exception as e:
        print(f"[-] Gagal memuat library GPU: {e}")
        sys.exit(1)

def prepare_bsgs_tables(target_pubkey, bp_size):
    """Mempersiapkan tabel BSGS (Baby-Step Giant-Step)"""
    print("[+] Memulai persiapan tabel BSGS...")
    
    # 1. Konversi public key target ke uncompressed
    P = pubkey_to_uncompressed(target_pubkey)
    print(f"   Target pubkey (uncompressed): {P.hex()[:20]}...")
    
    # 2. Dapatkan generator point G
    G = ice.scalar_multiplication(1)
    print(f"   Generator point G: {G.hex()[:20]}...")
    
    # 3. Buat tabel baby steps: P + i*G untuk i = 0..bp_size-1
    print(f"   Membuat tabel baby-step dengan {bp_size} elemen...")
    start_time = time.time()
    
    # Gunakan point_loop_addition untuk membuat tabel
    # P3 = [P, P+G, P+2G, ..., P+(bp_size-1)G]
    P3 = ice.point_loop_addition(bp_size, P, G)
    
    table_time = time.time() - start_time
    print(f"   Tabel selesai dalam {table_time:.2f} detik")
    print(f"   Ukuran tabel: {len(P3)} bytes ({len(P3)//65} points)")
    
    return P, G, P3

def search_single_range(bsgsgpu, P3, start_key, end_key, bp_size, attempt_num):
    """Search dalam satu range menggunakan BSGS GPU"""
    print(f"\n[+] Percobaan #{attempt_num}")
    print(f"   Range: {hex(start_key)} - {hex(end_key)}")
    print(f"   Ukuran: {end_key - start_key + 1:,} keys")
    
    # Hitung gpu_bits (log2 dari bp_size)
    gpu_bits = int(math.log2(bp_size))
    
    # Format keyspace sebagai "start:end" dalam hex
    keyspace_str = f"{start_key:08x}:{end_key:08x}"
    
    # Konversi bp_size ke string
    bp_size_str = str(bp_size)
    
    start_time = time.time()
    
    try:
        # Panggil fungsi BSGS GPU
        res_ptr = bsgsgpu.bsgsGPU(
            GPU_THREADS,
            GPU_BLOCKS,
            GPU_POINTS,
            gpu_bits,
            GPU_DEVICE,
            P3,
            len(P3) // 65,  # Number of points in P3
            keyspace_str.encode('utf-8'),
            bp_size_str.encode('utf-8')
        )
        
        # Ekstrak hasil
        result = ctypes.cast(res_ptr, ctypes.c_char_p).value
        if result:
            found_key_hex = result.decode('utf-8')
        else:
            found_key_hex = ""
        
        # Bebaskan memori
        bsgsgpu.free_memory(res_ptr)
        
    except Exception as e:
        print(f"   Error saat menjalankan BSGS GPU: {e}")
        found_key_hex = ""
    
    elapsed_time = time.time() - start_time
    
    # Hitung kecepatan
    if elapsed_time > 0:
        keys_per_sec = (end_key - start_key + 1) / elapsed_time
        print(f"   Kecepatan: {keys_per_sec:,.0f} keys/detik")
        print(f"   Waktu: {elapsed_time:.2f} detik")
    
    return found_key_hex

def verify_private_key(pvk_hex, target_pubkey, P3, bp_size):
    """Verifikasi private key yang ditemukan"""
    if not pvk_hex:
        return False, None
    
    try:
        print(f"\n[!] Kandidat ditemukan: {pvk_hex}")
        
        pvk_int = int(pvk_hex, 16)
        
        # Hitung public key dari private key
        candidate_pubkey = bit.Key.from_int(pvk_int)
        candidate_pubkey_hex = candidate_pubkey.public_key
        
        # Konversi ke uncompressed untuk perbandingan
        candidate_uncompressed = pubkey_to_uncompressed(candidate_pubkey_hex)
        
        # Cari dalam tabel P3
        found_idx = -1
        for i in range(0, len(P3), 65):
            if P3[i:i+65] == candidate_uncompressed:
                found_idx = i // 65
                break
        
        if found_idx >= 0:
            # Hitung private key yang sebenarnya
            # private_key = found_key - found_idx
            actual_privkey = pvk_int - found_idx
            
            # Verifikasi final
            verify_pubkey = bit.Key.from_int(actual_privkey).public_key
            target_compressed = target_pubkey
            
            if verify_pubkey == target_compressed:
                print(f"\n{'='*60}")
                print("SUKSES! PRIVATE KEY DITEMUKAN!")
                print(f"{'='*60}")
                print(f"Private Key (hex): {hex(actual_privkey)}")
                print(f"Private Key (dec): {actual_privkey}")
                print(f"Public Key: {target_pubkey}")
                print(f"{'='*60}")
                return True, actual_privkey
            else:
                print("[-] Verifikasi gagal - public key tidak cocok")
                return False, None
        else:
            print("[-] Key tidak ditemukan dalam tabel P3")
            return False, None
            
    except Exception as e:
        print(f"[-] Error verifikasi: {e}")
        return False, None

def save_result(private_key, target_pubkey, range_info):
    """Simpan hasil ke file"""
    filename = "found_key.txt"
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    
    with open(filename, "w") as f:
        f.write("="*60 + "\n")
        f.write("BTC PUZZLE SOLUTION\n")
        f.write("="*60 + "\n")
        f.write(f"Timestamp: {timestamp}\n")
        f.write(f"Target Public Key: {target_pubkey}\n")
        f.write(f"Private Key (hex): {hex(private_key)}\n")
        f.write(f"Private Key (decimal): {private_key}\n")
        f.write(f"Search Range: {range_info}\n")
        f.write("="*60 + "\n")
    
    print(f"[+] Hasil disimpan ke {filename}")
    return filename

# ==============================================================================
# MAIN PROGRAM
# ==============================================================================

def main():
    """Program utama"""
    print_banner()
    
    # 1. Load GPU library
    bsgsgpu = load_gpu_library()
    
    # 2. Persiapkan tabel BSGS
    P, G, P3 = prepare_bsgs_tables(TARGET_PUBKEY, BP_SIZE)
    
    # 3. Hitung parameter pencarian
    total_keys = KEYSPACE_MAX - KEYSPACE_MIN + 1
    print(f"\n[+] Total kunci yang akan dicari: {total_keys:,}")
    
    # 4. Lakukan pencarian dalam range yang ditentukan
    attempt = 1
    found = False
    
    print(f"\n[+] Memulai pencarian...")
    
    # Untuk range kecil, kita bisa langsung cari semuanya
    found_key_hex = search_single_range(
        bsgsgpu, 
        P3, 
        KEYSPACE_MIN, 
        KEYSPACE_MAX, 
        BP_SIZE, 
        attempt
    )
    
    # 5. Verifikasi jika ada kandidat
    if found_key_hex:
        found, private_key = verify_private_key(found_key_hex, TARGET_PUBKEY, P3, BP_SIZE)
        if found:
            save_result(private_key, TARGET_PUBKEY, 
                       f"{hex(KEYSPACE_MIN)} - {hex(KEYSPACE_MAX)}")
            return
    
    print(f"\n[-] Private key tidak ditemukan dalam range yang ditentukan.")
    
    # 6. Alternatif: Jika tidak ditemukan, coba pendekatan berbeda
    print("\n[+] Mencoba pendekatan alternatif...")
    
    # Coba bagi range menjadi bagian yang lebih kecil
    chunk_size = 65536  # 64K keys per chunk
    start = KEYSPACE_MIN
    
    while start <= KEYSPACE_MAX and not found:
        end = min(start + chunk_size - 1, KEYSPACE_MAX)
        
        print(f"\n   Mencari chunk: {hex(start)} - {hex(end)}")
        
        found_key_hex = search_single_range(
            bsgsgpu,
            P3,
            start,
            end,
            BP_SIZE,
            attempt
        )
        
        if found_key_hex:
            found, private_key = verify_private_key(found_key_hex, TARGET_PUBKEY, P3, BP_SIZE)
            if found:
                save_result(private_key, TARGET_PUBKEY, 
                           f"{hex(start)} - {hex(end)}")
                break
        
        start = end + 1
        attempt += 1
    
    if not found:
        print(f"\n[-] Pencarian selesai. Key tidak ditemukan.")
        print(f"\n[+] Saran:")
        print(f"    1. Pastikan public key target benar")
        print(f"    2. Periksa apakah key benar berada dalam range {hex(KEYSPACE_MIN)}-{hex(KEYSPACE_MAX)}")
        print(f"    3. Coba ukuran BP_SIZE yang berbeda")
        print(f"    4. Verifikasi library bt2.so kompatibel dengan GPU Anda")

# ==============================================================================
# JALANKAN PROGRAM
# ==============================================================================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Pencarian dihentikan oleh pengguna.")
    except Exception as e:
        print(f"\n[-] Error: {e}")
        import traceback
        traceback.print_exc()
