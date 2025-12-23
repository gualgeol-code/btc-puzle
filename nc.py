# -*- coding: utf-8 -*-
"""
Direct Search BTC Puzzle
"""

import secp256k1_lib as ice
import bit
import time

TARGET_PUBKEY = "033c4a45cbd643ff97d77f41ea37e843648d50fd894b864b0d52febc62f6454f7c"
START_KEY = 0x80000
END_KEY = 0xfffff

def pubkey_to_uncompressed(pub_hex):
    """Konversi public key ke uncompressed"""
    if pub_hex.startswith('04'):
        return bytes.fromhex(pub_hex)
    
    x = int(pub_hex[2:66], 16)
    prefix = int(pub_hex[:2], 16)
    y_parity = prefix % 2
    y = bit.format.x_to_y(x, y_parity)
    
    return bytes.fromhex('04' + format(x, '064x') + format(y, '064x'))

def main():
    print(f"Target: {TARGET_PUBKEY}")
    print(f"Range: {hex(START_KEY)} - {hex(END_KEY)}")
    print(f"Total keys: {END_KEY - START_KEY + 1:,}\n")
    
    target_pubkey_bytes = pubkey_to_uncompressed(TARGET_PUBKEY)
    
    start_time = time.time()
    keys_checked = 0
    last_print = start_time
    
    print(f"[{time.strftime('%H:%M:%S')}] Memulai pencarian...")
    
    for private_key in range(START_KEY, END_KEY + 1):
        # Hitung public key dari private key
        pubkey_bytes = ice.scalar_multiplication(private_key)
        
        # Bandingkan dengan target
        if pubkey_bytes == target_pubkey_bytes:
            print(f"\n{'='*60}")
            print("SUCCESS! KEY FOUND!")
            print(f"{'='*60}")
            print(f"Private Key: {hex(private_key)}")
            print(f"Private Key (decimal): {private_key}")
            print(f"Public Key: {TARGET_PUBKEY}")
            print(f"{'='*60}")
            
            with open("found_direct.txt", "w") as f:
                f.write(f"Private Key: {hex(private_key)}\n")
                f.write(f"Public Key: {TARGET_PUBKEY}\n")
            
            return
        
        keys_checked += 1
        
        # Print progress setiap 10 detik
        current_time = time.time()
        if current_time - last_print >= 10:
            elapsed = current_time - start_time
            speed = keys_checked / elapsed if elapsed > 0 else 0
            print(f"[{time.strftime('%H:%M:%S')}] Progress: {keys_checked:,} keys, "
                  f"Speed: {speed:,.0f} keys/sec")
            last_print = current_time
    
    print(f"\n[-] Key tidak ditemukan dalam range")

if __name__ == "__main__":
    main()
