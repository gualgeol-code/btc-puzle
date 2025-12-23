# -*- coding: utf-8 -*-
"""
SIMPLE BITCOIN PRIVATE KEY FINDER
"""

import secp256k1_lib as ice
import time

# Target public key
TARGET_PUBKEY = "033c4a45cbd643ff97d77f41ea37e843648d50fd894b864b0d52febc62f6454f7c"

# Search range
START = 0x80000   # 524,288
END = 0xFFFFF     # 1,048,575

def main():
    print(f"Searching for private key of: {TARGET_PUBKEY[:20]}...")
    print(f"Range: {hex(START)} to {hex(END)}")
    print(f"Total keys: {END - START + 1:,}")
    print("-" * 50)
    
    # Convert target to uncompressed
    def convert_pubkey(pubkey_hex):
        if pubkey_hex.startswith('02') or pubkey_hex.startswith('03'):
            x = int(pubkey_hex[2:], 16)
            p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
            y_sq = (pow(x, 3, p) + 7) % p
            y = pow(y_sq, (p + 1) // 4, p)
            
            if (pubkey_hex.startswith('02') and y % 2 == 1) or (pubkey_hex.startswith('03') and y % 2 == 0):
                y = p - y
            
            return bytes.fromhex('04' + format(x, '064x') + format(y, '064x'))
        return bytes.fromhex(pubkey_hex)
    
    target = convert_pubkey(TARGET_PUBKEY)
    print("Starting search...\n")
    
    start_time = time.time()
    
    for k in range(START, END + 1):
        # Calculate public key
        pub = ice.scalar_multiplication(k)
        
        # Check if matches target
        if pub == target:
            elapsed = time.time() - start_time
            print("\n" + "="*50)
            print(f"✅ FOUND! Private Key: 0x{k:x}")
            print(f"Time: {elapsed:.2f} seconds")
            print("="*50)
            
            # Save result
            with open("key_found.txt", "w") as f:
                f.write(f"Private Key: 0x{k:x}\n")
                f.write(f"Public Key: {TARGET_PUBKEY}\n")
                f.write(f"Found in: {elapsed:.2f}s\n")
            
            return k
        
        # Show progress
        if (k - START) % 50000 == 0 and k > START:
            elapsed = time.time() - start_time
            progress = (k - START + 1) / (END - START + 1) * 100
            speed = (k - START + 1) / elapsed
            print(f"Progress: {progress:.1f}% - Speed: {speed:,.0f} keys/sec")
    
    print("\n❌ Key not found in range.")
    return None

if __name__ == "__main__":
    main()
