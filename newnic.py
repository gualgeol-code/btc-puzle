# -*- coding: utf-8 -*-
"""
BSGS GPU Tool - Optimized for 2^39 Range
Target: Search range 0x8000000000 to 0xffffffffff
Public Key: 03a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4
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
import multiprocessing as mp
from datetime import datetime, timedelta

# ==================== CONFIGURATION ====================
# Optimized for 2^39 range search

PUBLIC_KEY = "03a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4"
START_RANGE_HEX = "8000000000"
END_RANGE_HEX   = "ffffffffff"

# Search mode
SEARCH_MODE = "sequential"

# BSGS parameters optimized for 2^39 range
BP_SIZE = 1048576  # 2^20
WINDOW_SIZE_HEX = "1000000000"   # 2^36 = 68,719,476,736 keys per window

# GPU Configuration
USE_MULTI_GPU = True
GPU_DEVICE_ID = 0
GPU_THREADS = 256
GPU_BLOCKS = 128
GPU_POINTS = 512

# Output
OUTPUT_FILE = "found_keys.txt"
PROGRESS_FILE = "search_progress.txt"
VERBOSE = True

# ==================== INITIALIZATION ====================

def hex_to_int(hex_str):
    """Convert hex string to integer"""
    try:
        return int(hex_str, 16) if hex_str else None
    except ValueError:
        print(f"Error: Invalid hex string: {hex_str}")
        return None

# Convert range
START_RANGE = hex_to_int(START_RANGE_HEX)
END_RANGE = hex_to_int(END_RANGE_HEX)
WINDOW_SIZE = hex_to_int(WINDOW_SIZE_HEX)

if START_RANGE is None or END_RANGE is None:
    print("Error: Invalid range specified")
    sys.exit(1)

# Calculate total keys
TOTAL_KEYS = END_RANGE - START_RANGE + 1

# ==================== HELPER FUNCTIONS ====================

def format_large_number(num):
    """Format large numbers for readability"""
    if num >= 1e12:
        return f"{num/1e12:.2f}T"
    elif num >= 1e9:
        return f"{num/1e9:.2f}B"
    elif num >= 1e6:
        return f"{num/1e6:.2f}M"
    else:
        return f"{num:,}"

def print_config():
    """Print configuration summary"""
    print("\n" + "="*60)
    print("BSGS GPU TOOL - 2^39 RANGE SEARCH")
    print("="*60)
    print(f"Public Key: {PUBLIC_KEY}")
    print(f"Search Range: {START_RANGE_HEX} to {END_RANGE_HEX}")
    print(f"Total Keys: {format_large_number(TOTAL_KEYS)}")
    print(f"Search Mode: {SEARCH_MODE.upper()}")
    
    if SEARCH_MODE.lower() == "sequential":
        windows = math.ceil(TOTAL_KEYS / WINDOW_SIZE)
        print(f"Windows: {windows:,}")
    
    print(f"\nGPU Configuration:")
    print(f"  Threads: {GPU_THREADS}, Blocks: {GPU_BLOCKS}")
    print(f"  Baby-Point Size: {BP_SIZE:,}")
    print("="*60 + "\n")

def pub2upub(pub_hex):
    """Convert compressed/uncompressed public key to uncompressed format"""
    if pub_hex.startswith('04'):
        return bytes.fromhex(pub_hex)
    elif pub_hex.startswith('02') or pub_hex.startswith('03'):
        x = int(pub_hex[2:], 16)
        y_parity = int(pub_hex[:2], 16) % 2
        try:
            y = bit.format.x_to_y(x, y_parity)
            return bytes.fromhex('04' + hex(x)[2:].zfill(64) + hex(y)[2:].zfill(64))
        except:
            try:
                pub_bytes = bytes.fromhex(pub_hex)
                pub_uncompressed = ice.pub2upub(pub_bytes)
                return pub_uncompressed
            except:
                raise ValueError(f"Cannot convert public key: {pub_hex}")
    else:
        raise ValueError(f"Unknown public key format: {pub_hex}")

def get_gpu_count():
    """Get number of available GPUs"""
    try:
        import pycuda.driver as cuda
        cuda.init()
        count = cuda.Device.count()
        print(f"[+] Found {count} CUDA GPU(s)")
        
        for i in range(count):
            device = cuda.Device(i)
            print(f"  GPU {i}: {device.name()}")
        
        return count
    except ImportError:
        if VERBOSE:
            print("[-] CUDA not available, using single GPU mode")
        return 1
    except Exception:
        return 1

def validate_private_key(pvk_int, target_pubkey):
    """Validate if private key matches target public key"""
    try:
        test_pubkey = ice.scalar_multiplication(pvk_int)
        test_pubkey_hex = test_pubkey.hex()
        target_uncompressed = pub2upub(PUBLIC_KEY).hex()
        return test_pubkey_hex == target_uncompressed
    except Exception:
        return False

# ==================== DLL LOADING ====================

def load_bsgs_dll():
    """Load the BSGS DLL for the current platform"""
    if platform.system().lower().startswith('win'):
        dllfile = 'bt2.dll'
    elif platform.system().lower().startswith('lin'):
        dllfile = 'bt2.so'
    else:
        print('[-] Unsupported Platform.')
        return None
    
    if os.path.isfile(dllfile):
        pathdll = os.path.realpath(dllfile)
        try:
            bsgsgpu = ctypes.CDLL(pathdll)
            if VERBOSE:
                print(f"[+] Loaded {dllfile}")
            return bsgsgpu
        except Exception as e:
            print(f"[-] Failed to load {dllfile}: {e}")
            return None
    else:
        print(f'[-] File {dllfile} not found')
        return None

# ==================== CORE SEARCH FUNCTIONS ====================

def bsgs_search_window(start_key, end_key, gpu_device=0):
    """Perform BSGS search on a window of keys"""
    bsgsgpu = load_bsgs_dll()
    if not bsgsgpu:
        return None
    
    # Configure DLL
    bsgsgpu.bsgsGPU.argtypes = [
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_char_p
    ]
    bsgsgpu.bsgsGPU.restype = ctypes.c_void_p
    bsgsgpu.free_memory.argtypes = [ctypes.c_void_p]
    
    # Prepare public key
    P = pub2upub(PUBLIC_KEY)
    G = ice.scalar_multiplication(1)
    P3 = ice.point_loop_addition(BP_SIZE, P, G)
    gpu_bits = int(math.log2(BP_SIZE))
    
    # Format keyspace
    st_en = hex(start_key)[2:] + ':' + hex(end_key)[2:]
    
    # Execute search
    start_time = time.time()
    res = bsgsgpu.bsgsGPU(
        GPU_THREADS, GPU_BLOCKS, GPU_POINTS, gpu_bits,
        gpu_device, P3, len(P3)//65,
        st_en.encode('utf8'), str(BP_SIZE).encode('utf8')
    )
    elapsed_time = time.time() - start_time
    
    # Process result
    if res:
        pvk = (ctypes.cast(res, ctypes.c_char_p).value)
        if pvk:
            pvk_str = pvk.decode('utf8')
            bsgsgpu.free_memory(res)
            
            if pvk_str and pvk_str != '':
                try:
                    pvk_int = int(pvk_str, 16)
                    if validate_private_key(pvk_int, PUBLIC_KEY):
                        return {
                            'private_key': pvk_int,
                            'public_key': PUBLIC_KEY,
                            'range_searched': f"{hex(start_key)}-{hex(end_key)}",
                            'time': elapsed_time
                        }
                except:
                    pass
    
    # Return stats
    keys_searched = end_key - start_key + 1
    speed = keys_searched / elapsed_time if elapsed_time > 0 else 0
    
    return {
        'found': False,
        'keys_searched': keys_searched,
        'time': elapsed_time,
        'speed': speed
    }

def split_range_into_windows(start, end, window_size):
    """Split range into windows"""
    windows = []
    current = start
    
    while current <= end:
        window_end = current + window_size - 1
        if window_end > end:
            window_end = end
        windows.append((current, window_end))
        current = window_end + 1
    
    return windows

def sequential_search_worker(gpu_id, start_key, end_key, result_queue, window_size):
    """Worker for sequential search on a GPU"""
    try:
        print(f"[GPU {gpu_id}] Starting: {hex(start_key)} to {hex(end_key)}")
        
        windows = split_range_into_windows(start_key, end_key, window_size)
        total_windows = len(windows)
        
        total_keys_searched = 0
        total_time = 0
        speeds = []
        
        for i, (window_start, window_end) in enumerate(windows, 1):
            # Check if another GPU found the key
            if not result_queue.empty():
                try:
                    msg = result_queue.get_nowait()
                    if 'result' in msg:
                        return None
                except:
                    pass
            
            window_size_keys = window_end - window_start + 1
            
            print(f"[GPU {gpu_id}] Window {i}/{total_windows}: {hex(window_start)}")
            
            result = bsgs_search_window(window_start, window_end, gpu_id)
            
            if result and 'private_key' in result:
                result_queue.put({'gpu_id': gpu_id, 'result': result})
                return result
            
            # Collect stats
            if result and 'keys_searched' in result:
                total_keys_searched += result['keys_searched']
                total_time += result['time']
                if result['speed'] > 0:
                    speeds.append(result['speed'])
            
            # Print progress every window
            avg_speed = sum(speeds) / len(speeds) if speeds else 0
            progress = (total_keys_searched / (end_key - start_key + 1)) * 100
            
            print(f"[GPU {gpu_id}] Progress: {progress:.2f}%, Speed: {avg_speed:,.0f} keys/sec")
        
        # Finished all windows without finding key
        print(f"[GPU {gpu_id}] Completed range without finding key")
        
    except Exception as e:
        print(f"[GPU {gpu_id}] Error: {e}")
        result_queue.put({'gpu_id': gpu_id, 'error': str(e)})
    
    return None

def save_progress(gpu_id, iteration, keys_searched, speed, start_time):
    """Save search progress to file"""
    try:
        elapsed = time.time() - start_time
        
        with open(PROGRESS_FILE, 'w') as f:
            f.write(f"Progress - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*50 + "\n")
            f.write(f"GPU: {gpu_id}\n")
            f.write(f"Iteration: {iteration}\n")
            f.write(f"Keys Checked: {format_large_number(keys_searched)}\n")
            f.write(f"Speed: {speed:,.0f} keys/sec\n")
            f.write(f"Elapsed: {str(timedelta(seconds=int(elapsed)))}\n")
            
            if speed > 0:
                keys_remaining = TOTAL_KEYS - keys_searched
                eta_seconds = keys_remaining / speed
                eta_str = str(timedelta(seconds=int(eta_seconds)))
                f.write(f"ETA: {eta_str}\n")
            
            f.write("="*50 + "\n")
    except Exception:
        pass

# ==================== MAIN EXECUTION ====================

def save_result(result):
    """Save found key to file"""
    try:
        with open(OUTPUT_FILE, 'a') as f:
            f.write("\n" + "="*60 + "\n")
            f.write(f"FOUND PRIVATE KEY!\n")
            f.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Private Key (hex): {hex(result['private_key'])}\n")
            f.write(f"Private Key (dec): {result['private_key']}\n")
            f.write(f"Public Key: {result['public_key']}\n")
            
            if 'range_searched' in result:
                f.write(f"Range: {result['range_searched']}\n")
            if 'time' in result:
                f.write(f"Search Time: {result['time']:.2f}s\n")
            
            f.write("="*60 + "\n")
        
        print(f"[+] Result saved to {OUTPUT_FILE}")
        
    except Exception as e:
        print(f"[-] Error saving result: {e}")

def main():
    """Main execution function"""
    print_config()
    
    # Check for DLL
    if not load_bsgs_dll():
        print("[-] BSGS DLL not found.")
        return
    
    # Determine GPU configuration
    num_gpus = get_gpu_count()
    use_multi_gpu = USE_MULTI_GPU and num_gpus > 1
    
    if use_multi_gpu:
        print(f"[+] Using {num_gpus} GPUs")
    else:
        print("[+] Using single GPU")
        num_gpus = 1
    
    print("[+] Starting search...")
    print("[+] Press Ctrl+C to stop\n")
    
    # Setup signal handler
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    
    found = False
    result = None
    
    try:
        if SEARCH_MODE.lower() == "sequential":
            if use_multi_gpu:
                # Split range among GPUs
                keys_per_gpu = TOTAL_KEYS // num_gpus
                gpu_ranges = []
                
                for i in range(num_gpus):
                    gpu_start = START_RANGE + (i * keys_per_gpu)
                    gpu_end = gpu_start + keys_per_gpu - 1 if i < num_gpus - 1 else END_RANGE
                    gpu_ranges.append((gpu_start, gpu_end))
                
                # Create multiprocessing queue
                result_queue = mp.Queue()
                processes = []
                
                # Start workers
                for gpu_id in range(num_gpus):
                    start_key, end_key = gpu_ranges[gpu_id]
                    p = mp.Process(
                        target=sequential_search_worker,
                        args=(gpu_id, start_key, end_key, result_queue, WINDOW_SIZE)
                    )
                    p.start()
                    processes.append(p)
                    time.sleep(0.5)
                
                # Wait for results
                start_time = time.time()
                last_progress_time = start_time
                
                while any(p.is_alive() for p in processes) and not found:
                    try:
                        msg = result_queue.get(timeout=5)
                        if 'result' in msg:
                            result = msg['result']
                            found = True
                            print(f"\n[+] Key found by GPU {msg['gpu_id']}!")
                            
                            # Terminate other processes
                            for p in processes:
                                if p.is_alive():
                                    p.terminate()
                            break
                    except:
                        # Timeout, check progress
                        current_time = time.time()
                        if current_time - last_progress_time > 30:  # Every 30 seconds
                            print("[+] Still searching...")
                            last_progress_time = current_time
                        continue
                
                # Cleanup
                for p in processes:
                    p.join(timeout=1)
                    
            else:
                # Single GPU sequential search
                windows = split_range_into_windows(START_RANGE, END_RANGE, WINDOW_SIZE)
                total_windows = len(windows)
                
                print(f"[+] Searching {total_windows} windows")
                
                total_keys_searched = 0
                speeds = []
                start_time = time.time()
                
                for i, (window_start, window_end) in enumerate(windows, 1):
                    print(f"\n[+] Window {i}/{total_windows}: {hex(window_start)}")
                    
                    result = bsgs_search_window(window_start, window_end, GPU_DEVICE_ID)
                    
                    if result and 'private_key' in result:
                        found = True
                        break
                    
                    # Update stats
                    if result and 'keys_searched' in result:
                        total_keys_searched += result['keys_searched']
                        if result['speed'] > 0:
                            speeds.append(result['speed'])
                        
                        avg_speed = sum(speeds) / len(speeds) if speeds else 0
                        progress = (total_keys_searched / TOTAL_KEYS) * 100
                        
                        print(f"[+] Progress: {progress:.2f}%, Speed: {avg_speed:,.0f} keys/sec")
                        
                        # Save progress every 10 windows
                        if i % 10 == 0:
                            save_progress(0, i, total_keys_searched, avg_speed, start_time)
        
        else:
            print("[-] Only sequential mode supported for this range")
            return
        
        # Process result
        if result and found:
            print("\n" + "="*60)
            print("🎉 PRIVATE KEY FOUND! 🎉")
            print("="*60)
            print(f"Private Key (hex): {hex(result['private_key'])}")
            print(f"Private Key (dec): {result['private_key']}")
            
            if 'range_searched' in result:
                print(f"Found in range: {result['range_searched']}")
            if 'time' in result:
                print(f"Search time: {result['time']:.2f}s")
            
            print("="*60)
            
            # Save result
            save_result(result)
        else:
            print("\n[-] Private key not found in the specified range")
    
    except KeyboardInterrupt:
        print("\n\n[-] Search interrupted by user")
    except Exception as e:
        print(f"\n[-] Error during search: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n[+] Program finished")

# ==================== ENTRY POINT ====================

if __name__ == "__main__":
    main()
