# -*- coding: utf-8 -*-
"""
Upgraded BSGS GPU Tool - Large Range Version
Usage: 
    Edit configuration variables below and run directly
    Example: python bxx_upgraded.py
    
Features:
- Compatible with 128-bit and larger ranges
- Windowed BSGS for large ranges
- Simple configuration without argparse
- Multi-GPU support
- Random or sequential search modes
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

# ==================== CONFIGURATION ====================
# Edit these variables for your search

PUBLIC_KEY = "02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16"
START_RANGE_HEX = "4000000000000000000000000000000000"
END_RANGE_HEX   = "7fffffffffffffffffffffffffffffffff"

# Search mode: "random" or "sequential"
SEARCH_MODE = "sequential"

# Windowed BSGS parameters
WINDOW_SIZE_HEX = "100000000000000000000"   # 2⁷²
BP_SIZE = 1048576  # 2²⁰

# GPU Configuration
USE_MULTI_GPU = True  # Set to False for single GPU
GPU_DEVICE_ID = 0  # Used when USE_MULTI_GPU=False
GPU_THREADS = 64
GPU_BLOCKS = 10
GPU_POINTS = 256
BATCH_SIZE = 1000000000  # Keys per batch in random mode

# Output
OUTPUT_FILE = "found_keys.txt"
VERBOSE = True

# ==================== INITIALIZATION ====================

def hex_to_int(hex_str):
    """Convert hex string to integer (supports very large numbers)"""
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

# ==================== HELPER FUNCTIONS ====================

def print_config():
    """Print configuration summary"""
    print("\n" + "="*60)
    print("BSGS GPU TOOL - LARGE RANGE VERSION")
    print("="*60)
    print(f"Public Key: {PUBLIC_KEY}")
    print(f"Search Range: {START_RANGE_HEX[:20]}... to {END_RANGE_HEX[:20]}...")
    print(f"Range Size: 2^{int(math.log2(END_RANGE - START_RANGE + 1)):.1f} keys")
    print(f"Search Mode: {SEARCH_MODE.upper()}")
    if SEARCH_MODE.lower() == "sequential" and WINDOW_SIZE:
        print(f"Window Size: {WINDOW_SIZE_HEX[:20]}... (2^{int(math.log2(WINDOW_SIZE)):.0f})")
    print(f"GPU Threads: {GPU_THREADS}, Blocks: {GPU_BLOCKS}, Points: {GPU_POINTS}")
    print(f"Baby-Point Size: {BP_SIZE:,} (2^{int(math.log2(BP_SIZE))})")
    print("="*60 + "\n")

def pub2upub(pub_hex):
    """Convert compressed/uncompressed public key to uncompressed format"""
    if pub_hex.startswith('04'):
        # Already uncompressed
        return bytes.fromhex(pub_hex)
    elif pub_hex.startswith('02') or pub_hex.startswith('03'):
        # Compressed format
        x = int(pub_hex[2:], 16)
        y_parity = int(pub_hex[:2], 16) % 2
        try:
            # Use bit library to compute y from x
            y = bit.format.x_to_y(x, y_parity)
            return bytes.fromhex('04' + hex(x)[2:].zfill(64) + hex(y)[2:].zfill(64))
        except:
            # Fallback using ice library
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
        # Try to import CUDA if available
        import pycuda.driver as cuda
        cuda.init()
        count = cuda.Device.count()
        print(f"[+] Found {count} CUDA GPU(s)")
        return count
    except ImportError:
        if VERBOSE:
            print("[-] CUDA not available, using single GPU mode")
        return 1
    except Exception as e:
        if VERBOSE:
            print(f"[-] CUDA error: {e}")
        return 1

def split_range_among_gpus(start, end, num_gpus):
    """Split search range among multiple GPUs"""
    total_keys = end - start + 1
    keys_per_gpu = total_keys // num_gpus
    
    ranges = []
    for i in range(num_gpus):
        gpu_start = start + (i * keys_per_gpu)
        gpu_end = gpu_start + keys_per_gpu - 1 if i < num_gpus - 1 else end
        ranges.append((gpu_start, gpu_end))
    
    return ranges

def split_range_into_windows(start, end, window_size):
    """Split large range into manageable windows"""
    windows = []
    current = start
    
    while current <= end:
        window_end = current + window_size - 1
        if window_end > end:
            window_end = end
        windows.append((current, window_end))
        current = window_end + 1
    
    return windows

def validate_private_key(pvk_int, target_pubkey):
    """Validate if private key matches target public key"""
    try:
        # Generate public key from private key
        test_pubkey = ice.scalar_multiplication(pvk_int)
        
        # Convert to hex for comparison
        test_pubkey_hex = test_pubkey.hex()
        target_uncompressed = pub2upub(PUBLIC_KEY).hex()
        
        # Compare uncompressed public keys
        return test_pubkey_hex == target_uncompressed
    except Exception as e:
        if VERBOSE:
            print(f"Validation error: {e}")
        return False

# ==================== DLL LOADING ====================

def load_bsgs_dll():
    """Load the BSGS DLL for the current platform"""
    if platform.system().lower().startswith('win'):
        dllfile = 'bt2.dll'
    elif platform.system().lower().startswith('lin'):
        dllfile = 'bt2.so'
    else:
        print('[-] Unsupported Platform. Only Windows and Linux are supported.')
        return None
    
    if os.path.isfile(dllfile):
        pathdll = os.path.realpath(dllfile)
        try:
            bsgsgpu = ctypes.CDLL(pathdll)
            if VERBOSE:
                print(f"[+] Successfully loaded {dllfile}")
            return bsgsgpu
        except Exception as e:
            print(f"[-] Failed to load {dllfile}: {e}")
            return None
    else:
        print(f'[-] File {dllfile} not found')
        return None

# ==================== CORE SEARCH FUNCTIONS ====================

def bsgs_search_window(start_key, end_key, gpu_device=0, window_size=None):
    """Perform BSGS search on a window of keys"""
    # Load DLL
    bsgsgpu = load_bsgs_dll()
    if not bsgsgpu:
        return None
    
    # Configure DLL function signatures
    bsgsgpu.bsgsGPU.argtypes = [
        ctypes.c_uint32,  # threads
        ctypes.c_uint32,  # blocks
        ctypes.c_uint32,  # points
        ctypes.c_uint32,  # bits
        ctypes.c_int,     # device
        ctypes.c_char_p,  # upubs
        ctypes.c_uint32,  # size
        ctypes.c_char_p,  # keyspace
        ctypes.c_char_p   # bp
    ]
    bsgsgpu.bsgsGPU.restype = ctypes.c_void_p
    bsgsgpu.free_memory.argtypes = [ctypes.c_void_p]
    
    # Prepare public key
    P = pub2upub(PUBLIC_KEY)
    G = ice.scalar_multiplication(1)
    P3 = ice.point_loop_addition(BP_SIZE, P, G)
    
    gpu_bits = int(math.log2(BP_SIZE))
    
    # Use window size if provided, otherwise use full range
    if window_size and (end_key - start_key) > window_size:
        actual_end = start_key + window_size - 1
        if actual_end > end_key:
            actual_end = end_key
    else:
        actual_end = end_key
    
    # Convert keyspace to string
    st_en = hex(start_key)[2:].zfill(64) + ':' + hex(actual_end)[2:].zfill(64)
    
    if VERBOSE:
        range_size = actual_end - start_key + 1
        print(f"[GPU {gpu_device}] Window: {hex(start_key)[:20]}... to {hex(actual_end)[:20]}...")
        print(f"[GPU {gpu_device}] Window size: 2^{math.log2(range_size):.1f} keys")
    
    # Execute BSGS search
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
                # Validate the found key
                try:
                    pvk_int = int(pvk_str, 16)
                    if validate_private_key(pvk_int, PUBLIC_KEY):
                        return {
                            'private_key': pvk_int,
                            'public_key': PUBLIC_KEY,
                            'range_searched': f"{hex(start_key)[:20]}...-{hex(actual_end)[:20]}...",
                            'window_start': hex(start_key),
                            'window_end': hex(actual_end),
                            'time': elapsed_time
                        }
                except:
                    pass
    
    if VERBOSE and elapsed_time > 0:
        keys_searched = actual_end - start_key + 1
        keys_per_second = keys_searched / elapsed_time
        print(f"[GPU {gpu_device}] Speed: {keys_per_second:,.0f} keys/sec")
    
    return None

def bsgs_search_random(gpu_device=0, max_iterations=100):
    """Perform random search within range (for smaller ranges)"""
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
    
    print(f"[+] Starting random search on GPU {gpu_device}")
    print(f"[+] Each batch: {BATCH_SIZE:,} keys")
    
    iteration = 0
    total_keys_checked = 0
    start_time = time.time()
    
    while iteration < max_iterations:
        # Generate random range within bounds
        k1 = random.randint(START_RANGE, END_RANGE - BATCH_SIZE)
        k2 = k1 + BATCH_SIZE
        
        if k2 > END_RANGE:
            k2 = END_RANGE
            k1 = k2 - BATCH_SIZE
        
        st_en = hex(k1)[2:].zfill(64) + ':' + hex(k2)[2:].zfill(64)
        
        if VERBOSE and iteration % 10 == 0:
            print(f"\nIteration {iteration + 1}: {hex(k1)[:20]}... - {hex(k2)[:20]}...")
        
        # Execute search
        batch_start = time.time()
        res = bsgsgpu.bsgsGPU(
            GPU_THREADS, GPU_BLOCKS, GPU_POINTS, gpu_bits,
            gpu_device, P3, len(P3)//65,
            st_en.encode('utf8'), str(BP_SIZE).encode('utf8')
        )
        batch_time = time.time() - batch_start
        
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
                            total_time = time.time() - start_time
                            return {
                                'private_key': pvk_int,
                                'public_key': PUBLIC_KEY,
                                'iterations': iteration + 1,
                                'total_keys': total_keys_checked + (k2 - k1),
                                'total_time': total_time
                            }
                    except:
                        pass
        
        # Update statistics
        total_keys_checked += (k2 - k1)
        iteration += 1
        
        if batch_time > 0 and iteration % 10 == 0:
            batch_speed = (k2 - k1) / batch_time
            avg_speed = total_keys_checked / (time.time() - start_time)
            print(f"  Batch speed: {batch_speed:,.0f} keys/sec")
            print(f"  Average speed: {avg_speed:,.0f} keys/sec")
            print(f"  Total checked: {total_keys_checked:,}")
    
    return None

def sequential_search_worker(gpu_id, start_key, end_key, result_queue, window_size=None):
    """Worker for sequential search on a GPU with windowing"""
    try:
        print(f"[GPU {gpu_id}] Starting search: {hex(start_key)[:20]}... to {hex(end_key)[:20]}...")
        
        # If window_size is provided, split into windows
        if window_size and (end_key - start_key) > window_size:
            windows = split_range_into_windows(start_key, end_key, window_size)
            print(f"[GPU {gpu_id}] Split into {len(windows)} windows")
            
            for i, (window_start, window_end) in enumerate(windows):
                print(f"[GPU {gpu_id}] Window {i+1}/{len(windows)}: {hex(window_start)[:20]}...")
                
                result = bsgs_search_window(window_start, window_end, gpu_id, window_size)
                if result:
                    result_queue.put({'gpu_id': gpu_id, 'result': result})
                    return result
                
                # Check if we should stop (another GPU found the key)
                if not result_queue.empty():
                    try:
                        msg = result_queue.get_nowait()
                        if 'result' in msg:
                            return None
                    except:
                        pass
        else:
            # Single window search
            result = bsgs_search_window(start_key, end_key, gpu_id)
            if result:
                result_queue.put({'gpu_id': gpu_id, 'result': result})
                return result
    
    except Exception as e:
        print(f"[GPU {gpu_id}] Error: {e}")
        import traceback
        traceback.print_exc()
        result_queue.put({'gpu_id': gpu_id, 'error': str(e)})
    
    return None

# ==================== MAIN EXECUTION ====================

def save_result(result):
    """Save found key to file"""
    try:
        with open(OUTPUT_FILE, 'a') as f:
            f.write("\n" + "="*80 + "\n")
            f.write(f"FOUND PRIVATE KEY!\n")
            f.write(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Private Key (hex): {hex(result['private_key'])}\n")
            f.write(f"Private Key (dec): {result['private_key']}\n")
            f.write(f"Public Key: {result['public_key']}\n")
            
            if 'range_searched' in result:
                f.write(f"Range Searched: {result['range_searched']}\n")
            if 'iterations' in result:
                f.write(f"Iterations: {result['iterations']}\n")
            if 'total_keys' in result:
                f.write(f"Total Keys Checked: {result['total_keys']:,}\n")
            if 'total_time' in result:
                f.write(f"Total Time: {result['total_time']:.2f} seconds\n")
                f.write(f"Speed: {result['total_keys']/result['total_time']:,.0f} keys/sec\n")
            
            f.write("="*80 + "\n")
        
        print(f"\n[+] Result saved to {OUTPUT_FILE}")
    except Exception as e:
        print(f"[-] Error saving result: {e}")

def main():
    """Main execution function"""
    print_config()
    
    # Check for DLL
    if not load_bsgs_dll():
        print("[-] BSGS DLL not found. Please ensure bt2.dll (Windows) or bt2.so (Linux) is in the same directory.")
        return
    
    # Determine GPU configuration
    use_multi_gpu = USE_MULTI_GPU
    num_gpus = 1
    
    if USE_MULTI_GPU:
        num_gpus = get_gpu_count()
        if num_gpus > 1:
            print(f"[+] Using {num_gpus} GPUs")
            use_multi_gpu = True
        else:
            print("[+] Using single GPU mode")
            use_multi_gpu = False
    else:
        print("[+] Using single GPU mode")
        use_multi_gpu = False
    
    # Calculate window size (default to WINDOW_SIZE or auto-calculate)
    window_size = WINDOW_SIZE
    if not window_size:
        # Auto-calculate window size based on BP_SIZE
        window_size = BP_SIZE * 1000  # Default factor
    
    # For very large ranges, force windowed search in sequential mode
    range_size = END_RANGE - START_RANGE
    if range_size > window_size * 10 and SEARCH_MODE.lower() == "sequential":
        print(f"[+] Large range detected: 2^{math.log2(range_size):.1f} keys")
        print(f"[+] Using windowed search with window size: 2^{math.log2(window_size):.1f}")
        print(f"[+] Total windows: {math.ceil(range_size / window_size):,}")
    
    # Setup signal handler for graceful exit
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    
    print("[+] Starting search...")
    print("[+] Press Ctrl+C to stop\n")
    
    found = False
    result = None
    
    try:
        if SEARCH_MODE.lower() == "random":
            # Random search mode
            if use_multi_gpu and num_gpus > 1:
                print("[+] Random search with multiple GPUs not yet implemented")
                print("[+] Falling back to single GPU random search")
            
            result = bsgs_search_random(GPU_DEVICE_ID, max_iterations=1000)
        
        elif SEARCH_MODE.lower() == "sequential":
            # Sequential search mode
            if use_multi_gpu and num_gpus > 1:
                # Split range among GPUs
                gpu_ranges = split_range_among_gpus(START_RANGE, END_RANGE, num_gpus)
                
                # Create multiprocessing queue
                result_queue = mp.Queue()
                processes = []
                
                # Start workers
                for gpu_id in range(num_gpus):
                    start_key, end_key = gpu_ranges[gpu_id]
                    p = mp.Process(
                        target=sequential_search_worker,
                        args=(gpu_id, start_key, end_key, result_queue, window_size)
                    )
                    p.start()
                    processes.append(p)
                    time.sleep(0.5)  # Stagger process starts
                
                # Wait for results
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
                        elif 'error' in msg:
                            print(f"[GPU {msg['gpu_id']}] error: {msg['error']}")
                    except:
                        # Timeout, check if processes are still alive
                        continue
                
                # Cleanup
                for p in processes:
                    p.join(timeout=1)
            
            else:
                # Single GPU sequential search with windowing
                if range_size > window_size:
                    # Windowed search for large ranges
                    windows = split_range_into_windows(START_RANGE, END_RANGE, window_size)
                    print(f"[+] Single GPU searching {len(windows)} windows")
                    
                    for i, (window_start, window_end) in enumerate(windows):
                        print(f"\n[+] Window {i+1}/{len(windows)}: {hex(window_start)[:20]}...")
                        
                        result = bsgs_search_window(window_start, window_end, GPU_DEVICE_ID, window_size)
                        if result:
                            found = True
                            break
                        
                        # Check for interrupt
                        time.sleep(0.1)
                else:
                    # Single window search
                    result = bsgs_search_window(START_RANGE, END_RANGE, GPU_DEVICE_ID)
        
        else:
            print(f"[-] Unknown search mode: {SEARCH_MODE}")
            print("[-] Please use 'random' or 'sequential'")
            return
        
        # Process result
        if result:
            found = True
            print("\n" + "="*60)
            print("🎉 PRIVATE KEY FOUND! 🎉")
            print("="*60)
            print(f"Private Key (hex): {hex(result['private_key'])}")
            print(f"Private Key (dec): {result['private_key']}")
            
            if 'range_searched' in result:
                print(f"Range Searched: {result['range_searched']}")
            if 'iterations' in result:
                print(f"Iterations: {result['iterations']}")
            if 'total_keys' in result:
                print(f"Total Keys Checked: {result['total_keys']:,}")
            if 'total_time' in result:
                print(f"Total Time: {result['total_time']:.2f} seconds")
                print(f"Average Speed: {result['total_keys']/result['total_time']:,.0f} keys/sec")
            
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
