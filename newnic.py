# -*- coding: utf-8 -*-
"""
Upgraded BSGS GPU Tool - Optimized for Large Ranges
Usage: 
    Edit configuration variables below and run directly
    
Features:
- Optimized for 128-bit+ ranges
- Random search strategy for large ranges
- Realistic time estimation
- Progress tracking
- Multi-GPU support
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
# Optimized for large range search

PUBLIC_KEY = "02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16"
START_RANGE_HEX = "4000000000000000000000000000000000"
END_RANGE_HEX   = "7fffffffffffffffffffffffffffffffff"

# Search mode: "random" for large ranges
SEARCH_MODE = "random"

# Windowed BSGS - Optimized for large ranges
WINDOW_SIZE_HEX = "1000000000000000000000000000"   # 2¹⁰⁰ ≈ 1.27×10³⁰ keys per window
BP_SIZE = 4194304  # 2²² - Larger table for better performance

# GPU Configuration - Optimized settings
USE_MULTI_GPU = True
GPU_DEVICE_ID = 0
GPU_THREADS = 128   # Increased for better GPU utilization
GPU_BLOCKS = 64     # Increased
GPU_POINTS = 512    # Increased
BATCH_SIZE = 10000000000000  # 10 trillion keys per batch

# Random search parameters
RANDOM_SEARCH_ITERATIONS = 10000  # Maximum iterations
MIN_BATCH_SIZE = 1000000000      # Minimum batch size (1 billion)
MAX_BATCH_SIZE = 100000000000000 # Maximum batch size (100 trillion)

# Performance monitoring
STATS_INTERVAL = 10  # Print stats every N batches
SAVE_PROGRESS_INTERVAL = 100  # Save progress every N batches

# Output
OUTPUT_FILE = "found_keys.txt"
PROGRESS_FILE = "search_progress.txt"
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

def format_large_number(num):
    """Format large numbers for readability"""
    if num >= 1e24:
        return f"{num/1e24:.2f} septillion"
    elif num >= 1e21:
        return f"{num/1e21:.2f} sextillion"
    elif num >= 1e18:
        return f"{num/1e18:.2f} quintillion"
    elif num >= 1e15:
        return f"{num/1e15:.2f} quadrillion"
    elif num >= 1e12:
        return f"{num/1e12:.2f} trillion"
    elif num >= 1e9:
        return f"{num/1e9:.2f} billion"
    elif num >= 1e6:
        return f"{num/1e6:.2f} million"
    else:
        return f"{num:,}"

def estimate_search_time(total_keys, speed_keys_per_sec):
    """Estimate search time and display in human-readable format"""
    if speed_keys_per_sec <= 0:
        return "Unknown (speed cannot be calculated)"
    
    seconds = total_keys / speed_keys_per_sec
    
    # Convert to different time units
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.2f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.2f} hours"
    elif seconds < 31536000:  # 1 year
        return f"{seconds/86400:.2f} days"
    else:
        years = seconds / 31536000
        return f"{years:.2f} years"

def print_config():
    """Print configuration summary with time estimation"""
    print("\n" + "="*80)
    print("BSGS GPU TOOL - OPTIMIZED FOR LARGE RANGES")
    print("="*80)
    print(f"Public Key: {PUBLIC_KEY[:30]}...{PUBLIC_KEY[-30:]}")
    print(f"Search Range: {START_RANGE_HEX[:20]}... to {END_RANGE_HEX[:20]}...")
    
    total_keys = END_RANGE - START_RANGE + 1
    keys_log2 = math.log2(total_keys) if total_keys > 0 else 0
    
    print(f"Total Keys: {format_large_number(total_keys)} (2^{keys_log2:.1f})")
    print(f"Search Mode: {SEARCH_MODE.upper()}")
    
    if SEARCH_MODE.lower() == "random":
        print(f"Batch Size: {format_large_number(BATCH_SIZE)} keys")
        print(f"Max Iterations: {RANDOM_SEARCH_ITERATIONS:,}")
    else:
        print(f"Window Size: {format_large_number(WINDOW_SIZE)} keys (2^{math.log2(WINDOW_SIZE):.0f})")
        total_windows = math.ceil(total_keys / WINDOW_SIZE)
        print(f"Total Windows: {format_large_number(total_windows)}")
    
    print(f"\nGPU Configuration:")
    print(f"  Threads: {GPU_THREADS}, Blocks: {GPU_BLOCKS}, Points: {GPU_POINTS}")
    print(f"  Baby-Point Size: {BP_SIZE:,} (2^{int(math.log2(BP_SIZE))})")
    print("="*80)
    
    # Time estimation
    print(f"\n[!] TIME ESTIMATION (assuming 1 billion keys/sec):")
    est_time = estimate_search_time(total_keys, 1000000000)
    print(f"[!] Estimated search time: {est_time}")
    
    if "years" in est_time and float(est_time.split()[0]) > 10:
        print(f"\n[!] WARNING: Search may take a VERY long time!")
        print(f"[!] Recommendations:")
        print(f"[!] 1. Random search provides better chance of early success")
        print(f"[!] 2. Consider using more GPUs")
        print(f"[!] 3. Adjust batch size for optimal performance")
    print("="*80 + "\n")

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
        
        # Print GPU info
        for i in range(count):
            device = cuda.Device(i)
            print(f"  GPU {i}: {device.name()}, Compute: {device.compute_capability()}")
        
        return count
    except ImportError:
        if VERBOSE:
            print("[-] CUDA not available, using single GPU mode")
        return 1
    except Exception as e:
        if VERBOSE:
            print(f"[-] CUDA error: {e}")
        return 1

def validate_private_key(pvk_int, target_pubkey):
    """Validate if private key matches target public key"""
    try:
        test_pubkey = ice.scalar_multiplication(pvk_int)
        test_pubkey_hex = test_pubkey.hex()
        target_uncompressed = pub2upub(PUBLIC_KEY).hex()
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

def bsgs_search_batch(start_key, end_key, gpu_device=0):
    """Perform BSGS search on a batch of keys"""
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
    batch_size = end_key - start_key + 1
    st_en = hex(start_key)[2:].zfill(64) + ':' + hex(end_key)[2:].zfill(64)
    
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
                            'batch_start': hex(start_key),
                            'batch_end': hex(end_key),
                            'batch_size': batch_size,
                            'time': elapsed_time
                        }
                except Exception as e:
                    if VERBOSE:
                        print(f"Result processing error: {e}")
    
    # Return stats even if no key found
    return {
        'found': False,
        'batch_size': batch_size,
        'time': elapsed_time,
        'speed': batch_size / elapsed_time if elapsed_time > 0 else 0
    }

def adaptive_batch_size(current_speed, current_batch_size):
    """Adjust batch size based on performance"""
    # Target: 1-5 seconds per batch
    target_time = 3.0  # seconds
    suggested_size = int(current_speed * target_time)
    
    # Clamp to reasonable bounds
    suggested_size = max(MIN_BATCH_SIZE, min(suggested_size, MAX_BATCH_SIZE))
    
    # Adjust gradually (no more than 20% change)
    if suggested_size > current_batch_size * 1.2:
        new_batch_size = int(current_batch_size * 1.2)
    elif suggested_size < current_batch_size * 0.8:
        new_batch_size = int(current_batch_size * 0.8)
    else:
        new_batch_size = suggested_size
    
    if VERBOSE and new_batch_size != current_batch_size:
        print(f"[*] Adaptive batch size: {format_large_number(new_batch_size)} keys (from {format_large_number(current_batch_size)})")
    
    return new_batch_size

def save_progress(iteration, total_keys, avg_speed, start_time, batch_size):
    """Save search progress to file"""
    try:
        elapsed = time.time() - start_time
        keys_remaining = (END_RANGE - START_RANGE + 1) - total_keys
        
        with open(PROGRESS_FILE, 'w') as f:
            f.write(f"Search Progress - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*60 + "\n")
            f.write(f"Public Key: {PUBLIC_KEY}\n")
            f.write(f"Range: {START_RANGE_HEX[:30]}... to {END_RANGE_HEX[:30]}...\n")
            f.write(f"Iteration: {iteration}\n")
            f.write(f"Total Keys Checked: {format_large_number(total_keys)}\n")
            f.write(f"Average Speed: {avg_speed:,.0f} keys/sec\n")
            f.write(f"Elapsed Time: {str(timedelta(seconds=int(elapsed)))}\n")
            f.write(f"Current Batch Size: {format_large_number(batch_size)}\n")
            
            if avg_speed > 0 and keys_remaining > 0:
                eta_seconds = keys_remaining / avg_speed
                eta_str = str(timedelta(seconds=int(eta_seconds)))
                f.write(f"Estimated Time Remaining: {eta_str}\n")
            
            # Calculate probability of finding key
            if total_keys > 0 and (END_RANGE - START_RANGE + 1) > 0:
                probability = (total_keys / (END_RANGE - START_RANGE + 1)) * 100
                f.write(f"Probability Coverage: {probability:.10f}%\n")
            
            f.write("="*60 + "\n")
        
        if VERBOSE and iteration % 50 == 0:
            print(f"[*] Progress saved to {PROGRESS_FILE}")
    except Exception as e:
        print(f"[-] Error saving progress: {e}")

def bsgs_search_random_optimized(gpu_device=0):
    """Optimized random search for large ranges"""
    global BATCH_SIZE  # Declare as global to modify it
    
    print(f"[+] Starting OPTIMIZED random search on GPU {gpu_device}")
    print(f"[+] Initial batch size: {format_large_number(BATCH_SIZE)} keys")
    print(f"[+] Max iterations: {RANDOM_SEARCH_ITERATIONS:,}")
    print(f"[+] Press Ctrl+C to stop and save progress\n")
    
    bsgsgpu = load_bsgs_dll()
    if not bsgsgpu:
        return None
    
    # Prepare public key once
    P = pub2upub(PUBLIC_KEY)
    G = ice.scalar_multiplication(1)
    P3 = ice.point_loop_addition(BP_SIZE, P, G)
    gpu_bits = int(math.log2(BP_SIZE))
    
    iteration = 0
    total_keys_checked = 0
    start_time = time.time()
    speeds = []
    
    # Use local variable for current batch size
    current_batch_size = BATCH_SIZE
    
    print(f"\n{'Iter':>6} {'Batch Size':>15} {'Speed':>15} {'Total Keys':>20} {'Progress':>12}")
    print("-" * 80)
    
    while iteration < RANDOM_SEARCH_ITERATIONS:
        try:
            # Generate random batch
            batch_size = current_batch_size
            if END_RANGE - START_RANGE < batch_size:
                batch_size = END_RANGE - START_RANGE
            
            k1 = random.randint(START_RANGE, END_RANGE - batch_size)
            k2 = k1 + batch_size - 1
            
            # Format keyspace
            st_en = hex(k1)[2:].zfill(64) + ':' + hex(k2)[2:].zfill(64)
            
            # Execute search
            batch_start = time.time()
            res = bsgsgpu.bsgsGPU(
                GPU_THREADS, GPU_BLOCKS, GPU_POINTS, gpu_bits,
                gpu_device, P3, len(P3)//65,
                st_en.encode('utf8'), str(BP_SIZE).encode('utf8')
            )
            batch_time = time.time() - batch_start
            
            # Process result
            found_key = None
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
                                found_key = {
                                    'private_key': pvk_int,
                                    'public_key': PUBLIC_KEY,
                                    'iterations': iteration + 1,
                                    'total_keys': total_keys_checked + batch_size,
                                    'total_time': total_time,
                                    'average_speed': (total_keys_checked + batch_size) / total_time
                                }
                        except:
                            pass
            
            # Update statistics
            total_keys_checked += batch_size
            iteration += 1
            
            # Calculate speeds
            batch_speed = batch_size / batch_time if batch_time > 0 else 0
            speeds.append(batch_speed)
            if len(speeds) > 100:  # Keep last 100 samples
                speeds.pop(0)
            
            avg_speed = sum(speeds) / len(speeds) if speeds else 0
            
            # Adaptive batch sizing
            if iteration % 10 == 0 and avg_speed > 0:
                current_batch_size = adaptive_batch_size(avg_speed, current_batch_size)
            
            # Print statistics
            if iteration % STATS_INTERVAL == 0 or found_key:
                progress = (total_keys_checked / (END_RANGE - START_RANGE + 1)) * 100
                
                print(f"{iteration:6d} {format_large_number(batch_size):>15} "
                      f"{avg_speed:15,.0f} {format_large_number(total_keys_checked):>20} "
                      f"{progress:11.8f}%")
            
            # Save progress periodically
            if iteration % SAVE_PROGRESS_INTERVAL == 0:
                save_progress(iteration, total_keys_checked, avg_speed, start_time, current_batch_size)
            
            # Return if key found
            if found_key:
                # Update global BATCH_SIZE with optimized value
                BATCH_SIZE = current_batch_size
                save_progress(iteration, total_keys_checked, avg_speed, start_time, current_batch_size)
                return found_key
            
            # Check for user interrupt without blocking
            time.sleep(0.001)
            
        except KeyboardInterrupt:
            print(f"\n\n[-] Search interrupted at iteration {iteration}")
            # Update global BATCH_SIZE with optimized value
            BATCH_SIZE = current_batch_size
            save_progress(iteration, total_keys_checked, avg_speed, start_time, current_batch_size)
            return None
        except Exception as e:
            print(f"\n[-] Error in iteration {iteration}: {e}")
            # Reduce batch size on error
            current_batch_size = max(MIN_BATCH_SIZE, current_batch_size // 2)
            time.sleep(1)  # Brief pause before retry
    
    print(f"\n[-] Reached maximum iterations ({RANDOM_SEARCH_ITERATIONS})")
    # Update global BATCH_SIZE with optimized value
    BATCH_SIZE = current_batch_size
    save_progress(iteration, total_keys_checked, avg_speed, start_time, current_batch_size)
    return None

# ==================== MAIN EXECUTION ====================

def save_result(result):
    """Save found key to file"""
    try:
        with open(OUTPUT_FILE, 'a') as f:
            f.write("\n" + "="*80 + "\n")
            f.write(f"FOUND PRIVATE KEY!\n")
            f.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Private Key (hex): {hex(result['private_key'])}\n")
            f.write(f"Private Key (dec): {result['private_key']}\n")
            f.write(f"Public Key: {result['public_key']}\n")
            
            if 'iterations' in result:
                f.write(f"Iterations: {result['iterations']}\n")
            if 'total_keys' in result:
                f.write(f"Total Keys Checked: {result['total_keys']:,}\n")
            if 'total_time' in result:
                f.write(f"Total Time: {result['total_time']:.2f} seconds\n")
                f.write(f"Average Speed: {result['total_keys']/result['total_time']:,.0f} keys/sec\n")
            
            f.write("="*80 + "\n")
        
        print(f"\n[+] Result saved to {OUTPUT_FILE}")
        
        # Also update progress file
        with open(PROGRESS_FILE, 'a') as pf:
            pf.write(f"\n[SUCCESS] Key found at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            
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
    num_gpus = get_gpu_count()
    use_multi_gpu = USE_MULTI_GPU and num_gpus > 1
    
    if use_multi_gpu:
        print(f"[+] Using {num_gpus} GPUs in parallel")
        # Note: For simplicity, this version focuses on single GPU
        # Multi-GPU would require more complex coordination
        print("[+] Note: Multi-GPU fully parallel not implemented in this version")
        print("[+] Continuing with single GPU random search")
        use_multi_gpu = False
    
    print("[+] Starting search...")
    print("[+] Press Ctrl+C to stop at any time\n")
    
    # Ask for confirmation if search is very large
    total_keys = END_RANGE - START_RANGE + 1
    if total_keys > 1e30:  # Very large range
        response = input("[?] This is a VERY large search. Continue? (yes/no): ")
        if response.lower() != 'yes':
            print("[+] Search cancelled by user")
            return
    
    found = False
    result = None
    
    try:
        if SEARCH_MODE.lower() == "random":
            result = bsgs_search_random_optimized(GPU_DEVICE_ID)
        elif SEARCH_MODE.lower() == "sequential":
            print("[-] Sequential search not recommended for this large range")
            print("[-] Switching to random search mode")
            result = bsgs_search_random_optimized(GPU_DEVICE_ID)
        else:
            print(f"[-] Unknown search mode: {SEARCH_MODE}")
            print("[-] Using random search mode")
            result = bsgs_search_random_optimized(GPU_DEVICE_ID)
        
        # Process result
        if result:
            found = True
            print("\n" + "="*60)
            print("🎉 PRIVATE KEY FOUND! 🎉")
            print("="*60)
            print(f"Private Key (hex): {hex(result['private_key'])}")
            print(f"Private Key (dec): {result['private_key']}")
            
            if 'iterations' in result:
                print(f"Iterations: {result['iterations']:,}")
            if 'total_keys' in result:
                print(f"Total Keys Checked: {format_large_number(result['total_keys'])}")
            if 'total_time' in result:
                total_time = result['total_time']
                print(f"Total Time: {str(timedelta(seconds=int(total_time)))}")
                if 'average_speed' in result:
                    print(f"Average Speed: {result['average_speed']:,.0f} keys/sec")
            
            print("="*60)
            
            # Save result
            save_result(result)
        else:
            print("\n[-] Private key not found within the iterations limit")
            print(f"[-] Total keys checked: {format_large_number(total_keys)}")
            print(f"[-] Progress saved to {PROGRESS_FILE}")
            print(f"[-] Final optimized batch size: {format_large_number(BATCH_SIZE)}")
    
    except KeyboardInterrupt:
        print("\n\n[-] Search interrupted by user")
        print(f"[+] Progress saved to {PROGRESS_FILE}")
        print(f"[+] Final optimized batch size: {format_large_number(BATCH_SIZE)}")
    except Exception as e:
        print(f"\n[-] Error during search: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n[+] Program finished")
    print(f"[+] Check {PROGRESS_FILE} for detailed progress information")

# ==================== ENTRY POINT ====================

if __name__ == "__main__":
    main()
