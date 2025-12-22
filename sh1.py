import pycuda.driver as cuda
import pycuda.autoinit
from pycuda.compiler import SourceModule
import numpy as np
import time
import hashlib
import base58
import ecdsa
from ecdsa.curves import SECP256k1
import multiprocessing as mp
import os
import sys
import ctypes

# ==================== LOAD EXTERNAL LIBRARIES ====================
bt2_lib = None
ice_lib = None

try:
    # Load ice_secp256k1.so library
    ice_lib = ctypes.CDLL('./ice_secp256k1.so')
    print("✅ ice_secp256k1.so loaded successfully")
    
    # Define function signatures for ice_secp256k1.so
    ice_lib.scalar_multiplication.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    ice_lib.pubkey_to_address.argtypes = [ctypes.c_int, ctypes.c_bool, ctypes.c_char_p]
    ice_lib.pubkey_to_address.restype = ctypes.c_void_p
    ice_lib.free_memory.argtypes = [ctypes.c_void_p]
    ice_lib.init_secp256_lib.argtypes = []
    
    # Initialize the library
    ice_lib.init_secp256_lib()
    
except Exception as e:
    print(f"⚠️ Error loading ice_secp256k1.so: {e}")
    ice_lib = None

try:
    # Load bt2.so library for BSGS GPU
    bt2_lib = ctypes.CDLL('./bt2.so')
    print("✅ bt2.so loaded successfully")
    
    # Define function signatures for bt2.so
    bt2_lib.bsgsGPU.argtypes = [
        ctypes.c_uint32,  # gpu_threads
        ctypes.c_uint32,  # gpu_blocks
        ctypes.c_uint32,  # gpu_points
        ctypes.c_uint32,  # gpu_bits
        ctypes.c_int,     # gpu_device
        ctypes.c_char_p,  # upubs
        ctypes.c_uint32,  # size
        ctypes.c_char_p,  # keyspace
        ctypes.c_char_p   # bp
    ]
    bt2_lib.bsgsGPU.restype = ctypes.c_void_p
    bt2_lib.free_memory.argtypes = [ctypes.c_void_p]
    
except Exception as e:
    print(f"⚠️ Error loading bt2.so: {e}")
    bt2_lib = None

# ==================== INSTALL PYCYPTODOME IF NOT AVAILABLE ====================
try:
    from Crypto.Hash import RIPEMD160
    RIPEMD160_AVAILABLE = True
    print("✅ pycryptodome RIPEMD160 available")
except ImportError:
    print("⚠️ pycryptodome not available, installing...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome"])
    from Crypto.Hash import RIPEMD160
    RIPEMD160_AVAILABLE = True
    print("✅ pycryptodome RIPEMD160 installed")

# ==================== KONFIGURASI ====================
MIN_RANGE = "80000"  # Start range (Hex) - diperbaiki agar tidak nol
MAX_RANGE = "fffff"  # End range (Hex)

TARGET_ADDR = "1HsMJxNiV7TLxmoF6uJNkydxPFDog4NQum"

USE_ALL_GPUS = True
try:
    GPU_IDS = [0] if not USE_ALL_GPUS else list(range(cuda.Device.count()))
except:
    GPU_IDS = [0]  # Fallback jika CUDA tidak tersedia

WINDOW_SIZE = 4

# ==================== FUNGSI RIPEMD160 YANG BENAR ====================
def ripemd160_hash(data):
    """Implementasi RIPEMD160 yang benar menggunakan pycryptodome"""
    h = RIPEMD160.new()
    h.update(data)
    return h.digest()

# ==================== ENHANCED ECC GPU VERIFICATION ====================
class ECCGPUVerifier:
    """Kelas untuk verifikasi ECC menggunakan GPU eksternal"""
    
    def __init__(self, gpu_device=0, gpu_threads=64, gpu_blocks=10, 
                 gpu_points=256, bp_size=500000):
        self.gpu_device = gpu_device
        self.gpu_threads = gpu_threads
        self.gpu_blocks = gpu_blocks
        self.gpu_points = gpu_points
        self.bp_size = bp_size
        self.gpu_bits = int(np.log2(bp_size)) if bp_size > 0 else 0
    
    def scalar_multiplication_gpu(self, private_key_hex):
        """Perkalian skalar menggunakan GPU via ice_secp256k1.so"""
        try:
            if ice_lib is None:
                return None
                
            # Konversi private key ke format yang diperlukan
            pk_hex = private_key_hex.zfill(64)
            pk_bytes = pk_hex.encode('utf8')
            
            # Alokasi buffer untuk hasil (65 bytes untuk uncompressed pubkey)
            result_buffer = ctypes.create_string_buffer(65)
            
            # Panggil fungsi C
            ice_lib.scalar_multiplication(pk_bytes, result_buffer)
            
            return bytes(result_buffer)
        except Exception as e:
            print(f"⚠️ GPU scalar multiplication failed: {e}")
            return None
    
    def pubkey_to_address_gpu(self, pubkey_bytes, compressed=True):
        """Konversi public key ke address menggunakan GPU"""
        try:
            if ice_lib is None:
                return None
                
            # Tentukan jenis address (0 untuk P2PKH)
            addr_type = 0
            
            # Panggil fungsi C
            res_ptr = ice_lib.pubkey_to_address(
                addr_type, 
                compressed, 
                pubkey_bytes
            )
            
            # Dapatkan hasil
            address = (ctypes.cast(res_ptr, ctypes.c_char_p).value).decode('utf8')
            
            # Bebaskan memori
            ice_lib.free_memory(res_ptr)
            
            return address
        except Exception as e:
            print(f"⚠️ GPU pubkey to address failed: {e}")
            return None
    
    def verify_key_bsgs_gpu(self, target_pubkey_hex, keyspace_start, keyspace_end):
        """
        Verifikasi menggunakan algoritma BSGS pada GPU
        
        Args:
            target_pubkey_hex: Public key target dalam format hex
            keyspace_start: Start range keyspace
            keyspace_end: End range keyspace
            
        Returns:
            Tuple (found, private_key_hex) jika ditemukan
        """
        try:
            if bt2_lib is None:
                return False, None
                
            # Konversi public key ke uncompressed
            if len(target_pubkey_hex) == 66:  # Compressed
                prefix = int(target_pubkey_hex[:2], 16)
                x = int(target_pubkey_hex[2:], 16)
                
                # Hitung y dari x (persamaan kurva eliptik)
                p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
                a = 0
                b = 7
                
                # y² = x³ + ax + b mod p
                y_sq = (pow(x, 3, p) + a * x + b) % p
                
                # Cari akar kuadrat mod p
                y = pow(y_sq, (p + 1) // 4, p)
                
                # Sesuaikan dengan prefix
                if (prefix == 2 and y % 2 == 1) or (prefix == 3 and y % 2 == 0):
                    y = p - y
                
                pubkey_uncompressed = '04' + hex(x)[2:].zfill(64) + hex(y)[2:].zfill(64)
            else:
                pubkey_uncompressed = target_pubkey_hex
            
            # Buat P table
            P = bytes.fromhex(pubkey_uncompressed)
            
            # Panggil bsgsGPU
            st_en = f"{keyspace_start}:{keyspace_end}"
            
            res_ptr = bt2_lib.bsgsGPU(
                self.gpu_threads,
                self.gpu_blocks,
                self.gpu_points,
                self.gpu_bits,
                self.gpu_device,
                P,
                len(P) // 65,
                st_en.encode('utf8'),
                str(self.bp_size).encode('utf8')
            )
            
            # Dapatkan hasil
            pvk_hex = (ctypes.cast(res_ptr, ctypes.c_char_p).value).decode('utf8')
            
            # Bebaskan memori
            bt2_lib.free_memory(res_ptr)
            
            if pvk_hex and pvk_hex != '':
                return True, pvk_hex
            else:
                return False, None
                
        except Exception as e:
            print(f"⚠️ BSGS GPU verification failed: {e}")
            return False, None

# ==================== PYTHON HELPER FUNCTIONS ====================
def hex_to_u256(hex_str):
    hex_str = hex_str.zfill(64)
    parts = [int(hex_str[i:i+8], 16) for i in range(0, 64, 8)]
    parts.reverse()
    return np.array(parts, dtype=np.uint32)

def u256_to_hex(u32_array):
    val = 0
    for i in range(7, -1, -1):
        val = (val << 32) | int(u32_array[i])
    return format(val, '064x')

def address_to_hash160(address):
    decoded = base58.b58decode(address)
    return decoded[1:-4]

def precompute_g_table_cpu():
    """Generates the G lookup table for the GPU in constant memory format"""
    print("⚙️  Precomputing G-Table on CPU...")
    Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    curve = SECP256k1
    G = ecdsa.ellipticcurve.Point(curve.curve, Gx, Gy)
    
    table_x = []
    table_y = []
    
    table_x.append(np.zeros(8, dtype=np.uint32))
    table_y.append(np.zeros(8, dtype=np.uint32))
    
    for i in range(1, 16):
        private_key = i
        sk = ecdsa.SigningKey.from_secret_exponent(private_key, curve=SECP256k1)
        vk = sk.get_verifying_key()
        
        x_hex = format(vk.pubkey.point.x(), '064x')
        y_hex = format(vk.pubkey.point.y(), '064x')
        
        table_x.append(hex_to_u256(x_hex))
        table_y.append(hex_to_u256(y_hex))
        
        if i <= 3:
            print(f"  G[{i}] = ({x_hex[:16]}..., {y_hex[:16]}...)")
    
    return np.array(table_x).flatten(), np.array(table_y).flatten()

def is_valid_private_key_hex(private_key_hex):
    """Validasi private key sebelum verifikasi"""
    try:
        # Cek format hex
        if not all(c in '0123456789abcdefABCDEF' for c in private_key_hex):
            return False
        
        # Pastikan panjang 64 karakter
        if len(private_key_hex) != 64:
            return False
        
        # Konversi ke integer
        priv_key_int = int(private_key_hex, 16)
        
        # Cek rentang valid (1 <= key < CURVE_N)
        CURVE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8B0D1D0E8C
        
        if priv_key_int <= 0:
            return False
        if priv_key_int >= CURVE_N:
            return False
            
        return True
    except:
        return False

def verify_private_key(private_key_hex, target_address):
    """Verify if private key matches target address"""
    try:
        # Validasi private key sebelum diproses
        if not is_valid_private_key_hex(private_key_hex):
            return False
        
        priv_key_int = int(private_key_hex, 16)
        sk = ecdsa.SigningKey.from_secret_exponent(priv_key_int, curve=SECP256k1)
        vk = sk.get_verifying_key()
        
        # Compressed public key
        if vk.pubkey.point.y() % 2 == 0:
            public_key = b'\x02' + vk.to_string()[:32]
        else:
            public_key = b'\x03' + vk.to_string()[:32]
        
        # SHA256
        sha256 = hashlib.sha256(public_key).digest()
        
        # RIPEMD160 using pycryptodome
        hash160 = ripemd160_hash(sha256)
        
        # Bitcoin address
        version_hash = b'\x00' + hash160
        checksum = hashlib.sha256(hashlib.sha256(version_hash).digest()).digest()[:4]
        address_bytes = version_hash + checksum
        generated_address = base58.b58encode(address_bytes).decode()
        
        return generated_address == target_address
    except Exception as e:
        # Hanya log error jika diperlukan debugging
        # print(f"⚠️ Verification error: {e}")
        return False

def test_ripemd160():
    """Test our RIPEMD160 implementation using pycryptodome"""
    print("\n🔧 Testing RIPEMD160 implementation...")
    
    # Test vector from RFC 2286
    test_cases = [
        (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
        (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
        (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
        (b"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
    ]
    
    all_passed = True
    for data, expected in test_cases:
        result = ripemd160_hash(data).hex()
        passed = result == expected
        all_passed = all_passed and passed
        status = "✅" if passed else "❌"
        print(f"  {status} '{data.decode() if data else 'empty'}': {result} (expected: {expected})")
    
    if all_passed:
        print("  ✅ All RIPEMD160 tests passed!")
    else:
        print("  ❌ Some RIPEMD160 tests failed!")
    
    return all_passed

def test_bitcoin_address_generation():
    """Test Bitcoin address generation with known private keys"""
    print("\n🔧 Testing Bitcoin address generation...")
    
    # Known test vectors
    test_cases = [
        ("0000000000000000000000000000000000000000000000000000000000000001", 
         "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"),
        ("0000000000000000000000000000000000000000000000000000000000000002",
         "1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP"),
    ]
    
    all_passed = True
    for private_key_hex, expected_address in test_cases:
        result = verify_private_key(private_key_hex, expected_address)
        status = "✅" if result else "❌"
        print(f"  {status} Private key {private_key_hex[:16]}... -> {expected_address}")
        all_passed = all_passed and result
    
    if all_passed:
        print("  ✅ All Bitcoin address tests passed!")
    else:
        print("  ❌ Some Bitcoin address tests failed!")
    
    return all_passed

def test_gpu_libraries():
    """Test fungsi library GPU"""
    print("\n🔧 Testing GPU libraries...")
    
    test_private_key = "0000000000000000000000000000000000000000000000000000000000000001"
    expected_address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
    
    try:
        # Test ice_secp256k1.so
        print("  Testing ice_secp256k1.so...")
        if ice_lib:
            verifier = ECCGPUVerifier()
            pubkey = verifier.scalar_multiplication_gpu(test_private_key)
            if pubkey:
                print(f"    ✅ Scalar multiplication successful (pubkey length: {len(pubkey)})")
                
                address = verifier.pubkey_to_address_gpu(pubkey, compressed=True)
                if address:
                    print(f"    ✅ Address generated: {address}")
                    if address == expected_address:
                        print(f"    ✅ Address matches expected: {expected_address}")
                    else:
                        print(f"    ⚠️ Address mismatch. Expected: {expected_address}")
                else:
                    print("    ⚠️ Address generation failed")
            else:
                print("    ❌ Scalar multiplication failed")
        else:
            print("    ⚠️ ice_secp256k1.so not loaded")
        
        # Test bt2.so BSGS
        print("  Testing bt2.so BSGS functionality...")
        if bt2_lib:
            verifier = ECCGPUVerifier()
            # Test sederhana dengan range kecil
            found, pvk = verifier.verify_key_bsgs_gpu(
                "02CEB6CBBCDBDF5EF7150682150F4CE2C6F4807B349827DCDBDD1F2EFA885A2630",
                "1", "1000"
            )
            if found:
                print(f"    ✅ BSGS test found key: {pvk}")
            else:
                print("    ⚠️ BSGS test completed (no key found in small range)")
        else:
            print("    ⚠️ bt2.so not loaded")
            
    except Exception as e:
        print(f"    ❌ GPU library test failed: {e}")

def calculate_optimal_batch_size(gpu_id):
    try:
        device = cuda.Device(gpu_id)
        total_mem = device.total_memory()
        usable_mem = total_mem * 0.5  # Conservative
        bytes_per_thread = 160 
        optimal_batch = int(usable_mem // bytes_per_thread)
        optimal_batch = min(optimal_batch, 1_000_000)  # Smaller for testing
        optimal_batch = max(optimal_batch, 100_000)
        optimal_batch = (optimal_batch // 256) * 256
        return optimal_batch
    except:
        return 100_000

# ==================== GPU WORKER CLASS ====================
class GPUWorker:
    def __init__(self, gpu_id, min_key, max_key, target_hash, g_table_x, g_table_y, result_queue):
        self.gpu_id = gpu_id
        self.min_key = min_key
        self.max_key = max_key
        self.target_hash = target_hash
        self.g_table_x = g_table_x
        self.g_table_y = g_table_y
        self.result_queue = result_queue
        self.found = False
        
    def run(self):
        context = None
        stream = None
        
        try:
            cuda.init()
            device = cuda.Device(self.gpu_id)
            context = device.make_context()
            
            print(f"🚀 GPU {self.gpu_id}: Initialized ({device.name()})")
            
            stream = cuda.Stream()
            
            compute_capability = device.compute_capability()
            arch = f"sm_{compute_capability[0]}{compute_capability[1]}"
            
            # CUDA kernel code
            cuda_code = """
#include <stdint.h>
#include <stdio.h>

#define DEVICE_FUNC __device__ __forceinline__

typedef struct {
    unsigned int v[8];
} uint256_t;

typedef struct {
    uint256_t x, y, z;
} jacobian_point;

struct Result {
    int found;
    uint256_t private_key;
    unsigned char pubkey_hash[20];
};

__constant__ uint256_t CURVE_P = {{0xfffffc2f, 0xfffffffe, 0xffffffff, 0xffffffff, 
                                  0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff}};
__constant__ uint256_t CURVE_N = {{0xd0364141, 0xbfd25e8c, 0xaf48a03b, 0xbaaedce6,
                                  0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff}};

__constant__ uint256_t G_TABLE_X[16];
__constant__ uint256_t G_TABLE_Y[16];

__constant__ uint32_t K_SHA256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// ==================== HELPER FUNCTIONS ====================
DEVICE_FUNC void set_zero(uint256_t *a) {
    #pragma unroll
    for (int i = 0; i < 8; i++) a->v[i] = 0;
}

DEVICE_FUNC void set_one(uint256_t *a) {
    set_zero(a);
    a->v[0] = 1;
}

DEVICE_FUNC int is_zero(const uint256_t *a) {
    #pragma unroll
    for (int i = 0; i < 8; i++) if (a->v[i] != 0) return 0;
    return 1;
}

DEVICE_FUNC void copy_u256(uint256_t *dst, const uint256_t *src) {
    #pragma unroll
    for (int i = 0; i < 8; i++) dst->v[i] = src->v[i];
}

DEVICE_FUNC int compare_u256(const uint256_t *a, const uint256_t *b) {
    #pragma unroll
    for (int i = 7; i >= 0; i--) {
        if (a->v[i] < b->v[i]) return -1;
        if (a->v[i] > b->v[i]) return 1;
    }
    return 0;
}

DEVICE_FUNC void add_mod(uint256_t *res, const uint256_t *a, const uint256_t *b) {
    unsigned long long carry = 0;
    
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        unsigned long long sum = (unsigned long long)a->v[i] + b->v[i] + carry;
        res->v[i] = (unsigned int)sum;
        carry = sum >> 32;
    }
    
    if (carry || compare_u256(res, &CURVE_P) >= 0) {
        unsigned long long borrow = 0;
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            long long diff = (long long)res->v[i] - CURVE_P.v[i] - borrow;
            res->v[i] = (unsigned int)diff;
            borrow = (diff < 0) ? 1 : 0;
        }
    }
}

DEVICE_FUNC void sub_mod(uint256_t *res, const uint256_t *a, const uint256_t *b) {
    uint256_t temp;
    int borrow = 0;
    
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        long long diff = (long long)a->v[i] - b->v[i] - borrow;
        temp.v[i] = (unsigned int)diff;
        borrow = (diff < 0) ? 1 : 0;
    }
    
    if (borrow) {
        unsigned long long carry = 0;
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            unsigned long long sum = (unsigned long long)temp.v[i] + CURVE_P.v[i] + carry;
            res->v[i] = (unsigned int)sum;
            carry = sum >> 32;
        }
    } else {
        copy_u256(res, &temp);
    }
}

DEVICE_FUNC void mod_mul(uint256_t *res, const uint256_t *a, const uint256_t *b) {
    unsigned long long accum[16] = {0};
    
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        unsigned long long carry = 0;
        #pragma unroll
        for (int j = 0; j < 8; j++) {
            unsigned long long product = (unsigned long long)a->v[i] * b->v[j];
            accum[i+j] += product + carry;
            carry = accum[i+j] >> 32;
            accum[i+j] &= 0xFFFFFFFF;
        }
        if (carry) accum[i+8] += carry;
    }
    
    uint256_t result;
    #pragma unroll
    for (int i = 0; i < 8; i++) result.v[i] = accum[i];
    
    while (compare_u256(&result, &CURVE_P) >= 0) {
        sub_mod(&result, &result, &CURVE_P);
    }
    copy_u256(res, &result);
}

DEVICE_FUNC void mod_sqr(uint256_t *res, const uint256_t *a) {
    mod_mul(res, a, a);
}

DEVICE_FUNC void mod_inv(uint256_t *res, const uint256_t *a) {
    uint256_t exponent;
    copy_u256(&exponent, &CURVE_P);
    
    unsigned long long borrow = 0;
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        long long diff = (long long)exponent.v[i] - ((i == 0) ? 2 : 0) - borrow;
        if (diff < 0) {
            diff += 0x100000000ULL;
            borrow = 1;
        } else {
            borrow = 0;
        }
        exponent.v[i] = (unsigned int)diff;
    }
    
    uint256_t result;
    set_one(&result);
    uint256_t base;
    copy_u256(&base, a);
    
    for (int i = 0; i < 256; i++) {
        int word_idx = i / 32;
        int bit_idx = i % 32;
        if ((exponent.v[word_idx] >> bit_idx) & 1) {
            mod_mul(&result, &result, &base);
        }
        mod_sqr(&base, &base);
    }
    copy_u256(res, &result);
}

// ==================== ECC OPERATIONS ====================
DEVICE_FUNC void point_double(jacobian_point *res, const jacobian_point *p) {
    if (is_zero(&p->z)) {
        set_zero(&res->x); set_zero(&res->y); set_zero(&res->z);
        return;
    }
    
    uint256_t a, b, c, d;
    uint256_t three, two, eight;
    set_zero(&three); three.v[0] = 3;
    set_zero(&two); two.v[0] = 2;
    set_zero(&eight); eight.v[0] = 8;
    
    mod_sqr(&a, &p->x);
    mod_mul(&a, &a, &three);
    mod_mul(&b, &p->y, &p->z);
    mod_sqr(&c, &p->y);
    mod_mul(&c, &c, &p->x);
    mod_mul(&d, &c, &three);
    mod_mul(&res->z, &b, &two);
    mod_sqr(&res->x, &a);
    uint256_t two_d;
    mod_mul(&two_d, &d, &two);
    sub_mod(&res->x, &res->x, &two_d);
    
    uint256_t d_minus_x;
    sub_mod(&d_minus_x, &d, &res->x);
    mod_mul(&res->y, &a, &d_minus_x);
    uint256_t c_sqr, eight_c_sqr;
    mod_sqr(&c_sqr, &c);
    mod_mul(&eight_c_sqr, &c_sqr, &eight);
    sub_mod(&res->y, &res->y, &eight_c_sqr);
}

DEVICE_FUNC void point_add_mixed(jacobian_point *res, const jacobian_point *p, const uint256_t *qx, const uint256_t *qy) {
    if (is_zero(&p->z)) {
        copy_u256(&res->x, qx);
        copy_u256(&res->y, qy);
        set_one(&res->z);
        return;
    }

    uint256_t z1z1, u2, s2, h, i, j, r, v;
    uint256_t two; set_zero(&two); two.v[0] = 2;

    mod_sqr(&z1z1, &p->z);
    mod_mul(&u2, qx, &z1z1);
    
    uint256_t s2_temp;
    mod_mul(&s2_temp, &p->z, &z1z1);
    mod_mul(&s2, qy, &s2_temp);

    if (compare_u256(&p->x, &u2) == 0 && compare_u256(&p->y, &s2) == 0) {
        point_double(res, p);
        return;
    }

    sub_mod(&h, &u2, &p->x);
    
    uint256_t two_h;
    mod_mul(&two_h, &h, &two);
    mod_sqr(&i, &two_h);
    mod_mul(&j, &h, &i);
    
    sub_mod(&r, &s2, &p->y);
    uint256_t two_r;
    mod_mul(&two_r, &r, &two);
    
    mod_mul(&v, &p->x, &i);

    mod_sqr(&res->x, &two_r);
    sub_mod(&res->x, &res->x, &j);
    uint256_t two_v;
    mod_mul(&two_v, &v, &two);
    sub_mod(&res->x, &res->x, &two_v);

    sub_mod(&v, &v, &res->x);
    mod_mul(&res->y, &two_r, &v);
    
    uint256_t two_s1_j;
    mod_mul(&two_s1_j, &p->y, &j);
    mod_mul(&two_s1_j, &two_s1_j, &two);
    sub_mod(&res->y, &res->y, &two_s1_j);

    uint256_t z1_plus_h;
    add_mod(&z1_plus_h, &p->z, &h);
    mod_sqr(&res->z, &z1_plus_h);
    sub_mod(&res->z, &res->z, &z1z1);
    uint256_t h_sq;
    mod_sqr(&h_sq, &h);
    sub_mod(&res->z, &res->z, &h_sq);
}

DEVICE_FUNC void scalar_multiply_with_lookup(jacobian_point *result, const uint256_t *k) {
    set_zero(&result->x); set_zero(&result->y); set_zero(&result->z);
    
    unsigned char nibbles[64];
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        unsigned int word = k->v[7-i];
        #pragma unroll
        for (int j = 0; j < 8; j++) {
            nibbles[i*8 + j] = (word >> (28 - j*4)) & 0xF;
        }
    }
    
    for (int i = 0; i < 64; i++) {
        if (!is_zero(&result->z)) {
            point_double(result, result);
            point_double(result, result);
            point_double(result, result);
            point_double(result, result);
        }
        
        unsigned char nibble = nibbles[i];
        if (nibble != 0) {
            if (is_zero(&result->z)) {
                copy_u256(&result->x, &G_TABLE_X[nibble]);
                copy_u256(&result->y, &G_TABLE_Y[nibble]);
                set_one(&result->z);
            } else {
                point_add_mixed(result, result, &G_TABLE_X[nibble], &G_TABLE_Y[nibble]);
            }
        }
    }
}

// ==================== VALIDASI PRIVATE KEY ====================
DEVICE_FUNC int is_valid_private_key(const uint256_t *key) {
    // Cek apakah key == 0
    if (is_zero(key)) {
        return 0;
    }
    
    // Cek apakah key >= CURVE_N (order of curve)
    if (compare_u256(key, &CURVE_N) >= 0) {
        return 0;
    }
    
    // Private key harus antara 1 dan CURVE_N-1
    uint256_t one;
    set_one(&one);
    
    if (compare_u256(key, &one) < 0) {
        return 0;  // Kurang dari 1
    }
    
    return 1;
}

DEVICE_FUNC void add_u256_with_offset(uint256_t *num, unsigned long long offset) {
    unsigned long long carry = offset;
    
    for (int i = 0; i < 8 && carry > 0; i++) {
        unsigned long long sum = (unsigned long long)num->v[i] + (carry & 0xFFFFFFFF);
        num->v[i] = (unsigned int)sum;
        carry = (carry >> 32) + (sum >> 32);
    }
    
    // Jika ada overflow di luar 256-bit, set ke CURVE_N-1
    if (carry > 0) {
        // Set ke CURVE_N-1 (maksimum valid)
        uint256_t max_valid;
        copy_u256(&max_valid, &CURVE_N);
        
        unsigned long long borrow = 1;
        for (int i = 0; i < 8; i++) {
            long long diff = (long long)max_valid.v[i] - borrow;
            if (diff < 0) {
                max_valid.v[i] = (unsigned int)(diff + 0x100000000ULL);
                borrow = 1;
            } else {
                max_valid.v[i] = (unsigned int)diff;
                borrow = 0;
                break;
            }
        }
        copy_u256(num, &max_valid);
    }
}

// ==================== MAIN KERNEL ====================
extern "C" __global__ 
void crack_secp256k1_multi_gpu(const uint256_t *start_keys,
                               const uint8_t *target_hash,
                               struct Result *results,
                               unsigned long long total_threads) {
    
    unsigned long long global_idx = threadIdx.x + blockIdx.x * blockDim.x;
    if (global_idx >= total_threads) return;
    
    uint256_t private_key;
    copy_u256(&private_key, &start_keys[0]);
    add_u256_with_offset(&private_key, global_idx);
    
    // Validasi private key sebelum diproses
    if (!is_valid_private_key(&private_key)) {
        results[global_idx].found = 0;
        return;
    }
    
    jacobian_point pub_key;
    scalar_multiply_with_lookup(&pub_key, &private_key);
    
    if (is_zero(&pub_key.z)) {
        results[global_idx].found = 0;
        return;
    }
    
    // Set flag untuk verifikasi CPU
    results[global_idx].found = 1;
    copy_u256(&results[global_idx].private_key, &private_key);
}
"""
            
            mod = SourceModule(
                cuda_code,
                options=[
                    '-O3',
                    '-use_fast_math',
                    f'-arch={arch}',
                ],
                no_extern_c=False
            )
            
            g_table_x_ptr, _ = mod.get_global("G_TABLE_X")
            g_table_y_ptr, _ = mod.get_global("G_TABLE_Y")
            
            cuda.memcpy_htod(g_table_x_ptr, self.g_table_x)
            cuda.memcpy_htod(g_table_y_ptr, self.g_table_y)
            
            crack_kernel = mod.get_function("crack_secp256k1_multi_gpu")
            
            batch_size = calculate_optimal_batch_size(self.gpu_id)
            block_size = 256
            grid_size = (batch_size + block_size - 1) // block_size
            
            print(f"⚡ GPU {self.gpu_id}: Batch size: {batch_size:,} threads")
            
            result_dtype = np.dtype([
                ('found', np.int32),
                ('private_key', np.uint32, 8),
                ('pubkey_hash', np.uint8, 20)
            ])
            
            result_host = cuda.pagelocked_empty(batch_size, dtype=result_dtype)
            start_keys_ptr = cuda.mem_alloc(32)
            result_ptr = cuda.mem_alloc(result_host.nbytes)
            
            target_hash_bytes = self.target_hash
            if len(target_hash_bytes) < 20:
                target_hash_bytes = target_hash_bytes.ljust(20, b'\x00')
            
            target_hash_ptr = cuda.mem_alloc(20)
            cuda.memcpy_htod_async(target_hash_ptr, target_hash_bytes, stream=stream)
            
            current_key_int = int(self.min_key, 16)
            max_key_int = int(self.max_key, 16)
            
            total_checked = 0
            start_time = time.time()
            last_print = start_time
            
            print(f"🔍 GPU {self.gpu_id}: Search started...")
            
            while current_key_int < max_key_int and not self.found:
                current_hex = hex(current_key_int)[2:].zfill(64)
                key_u256 = hex_to_u256(current_hex)
                
                cuda.memcpy_htod_async(start_keys_ptr, key_u256.tobytes(), stream=stream)
                
                crack_kernel(
                    start_keys_ptr,
                    target_hash_ptr,
                    result_ptr,
                    np.uint64(batch_size),
                    block=(block_size, 1, 1),
                    grid=(grid_size, 1),
                    stream=stream
                )
                
                cuda.memcpy_dtoh_async(result_host, result_ptr, stream=stream)
                stream.synchronize()
                
                # Filter keys dengan validasi tambahan
                for i in range(min(batch_size, max_key_int - current_key_int)):
                    # Hanya proses jika kernel melaporkan found=1
                    if result_host[i]['found'] != 1:
                        continue
                    
                    key_parts = result_host[i]['private_key']
                    recovered_hex = u256_to_hex(key_parts)
                    
                    # Skip key yang jelas tidak valid
                    if recovered_hex == '0' * 64:
                        continue
                    
                    if len(recovered_hex) != 64:
                        continue
                    
                    if verify_private_key(recovered_hex, TARGET_ADDR):
                        self.found = True
                        self.result_queue.put({
                            'gpu_id': self.gpu_id,
                            'private_key': recovered_hex,
                            'status': 'FOUND'
                        })
                        print(f"🎉 GPU {self.gpu_id}: Found key: {recovered_hex}")
                        break
                
                current_key_int += batch_size
                total_checked += batch_size
                
                current_time = time.time()
                if current_time - last_print >= 2.0:
                    elapsed = current_time - start_time
                    if elapsed > 0:
                        speed = total_checked / elapsed
                        progress_pct = min(100.0, (current_key_int - int(self.min_key, 16)) / 
                                         (max_key_int - int(self.min_key, 16)) * 100)
                        
                        current_disp = hex(current_key_int)[2:].zfill(64)
                        print(f"GPU {self.gpu_id} | Speed: {speed/1_000_000:.2f} MKeys/s | "
                              f"Progress: {progress_pct:.2f}% | Current: ...{current_disp[-16:]}")
                        last_print = current_time
                
                if self.found:
                    break
            
            if not self.found:
                self.result_queue.put({
                    'gpu_id': self.gpu_id,
                    'status': 'COMPLETED',
                    'keys_checked': total_checked
                })
                
        except Exception as e:
            print(f"❌ GPU {self.gpu_id}: Error - {e}")
            import traceback
            traceback.print_exc()
            self.result_queue.put({
                'gpu_id': self.gpu_id,
                'status': 'ERROR',
                'error': str(e)
            })
        finally:
            if context:
                context.pop()

# ==================== MULTI-GPU MANAGER ====================
class MultiGPUManager:
    def __init__(self):
        try:
            cuda.init()
            self.num_gpus = cuda.Device.count()
            print(f"🔧 Found {self.num_gpus} GPU(s)")
        except:
            self.num_gpus = 0
            print("⚠️ No CUDA-capable GPU found or CUDA not installed")
        
        # Run tests
        print("\n🔧 Running tests...")
        ripemd160_ok = test_ripemd160()
        bitcoin_ok = test_bitcoin_address_generation()
        
        # Test GPU libraries
        test_gpu_libraries()
        
        if not ripemd160_ok or not bitcoin_ok:
            print("❌ Critical tests failed. Exiting.")
            sys.exit(1)
    
    def start_search(self, target_addr):
        print(f"\n{'='*60}")
        print(f"🎯 TARGET ADDRESS: {target_addr}")
        print(f"🔍 SEARCH RANGE: {MIN_RANGE} to {MAX_RANGE}")
        print(f"{'='*60}")
        
        try:
            target_hash = address_to_hash160(target_addr)
            print(f"📝 Target Hash160: {target_hash.hex()}")
            
            g_table_x, g_table_y = precompute_g_table_cpu()
        except Exception as e:
            print(f"❌ Initialization Error: {e}")
            return
        
        min_int = int(MIN_RANGE, 16)
        max_int = int(MAX_RANGE, 16)
        total_keys = max_int - min_int
        
        print(f"📊 Total keys to search: {total_keys:,}")
        
        if self.num_gpus == 0:
            print("❌ No GPUs available for CUDA computation")
            return
        
        gpu_ids = GPU_IDS if not USE_ALL_GPUS else list(range(self.num_gpus))
        if not gpu_ids:
            print("❌ No GPUs available")
            return
        
        print(f"🚀 Using {len(gpu_ids)} GPU(s): {gpu_ids}")
        
        range_per_gpu = total_keys // len(gpu_ids)
        processes = []
        result_queue = mp.Queue()
        
        for i, gpu_id in enumerate(gpu_ids):
            sub_min = min_int + (i * range_per_gpu)
            sub_max = sub_min + range_per_gpu if i < len(gpu_ids) - 1 else max_int
            sub_min = max(sub_min, min_int)
            sub_max = min(sub_max, max_int)
            
            p = mp.Process(
                target=worker_wrapper,
                args=(gpu_id, hex(sub_min)[2:], hex(sub_max)[2:], target_hash, g_table_x, g_table_y, result_queue)
            )
            p.daemon = True
            p.start()
            processes.append(p)
            time.sleep(0.5)
        
        print(f"\n🔍 Search started at {time.strftime('%H:%M:%S')}")
        print("Press Ctrl+C to stop\n")
        
        found = False
        completed = 0
        errors = 0
        start_time = time.time()
        
        try:
            while completed + errors < len(processes) and not found:
                try:
                    res = result_queue.get(timeout=5)
                    
                    if res['status'] == 'FOUND':
                        found = True
                        private_key = res['private_key']
                        print(f"\n{'='*60}")
                        print(f"🎉 KEY FOUND! GPU {res['gpu_id']} 🎉")
                        print(f"KEY: {private_key}")
                        print(f"{'='*60}")
                        with open('found_key.txt', 'w') as f:
                            f.write(private_key)
                        break
                        
                    elif res['status'] == 'COMPLETED':
                        completed += 1
                        print(f"✅ GPU {res['gpu_id']}: Completed ({res['keys_checked']:,} keys checked)")
                        
                    elif res['status'] == 'ERROR':
                        errors += 1
                        print(f"❌ GPU {res['gpu_id']}: Error - {res['error']}")
                        
                except:
                    if not any(p.is_alive() for p in processes):
                        break
                    continue
            
            elapsed = time.time() - start_time
            
            if not found:
                print(f"\n❌ Key not found in range {MIN_RANGE}-{MAX_RANGE}")
            
            print(f"\n📊 Summary:")
            print(f"  Time elapsed: {elapsed:.2f}s")
            print(f"  GPUs completed: {completed}/{len(gpu_ids)}")
            print(f"  GPUs with errors: {errors}")
            
        except KeyboardInterrupt:
            print("\n⚠️ Interrupted by user")
        finally:
            for p in processes:
                if p.is_alive():
                    p.terminate()

def worker_wrapper(gpu_id, min_k, max_k, t_hash, gx, gy, q):
    os.environ['CUDA_VISIBLE_DEVICES'] = str(gpu_id)
    worker = GPUWorker(gpu_id, min_k, max_k, t_hash, gx, gy, q)
    worker.run()

if __name__ == "__main__":
    mp.set_start_method('spawn', force=True)
    manager = MultiGPUManager()
    manager.start_search(TARGET_ADDR)
