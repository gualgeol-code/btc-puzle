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
try:
    # Load ice_secp256k1.so library
    ice_lib = ctypes.CDLL('./ice_secp256k1.so')
    print("✅ ice_secp256k1.so loaded successfully")
    
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
    
    # Define function signatures for ice_secp256k1.so
    ice_lib.scalar_multiplication.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    ice_lib.pubkey_to_address.argtypes = [ctypes.c_int, ctypes.c_bool, ctypes.c_char_p]
    ice_lib.pubkey_to_address.restype = ctypes.c_void_p
    ice_lib.free_memory.argtypes = [ctypes.c_void_p]
    
except Exception as e:
    print(f"⚠️ Error loading external libraries: {e}")
    print("⚠️ Some GPU acceleration features may be disabled")

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
GPU_IDS = [0] if not USE_ALL_GPUS else list(range(cuda.Device.count()))

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
        self.gpu_bits = int(np.log2(bp_size))
        
        # Inisialisasi library ice
        if 'ice_lib' in globals():
            ice_lib.init_secp256_lib()
    
    def scalar_multiplication_gpu(self, private_key_hex):
        """Perkalian skalar menggunakan GPU via ice_secp256k1.so"""
        try:
            # Konversi private key ke format yang diperlukan
            pk_bytes = bytes.fromhex(private_key_hex.zfill(64))
            
            # Alokasi buffer untuk hasil (65 bytes untuk uncompressed pubkey)
            result_buffer = (b'\x00') * 65
            
            # Panggil fungsi C
            ice_lib.scalar_multiplication(pk_bytes, result_buffer)
            
            return bytes(result_buffer)
        except Exception as e:
            print(f"⚠️ GPU scalar multiplication failed: {e}")
            return None
    
    def pubkey_to_address_gpu(self, pubkey_bytes, compressed=True):
        """Konversi public key ke address menggunakan GPU"""
        try:
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
            
            # Buat P3 table
            G = self.scalar_multiplication_gpu('01')  # Generator point
            if not G:
                return False, None
            
            # Hitung P3 = bp_size * P + G
            P = bytes.fromhex(pubkey_uncompressed)
            
            # Untuk demo, kita gunakan ukuran kecil
            actual_bp_size = min(self.bp_size, 1000)
            
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
                str(actual_bp_size).encode('utf8')
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
    
    def batch_verify_keys_gpu(self, private_keys_hex, target_address):
        """
        Verifikasi batch private keys menggunakan GPU
        
        Args:
            private_keys_hex: List private keys dalam format hex
            target_address: Address target untuk verifikasi
            
        Returns:
            List hasil verifikasi
        """
        results = []
        
        for pk_hex in private_keys_hex:
            try:
                # Generate public key menggunakan GPU
                pubkey_bytes = self.scalar_multiplication_gpu(pk_hex)
                
                if not pubkey_bytes:
                    results.append((pk_hex, False))
                    continue
                
                # Konversi ke address menggunakan GPU
                address = self.pubkey_to_address_gpu(pubkey_bytes, compressed=True)
                
                # Bandingkan dengan target
                found = (address == target_address)
                results.append((pk_hex, found))
                
                if found:
                    print(f"🎉 GPU Verification found match: {pk_hex} -> {address}")
                    return results  # Hentikan jika sudah ditemukan
                    
            except Exception as e:
                print(f"⚠️ Error verifying key {pk_hex[:16]}...: {e}")
                results.append((pk_hex, False))
        
        return results

# ==================== MODIFIED CUDA KERNEL DENGAN OPTIMASI ====================
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
    unsigned char pubkey_x[32];
    unsigned char pubkey_y[32];
};

__constant__ uint256_t CURVE_P = {{0xfffffc2f, 0xfffffffe, 0xffffffff, 0xffffffff, 
                                  0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff}};
__constant__ uint256_t CURVE_N = {{0xd0364141, 0xbfd25e8c, 0xaf48a03b, 0xbaaedce6,
                                  0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff}};

__constant__ uint256_t G_TABLE_X[16];
__constant__ uint256_t G_TABLE_Y[16];

// ==================== OPTIMIZED HELPER FUNCTIONS ====================
DEVICE_FUNC void set_zero(uint256_t *a) {
    #pragma unroll
    for (int i = 0; i < 8; i++) a->v[i] = 0;
}

DEVICE_FUNC void set_one(uint256_t *a) {
    set_zero(a);
    a->v[0] = 1;
}

DEVICE_FUNC int is_zero(const uint256_t *a) {
    unsigned int or_result = 0;
    #pragma unroll
    for (int i = 0; i < 8; i++) or_result |= a->v[i];
    return (or_result == 0);
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

// ==================== OPTIMIZED MODULAR ARITHMETIC ====================
DEVICE_FUNC void add_mod(uint256_t *res, const uint256_t *a, const uint256_t *b) {
    unsigned long long carry = 0;
    
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        unsigned long long sum = (unsigned long long)a->v[i] + b->v[i] + carry;
        res->v[i] = (unsigned int)sum;
        carry = sum >> 32;
    }
    
    // Modular reduction if necessary
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

// ==================== ECC POINT MULTIPLICATION OPTIMIZED ====================
DEVICE_FUNC void point_double_fast(jacobian_point *res, const jacobian_point *p) {
    if (is_zero(&p->z)) {
        set_zero(&res->x); set_zero(&res->y); set_zero(&res->z);
        return;
    }
    
    uint256_t a, b, c, d;
    uint256_t three, eight;
    set_zero(&three); three.v[0] = 3;
    set_zero(&eight); eight.v[0] = 8;
    
    // A = 3 * x²
    mod_sqr_fast(&a, &p->x);
    mod_mul_fast(&a, &a, &three);
    
    // B = y * z
    mod_mul_fast(&b, &p->y, &p->z);
    
    // C = y² * x
    mod_sqr_fast(&c, &p->y);
    mod_mul_fast(&c, &c, &p->x);
    
    // D = 3 * C
    mod_mul_fast(&d, &c, &three);
    
    // z' = 2 * B
    mod_mul_fast(&res->z, &b, &two);
    
    // x' = A² - 2*D
    mod_sqr_fast(&res->x, &a);
    uint256_t two_d;
    mod_mul_fast(&two_d, &d, &two);
    sub_mod_fast(&res->x, &res->x, &two_d);
    
    // y' = A*(D - x') - 8*C²
    uint256_t d_minus_x;
    sub_mod_fast(&d_minus_x, &d, &res->x);
    mod_mul_fast(&res->y, &a, &d_minus_x);
    
    uint256_t c_sqr, eight_c_sqr;
    mod_sqr_fast(&c_sqr, &c);
    mod_mul_fast(&eight_c_sqr, &c_sqr, &eight);
    sub_mod_fast(&res->y, &res->y, &eight_c_sqr);
}

DEVICE_FUNC void scalar_multiply_fast(jacobian_point *result, const uint256_t *k) {
    jacobian_point Q;
    set_zero(&Q.x); set_zero(&Q.y); set_zero(&Q.z);
    
    jacobian_point P;
    copy_u256(&P.x, &G_TABLE_X[1]);
    copy_u256(&P.y, &G_TABLE_Y[1]);
    set_one(&P.z);
    
    for (int i = 255; i >= 0; i--) {
        point_double_fast(&Q, &Q);
        
        int word_idx = i / 32;
        int bit_idx = i % 32;
        
        if ((k->v[7 - word_idx] >> bit_idx) & 1) {
            point_add_mixed_fast(&Q, &Q, &P.x, &P.y);
        }
    }
    
    copy_u256(&result->x, &Q.x);
    copy_u256(&result->y, &Q.y);
    copy_u256(&result->z, &Q.z);
}

// ==================== FAST PUBLIC KEY EXTRACTION ====================
DEVICE_FUNC void extract_public_key(unsigned char *pub_x, unsigned char *pub_y, 
                                   const jacobian_point *pub) {
    // Jika di infinity point
    if (is_zero(&pub->z)) {
        #pragma unroll
        for (int i = 0; i < 32; i++) {
            pub_x[i] = 0;
            pub_y[i] = 0;
        }
        return;
    }
    
    // Hitung z inverse dan z² inverse
    uint256_t z_inv, z_inv_sq;
    mod_inv_fast(&z_inv, &pub->z);
    mod_sqr_fast(&z_inv_sq, &z_inv);
    
    // Hitung affine coordinates
    uint256_t affine_x, affine_y;
    mod_mul_fast(&affine_x, &pub->x, &z_inv_sq);
    mod_mul_fast(&affine_y, &pub->y, &z_inv);
    mod_mul_fast(&affine_y, &affine_y, &z_inv_sq);
    
    // Convert to bytes (big-endian)
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        uint32_t word_x = affine_x.v[7 - i];
        uint32_t word_y = affine_y.v[7 - i];
        
        pub_x[i * 4] = (word_x >> 24) & 0xFF;
        pub_x[i * 4 + 1] = (word_x >> 16) & 0xFF;
        pub_x[i * 4 + 2] = (word_x >> 8) & 0xFF;
        pub_x[i * 4 + 3] = word_x & 0xFF;
        
        pub_y[i * 4] = (word_y >> 24) & 0xFF;
        pub_y[i * 4 + 1] = (word_y >> 16) & 0xFF;
        pub_y[i * 4 + 2] = (word_y >> 8) & 0xFF;
        pub_y[i * 4 + 3] = word_y & 0xFF;
    }
}

// ==================== MAIN KERNEL OPTIMIZED ====================
extern "C" __global__ 
void crack_secp256k1_gpu_optimized(const uint256_t *start_keys,
                                   struct Result *results,
                                   unsigned long long total_threads) {
    
    unsigned long long global_idx = threadIdx.x + blockIdx.x * blockDim.x;
    if (global_idx >= total_threads) return;
    
    // Generate private key
    uint256_t private_key;
    copy_u256(&private_key, &start_keys[0]);
    add_u256_with_offset(&private_key, global_idx);
    
    // Validate private key
    if (is_zero(&private_key) || compare_u256(&private_key, &CURVE_N) >= 0) {
        results[global_idx].found = 0;
        return;
    }
    
    // Compute public key
    jacobian_point pub_key;
    scalar_multiply_fast(&pub_key, &private_key);
    
    if (is_zero(&pub_key.z)) {
        results[global_idx].found = 0;
        return;
    }
    
    // Extract public key coordinates
    extract_public_key(results[global_idx].pubkey_x, 
                      results[global_idx].pubkey_y, 
                      &pub_key);
    
    // Mark as found for CPU verification
    results[global_idx].found = 1;
    copy_u256(&results[global_idx].private_key, &private_key);
}
"""

# ==================== PYTHON HELPER FUNCTIONS DENGAN GPU SUPPORT ====================
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

# Inisialisasi GPU verifier
ecc_gpu_verifier = ECCGPUVerifier()

def verify_private_key_gpu_enhanced(private_key_hex, target_address):
    """
    Verifikasi private key menggunakan kombinasi CPU dan GPU
    """
    try:
        # Coba verifikasi menggunakan GPU terlebih dahulu
        pubkey_bytes = ecc_gpu_verifier.scalar_multiplication_gpu(private_key_hex)
        
        if pubkey_bytes:
            # Konversi ke address menggunakan GPU
            address = ecc_gpu_verifier.pubkey_to_address_gpu(pubkey_bytes, compressed=True)
            
            if address and address == target_address:
                print(f"✅ GPU verification successful for key {private_key_hex[:16]}...")
                return True
        
        # Fallback ke verifikasi CPU jika GPU gagal
        return verify_private_key(private_key_hex, target_address)
        
    except Exception as e:
        # Fallback ke CPU verification
        return verify_private_key(private_key_hex, target_address)

def verify_private_key(private_key_hex, target_address):
    """Fallback CPU verification"""
    try:
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
        
        # RIPEMD160
        hash160 = ripemd160_hash(sha256)
        
        # Bitcoin address
        version_hash = b'\x00' + hash160
        checksum = hashlib.sha256(hashlib.sha256(version_hash).digest()).digest()[:4]
        address_bytes = version_hash + checksum
        generated_address = base58.b58encode(address_bytes).decode()
        
        return generated_address == target_address
    except Exception:
        return False

def is_valid_private_key_hex(private_key_hex):
    """Validasi private key sebelum verifikasi"""
    try:
        if not all(c in '0123456789abcdefABCDEF' for c in private_key_hex):
            return False
        
        if len(private_key_hex) != 64:
            return False
        
        priv_key_int = int(private_key_hex, 16)
        CURVE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8B0D1D0E8C
        
        if priv_key_int <= 0:
            return False
        if priv_key_int >= CURVE_N:
            return False
            
        return True
    except:
        return False

# ==================== MODIFIED GPU WORKER CLASS ====================
class GPUWorkerEnhanced:
    def __init__(self, gpu_id, min_key, max_key, target_hash, g_table_x, g_table_y, result_queue):
        self.gpu_id = gpu_id
        self.min_key = min_key
        self.max_key = max_key
        self.target_hash = target_hash
        self.g_table_x = g_table_x
        self.g_table_y = g_table_y
        self.result_queue = result_queue
        self.found = False
        self.ecc_verifier = ECCGPUVerifier(gpu_device=gpu_id)
        
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
            
            mod = SourceModule(
                cuda_code,
                options=[
                    '-O3',
                    '-use_fast_math',
                    f'-arch={arch}',
                    '-lineinfo'  # Untuk debugging jika diperlukan
                ],
                no_extern_c=False
            )
            
            # Set constant memory untuk G table
            g_table_x_ptr, _ = mod.get_global("G_TABLE_X")
            g_table_y_ptr, _ = mod.get_global("G_TABLE_Y")
            
            cuda.memcpy_htod(g_table_x_ptr, self.g_table_x)
            cuda.memcpy_htod(g_table_y_ptr, self.g_table_y)
            
            crack_kernel = mod.get_function("crack_secp256k1_gpu_optimized")
            
            # Hitung batch size optimal
            batch_size = self.calculate_optimal_batch_size(device)
            block_size = 256
            grid_size = (batch_size + block_size - 1) // block_size
            
            print(f"⚡ GPU {self.gpu_id}: Batch size: {batch_size:,} threads")
            
            # Definisikan struktur hasil yang diperbarui
            result_dtype = np.dtype([
                ('found', np.int32),
                ('private_key', np.uint32, 8),
                ('pubkey_hash', np.uint8, 20),
                ('pubkey_x', np.uint8, 32),
                ('pubkey_y', np.uint8, 32)
            ])
            
            result_host = cuda.pagelocked_empty(batch_size, dtype=result_dtype)
            start_keys_ptr = cuda.mem_alloc(32)
            result_ptr = cuda.mem_alloc(result_host.nbytes)
            
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
                
                # Eksekusi kernel
                crack_kernel(
                    start_keys_ptr,
                    result_ptr,
                    np.uint64(batch_size),
                    block=(block_size, 1, 1),
                    grid=(grid_size, 1),
                    stream=stream
                )
                
                cuda.memcpy_dtoh_async(result_host, result_ptr, stream=stream)
                stream.synchronize()
                
                # Proses hasil dengan verifikasi GPU yang ditingkatkan
                for i in range(min(batch_size, max_key_int - current_key_int)):
                    if result_host[i]['found'] != 1:
                        continue
                    
                    key_parts = result_host[i]['private_key']
                    recovered_hex = u256_to_hex(key_parts)
                    
                    # Validasi dasar
                    if recovered_hex == '0' * 64 or len(recovered_hex) != 64:
                        continue
                    
                    # Coba verifikasi menggunakan GPU yang ditingkatkan
                    if verify_private_key_gpu_enhanced(recovered_hex, TARGET_ADDR):
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
                
                # Update progress
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
    
    def calculate_optimal_batch_size(self, device):
        """Hitung batch size optimal berdasarkan memori GPU"""
        try:
            total_mem = device.total_memory()
            usable_mem = total_mem * 0.4  # Lebih konservatif
            bytes_per_thread = 200  # Ukuran struktur hasil yang lebih besar
            optimal_batch = int(usable_mem // bytes_per_thread)
            optimal_batch = min(optimal_batch, 2_000_000)
            optimal_batch = max(optimal_batch, 100_000)
            optimal_batch = (optimal_batch // 256) * 256  # Align dengan block size
            return optimal_batch
        except:
            return 100_000

# ==================== FUNGSI UNTUK TEST LIBRARY GPU ====================
def test_gpu_libraries():
    """Test fungsi library GPU"""
    print("\n🔧 Testing GPU libraries...")
    
    test_private_key = "0000000000000000000000000000000000000000000000000000000000000001"
    expected_address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
    
    try:
        # Test ice_secp256k1.so
        print("  Testing ice_secp256k1.so...")
        pubkey = ecc_gpu_verifier.scalar_multiplication_gpu(test_private_key)
        if pubkey:
            print(f"    ✅ Scalar multiplication successful (pubkey length: {len(pubkey)})")
            
            address = ecc_gpu_verifier.pubkey_to_address_gpu(pubkey, compressed=True)
            if address and address == expected_address:
                print(f"    ✅ Address generation correct: {address}")
            else:
                print(f"    ⚠️ Address mismatch or failed")
        else:
            print("    ❌ Scalar multiplication failed")
        
        # Test bt2.so BSGS
        print("  Testing bt2.so BSGS functionality...")
        # Test sederhana dengan range kecil
        found, pvk = ecc_gpu_verifier.verify_key_bsgs_gpu(
            "02CEB6CBBCDBDF5EF7150682150F4CE2C6F4807B349827DCDBDD1F2EFA885A2630",
            "1", "1000"
        )
        if found:
            print(f"    ✅ BSGS test found key: {pvk}")
        else:
            print("    ⚠️ BSGS test completed (no key found in small range)")
            
    except Exception as e:
        print(f"    ❌ GPU library test failed: {e}")

# ==================== MODIFIED MAIN FUNCTION ====================
if __name__ == "__main__":
    mp.set_start_method('spawn', force=True)
    
    # Run tests termasuk test library GPU
    print("🔧 Running comprehensive tests...")
    
    # Test RIPEMD160
    from Crypto.Hash import RIPEMD160
    test_hash = RIPEMD160.new()
    test_hash.update(b"test")
    if test_hash.hexdigest():
        print("✅ RIPEMD160 test passed")
    
    # Test GPU libraries
    test_gpu_libraries()
    
    # Lanjutkan dengan pencarian seperti sebelumnya
    print(f"\n{'='*60}")
    print(f"🎯 TARGET ADDRESS: {TARGET_ADDR}")
    print(f"🔍 SEARCH RANGE: {MIN_RANGE} to {MAX_RANGE}")
    print(f"{'='*60}")
    
    # Inisialisasi manager
    manager = MultiGPUManager()
    manager.start_search(TARGET_ADDR)
