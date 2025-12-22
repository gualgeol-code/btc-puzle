import os
import sys
import time
import binascii
import hashlib
import numpy as np
import pycuda.driver as cuda
from pycuda.compiler import SourceModule

# --- BAGIAN PERBAIKAN: IMPORT RIPEMD160 DARI PYCRYPTODOME ---
try:
    from Crypto.Hash import RIPEMD160
except ImportError:
    print("Error: Library 'pycryptodome' belum terinstall.")
    print("Silakan jalankan perintah: pip install pycryptodome")
    sys.exit(1)
# ------------------------------------------------------------

# ==================== 1. KONFIGURASI PUZZLE #20 ====================
TARGET_ADDRESS = "1CfZWK1QTQE3eS9qn61dQjV89KDjZzfNcv"

# Range Puzzle #20: 0x80000 s/d 0xFFFFF 200000:3fffff
START_KEY_HEX = "00000000000000000000000000000000000000000000000000000000000200000"
END_KEY_HEX   = "000000000000000000000000000000000000000000000000000000000003fffff"

# Konfigurasi GPU
GRID_SIZE  = 128     
BLOCK_SIZE = 128     
TOTAL_THREADS = GRID_SIZE * BLOCK_SIZE 

# ==================== 2. HELPER PYTHON ====================
def decode_base58(addr):
    """Mengubah Bitcoin Address menjadi 20-byte Hash160"""
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    base_count = len(alphabet)
    num = 0
    for char in addr:
        num = num * base_count + alphabet.index(char)
    # Konversi ke bytes (25 bytes: 1 byte ver + 20 byte hash + 4 byte chk)
    # Kita gunakan padding byte yang cukup
    try:
        combined = num.to_bytes(25, byteorder='big')
    except OverflowError:
        # Fallback jika ada leading zeros yang membuat byte count beda
        h = hex(num)[2:]
        if len(h) % 2 != 0: h = '0' + h
        combined = binascii.unhexlify(h)
        # Pad ke kiri jika kurang dari 25 byte
        combined = b'\x00' * (25 - len(combined)) + combined

    # Ambil 20 byte hash di tengah (skip versi byte pertama [0], buang checksum 4 byte terakhir [-4])
    return combined[1:-4]

# ==================== 3. CUDA KERNEL ====================
cuda_code_hybrid = """
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

__device__ const uint32_t P_ARR[8] = { 0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };

#define GX0 0x16F81798
#define GX1 0x59F2815B
#define GX2 0x2DCE28D9
#define GX3 0x029BFCDB
#define GX4 0xCE870B07
#define GX5 0x55A06295
#define GX6 0xF9DCBBAC
#define GX7 0x79BE667E

#define GY0 0xFB10D4B8
#define GY1 0x9C47D08F
#define GY2 0xA6855419
#define GY3 0xFD17B448
#define GY4 0x0E1108A8
#define GY5 0x5DA4FBFC
#define GY6 0x26A3C465
#define GY7 0x483ADA77

typedef struct { uint32_t n[8]; } u256;
typedef struct { u256 x; u256 y; u256 z; } Point;
typedef struct { 
    uint32_t key_idx;   
    uint32_t pub_x[8]; 
    uint32_t pub_y_parity; 
} Candidate;

#define DEVICE_FUNC __device__ __forceinline__

DEVICE_FUNC void set_zero(u256 *r) { for(int i=0; i<8; i++) r->n[i] = 0; }
DEVICE_FUNC void copy_val(u256 *d, const u256 *s) { for(int i=0; i<8; i++) d->n[i] = s->n[i]; }
DEVICE_FUNC int is_zero(const u256 *a) { return (a->n[0]|a->n[1]|a->n[2]|a->n[3]|a->n[4]|a->n[5]|a->n[6]|a->n[7]) == 0; }
DEVICE_FUNC int ge_P(const u256 *a) { for(int i=7; i>=0; i--) { if(a->n[i]>P_ARR[i]) return 1; if(a->n[i]<P_ARR[i]) return 0; } return 1; }

DEVICE_FUNC int add_raw(u256 *r, const u256 *a, const u256 *b) {
    uint64_t c = 0;
    for(int i=0; i<8; i++) { c += (uint64_t)a->n[i] + b->n[i]; r->n[i] = (uint32_t)c; c >>= 32; }
    return (int)c;
}
DEVICE_FUNC int sub_raw(u256 *r, const u256 *a, const u256 *b) {
    uint64_t borrow = 0;
    for(int i=0; i<8; i++) { uint64_t diff = (uint64_t)a->n[i] - b->n[i] - borrow; r->n[i] = (uint32_t)diff; borrow = (diff >> 63) & 1; }
    return (int)borrow;
}
DEVICE_FUNC void add_mod(u256 *r, const u256 *a, const u256 *b) {
    u256 t; if(add_raw(&t, a, b)) { u256 c={{0x3D1,1,0,0,0,0,0,0}}; add_raw(r, &t, &c); }
    else { if(ge_P(&t)) { u256 p; for(int i=0; i<8; i++) p.n[i]=P_ARR[i]; sub_raw(r, &t, &p); } else copy_val(r, &t); }
}
DEVICE_FUNC void sub_mod(u256 *r, const u256 *a, const u256 *b) {
    u256 t; if(sub_raw(&t, a, b)) { u256 p; for(int i=0; i<8; i++) p.n[i]=P_ARR[i]; add_raw(r, &t, &p); } else copy_val(r, &t);
}
DEVICE_FUNC void mul_mod(u256 *r, const u256 *a, const u256 *b) {
    u256 res; set_zero(&res); u256 ta; copy_val(&ta, a);
    if(is_zero(a) || is_zero(b)) { set_zero(r); return; }
    for(int i=0; i<8; i++) { uint32_t w=b->n[i]; for(int j=0; j<32; j++) { if((w>>j)&1) add_mod(&res, &res, &ta); add_mod(&ta, &ta, &ta); } }
    copy_val(r, &res);
}
DEVICE_FUNC void mod_sqr(u256 *r, const u256 *a) { mul_mod(r, a, a); }
DEVICE_FUNC void mod_inv(u256 *r, const u256 *a) {
    u256 t; copy_val(&t, a);
    u256 p_minus_2 = {{0xFFFFFC2D, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
    u256 res = {{1,0,0,0,0,0,0,0}};
    for(int i=0; i<8; i++) {
        uint32_t w = p_minus_2.n[i];
        for(int j=0; j<32; j++) {
            if((w>>j)&1) mul_mod(&res, &res, &t);
            mod_sqr(&t, &t);
        }
    }
    copy_val(r, &res);
}
DEVICE_FUNC void point_double(Point *r, const Point *p) {
    if(is_zero(&p->z)) { *r = *p; return; }
    u256 M,S,T,tmp,X3,Y3,Z3;
    mul_mod(&Z3, &p->y, &p->z); add_mod(&Z3, &Z3, &Z3);
    mod_sqr(&tmp, &p->y); mul_mod(&S, &p->x, &tmp); add_mod(&S, &S, &S); add_mod(&S, &S, &S);
    mod_sqr(&T, &tmp); add_mod(&T, &T, &T); add_mod(&T, &T, &T); add_mod(&T, &T, &T);
    mod_sqr(&tmp, &p->x); add_mod(&M, &tmp, &tmp); add_mod(&M, &M, &tmp);
    mod_sqr(&X3, &M); add_mod(&tmp, &S, &S); sub_mod(&X3, &X3, &tmp);
    sub_mod(&tmp, &S, &X3); mul_mod(&Y3, &M, &tmp); sub_mod(&Y3, &Y3, &T);
    copy_val(&r->x, &X3); copy_val(&r->y, &Y3); copy_val(&r->z, &Z3);
}
DEVICE_FUNC void point_add(Point *r, const Point *p, const Point *q) {
    if(is_zero(&p->z)) { *r = *q; return; } if(is_zero(&q->z)) { *r = *p; return; }
    u256 Z1Z1,Z2Z2,U1,U2,S1,S2,H,R,X3,Y3,Z3,H2,H3,U1H2;
    mod_sqr(&Z1Z1, &p->z); mod_sqr(&Z2Z2, &q->z);
    mul_mod(&U1, &p->x, &Z2Z2); mul_mod(&U2, &q->x, &Z1Z1);
    mul_mod(&S1, &p->y, &q->z); mul_mod(&S1, &S1, &Z2Z2); mul_mod(&S2, &q->y, &p->z); mul_mod(&S2, &S2, &Z1Z1);
    sub_mod(&H, &U2, &U1); sub_mod(&R, &S2, &S1);
    if(is_zero(&H)) { if(is_zero(&R)) { point_double(r, p); return; } else { set_zero(&r->x); set_zero(&r->y); set_zero(&r->z); return; } }
    mod_sqr(&H2, &H); mul_mod(&H3, &H2, &H); mul_mod(&U1H2, &U1, &H2);
    mod_sqr(&X3, &R); sub_mod(&X3, &X3, &H3); u256 t; add_mod(&t, &U1H2, &U1H2); sub_mod(&X3, &X3, &t);
    sub_mod(&Y3, &U1H2, &X3); mul_mod(&Y3, &Y3, &R); mul_mod(&t, &S1, &H3); sub_mod(&Y3, &Y3, &t);
    mul_mod(&Z3, &p->z, &q->z); mul_mod(&Z3, &Z3, &H);
    copy_val(&r->x, &X3); copy_val(&r->y, &Y3); copy_val(&r->z, &Z3);
}
DEVICE_FUNC void scalar_mul(Point *r, const u256 *k) {
    Point G; 
    G.x.n[0]=GX0; G.x.n[1]=GX1; G.x.n[2]=GX2; G.x.n[3]=GX3; G.x.n[4]=GX4; G.x.n[5]=GX5; G.x.n[6]=GX6; G.x.n[7]=GX7;
    G.y.n[0]=GY0; G.y.n[1]=GY1; G.y.n[2]=GY2; G.y.n[3]=GY3; G.y.n[4]=GY4; G.y.n[5]=GY5; G.y.n[6]=GY6; G.y.n[7]=GY7;
    set_zero(&G.z); G.z.n[0]=1; set_zero(&r->x); set_zero(&r->y); set_zero(&r->z);
    int started = 0;
    for(int i=255; i>=0; i--) {
        if(started) point_double(r, r);
        if((k->n[i/32] >> (i%32)) & 1) { if(!started) { *r = G; started=1; } else point_add(r, r, &G); }
    }
}
DEVICE_FUNC void affine_from_jacobian(u256 *x, u256 *y, const Point *p) {
    u256 zinv, z2, z3;
    mod_inv(&zinv, &p->z);
    mod_sqr(&z2, &zinv);
    mul_mod(&z3, &z2, &zinv);
    mul_mod(x, &p->x, &z2);
    mul_mod(y, &p->y, &z3);
}

extern "C" __global__ void gen_key_points(Candidate *out_buff, const u256 *base_key) {
    uint64_t idx = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
    u256 k; copy_val(&k, base_key); 
    uint64_t carry = idx;
    for(int i=0; i<8; i++) { uint64_t t = (uint64_t)k.n[i] + carry; k.n[i] = (uint32_t)t; carry = t >> 32; }
    Point pub; 
    scalar_mul(&pub, &k);
    u256 x, y;
    affine_from_jacobian(&x, &y, &pub);
    out_buff[idx].key_idx = (uint32_t)idx;
    for(int i=0; i<8; i++) out_buff[idx].pub_x[i] = x.n[i];
    out_buff[idx].pub_y_parity = y.n[0] & 1;
}
"""

def hex_to_u32_array(hex_str):
    arr = []
    hex_str = hex_str.zfill(64)
    for i in range(0, 64, 8):
        arr.append(int(hex_str[64-8-i : 64-i], 16))
    return np.array(arr, dtype=np.uint32)

def main():
    print(f"🎯 PUZZLE #20 SOLVER (ADDRESS MODE - FIXED)")
    print(f"📍 Target Address: {TARGET_ADDRESS}")
    
    # 1. Decode Target Address to Hash160
    target_h160 = decode_base58(TARGET_ADDRESS)
    print(f"💾 Target Hash160: {binascii.hexlify(target_h160).decode()}")
    print("-" * 50)
    
    # 2. Init CUDA
    cuda.init()
    dev = cuda.Device(0)
    ctx = dev.make_context()
    
    try:
        mod = SourceModule(cuda_code_hybrid, options=['-O2', '-use_fast_math'], no_extern_c=False)
        gen_kernel = mod.get_function("gen_key_points")
        
        start_val = int(START_KEY_HEX, 16)
        end_val   = int(END_KEY_HEX, 16)
        
        cand_dtype = np.dtype([('idx', np.uint32), ('x', np.uint32, 8), ('p', np.uint32)])
        batch_size = TOTAL_THREADS
        host_buff = cuda.pagelocked_empty(batch_size, dtype=cand_dtype)
        gpu_buff = cuda.mem_alloc(host_buff.nbytes)
        base_key_gpu = cuda.mem_alloc(32)
        
        current_val = start_val
        found = False
        
        while current_val <= end_val:
            batch_end = min(current_val + batch_size - 1, end_val)
            count = batch_end - current_val + 1
            if count <= 0: break

            print(f"🚀 Scanning {current_val:05x} ... {batch_end:05x}")
            
            curr_base_arr = hex_to_u32_array(f"{current_val:x}")
            cuda.memcpy_htod(base_key_gpu, curr_base_arr.tobytes())
            
            gen_kernel(
                gpu_buff, 
                base_key_gpu, 
                block=(BLOCK_SIZE, 1, 1), 
                grid=(GRID_SIZE, 1)
            )
            ctx.synchronize()
            cuda.memcpy_dtoh(host_buff, gpu_buff)
            
            # --- CPU VERIFICATION LOOP (OPTIMIZED) ---
            for i in range(count):
                item = host_buff[i]
                
                # Reconstruct X bytes (Big Endian)
                # item['x'] array is [LSW...MSW]. Convert to bytes
                x_bytes = b''.join([int(w).to_bytes(4, 'little') for w in item['x']])
                x_bytes = x_bytes[::-1] # Flip to BE
                
                # Compressed Prefix
                prefix = b'\x02' if item['p'] % 2 == 0 else b'\x03'
                pub_compressed = prefix + x_bytes
                
                # --- HASHING FIX HERE ---
                sha = hashlib.sha256(pub_compressed).digest()
                # Gunakan RIPEMD160 dari PyCryptodome
                h160 = RIPEMD160.new(sha).digest()
                # ------------------------
                
                if h160 == target_h160:
                    real_key_int = current_val + int(item['idx'])
                    print(f"\n🎉🎉🎉 FOUND KEY! 🎉🎉🎉")
                    print(f"🔑 Private Key (Hex): {real_key_int:064x}")
                    print(f"🔑 Private Key (Int): {real_key_int}")
                    print(f"📍 Address Found    : {TARGET_ADDRESS}")
                    found = True
                    break
            
            if found: break
            current_val += batch_size
            
    finally:
        ctx.pop()

if __name__ == "__main__":
    main()
