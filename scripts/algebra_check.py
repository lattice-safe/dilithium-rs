#!/usr/bin/env python3
"""Bit-exact algebraic verification of dilithium-rs arithmetic layer.

Re-implements every arithmetic primitive with the exact integer semantics of
the Rust code (i32/i64 wrapping, arithmetic shifts) and checks them against
the mathematical specification of FIPS 204 / CRYSTALS-Dilithium.
"""
import re, random, sys

random.seed(0xD1717)

Q = 8380417
QINV = 58728449
D = 13
N = 256
MONT = pow(2, 32, Q)
FAILS = []

def check(name, cond, detail=""):
    print(f"[{'OK ' if cond else 'FAIL'}] {name}{'' if cond else '  <-- ' + detail}")
    if not cond:
        FAILS.append((name, detail))

def i32(x):
    x &= 0xFFFFFFFF
    return x - (1 << 32) if x >= (1 << 31) else x

def i64(x):
    x &= 0xFFFFFFFFFFFFFFFF
    return x - (1 << 64) if x >= (1 << 63) else x

def asr31(x):  # i32 arithmetic shift right by 31: -1 if negative else 0
    return -1 if x < 0 else 0

# ---------------------------------------------------------------- constants
check("QINV: Q*QINV == 1 (mod 2^32)", (Q * QINV) % (1 << 32) == 1)
f_expected = (MONT * MONT % Q) * pow(256, -1, Q) % Q
check("f = 41978 == mont^2/256 (mod Q)", 41978 % Q == f_expected,
      f"expected {f_expected}")

# ---------------------------------------------------------------- reductions
def montgomery_reduce(a):  # exact Rust semantics of reduce.rs
    t = i32(i32(a) * i32(QINV))          # wrapping i32 multiply
    return i32(i64(a - t * Q) >> 32)

ok = True
for _ in range(200_000):
    a = random.randint(-(1 << 31) * Q, (1 << 31) * Q)
    r = montgomery_reduce(a)
    if (r - a * pow(2, -32, Q)) % Q != 0 or not (-Q < r < Q):
        ok = False; break
check("montgomery_reduce: r == a*2^-32 mod Q, |r| < Q (200k random)", ok, f"a={a}")

def reduce32(a):
    t = (a + (1 << 22)) >> 23
    return a - t * Q

ok = True
lim = 2**31 - 2**22 - 1
for a in [0, 1, -1, Q, -Q, lim, -lim] + [random.randint(-lim, lim) for _ in range(200_000)]:
    r = reduce32(a)
    if (r - a) % Q != 0 or not (-6283008 <= r <= 6283008):
        ok = False; break
check("reduce32: r == a mod Q, |r| <= 6283008 (200k random + bounds)", ok, f"a={a}")

def caddq(a):
    return a + (asr31(a) & Q)

ok = all(caddq(a) == (a + Q if a < 0 else a) for a in
         [-Q + 1, -1, 0, 1, Q - 1] + [random.randint(-Q + 1, Q - 1) for _ in range(10_000)])
check("caddq: adds Q iff negative", ok)

# ---------------------------------------------------------------- rounding
def power2round(a):
    a1 = (a + (1 << (D - 1)) - 1) >> D
    return a1, a - (a1 << D)

ok = True
bad = None
for a in range(Q):  # exhaustive over standard representatives
    a1, a0 = power2round(a)
    if a1 * (1 << D) + a0 != a or not (-(1 << (D - 1)) < a0 <= (1 << (D - 1))):
        ok = False; bad = a; break
check("power2round exhaustive [0,Q): a = a1*2^13 + a0, a0 in (-4096,4096]", ok, f"a={bad}")

def decompose(a, gamma2):  # exact rounding.rs semantics
    a1 = (a + 127) >> 7
    if gamma2 == (Q - 1) // 32:
        a1 = (a1 * 1025 + (1 << 21)) >> 22
        a1 &= 15
    else:
        a1 = (a1 * 11275 + (1 << 23)) >> 24
        a1 ^= asr31(43 - a1) & a1
    a0 = a - a1 * 2 * gamma2
    a0 -= asr31((Q - 1) // 2 - a0) & Q
    return a1, a0

for gamma2, m in [((Q - 1) // 32, 16), ((Q - 1) // 88, 44)]:
    ok = True
    bad = None
    for a in range(Q):
        a1, a0 = decompose(a, gamma2)
        if (a1 * 2 * gamma2 + a0 - a) % Q != 0 or not (0 <= a1 < m) \
           or not (-gamma2 <= a0 <= gamma2):
            ok = False; bad = (a, a1, a0); break
    check(f"decompose gamma2={gamma2} exhaustive: congruence, a1 in [0,{m}), |a0|<=gamma2",
          ok, f"case={bad}")

def make_hint(a0, a1, gamma2):
    return a0 > gamma2 or a0 < -gamma2 or (a0 == -gamma2 and a1 != 0)

def use_hint(a, hint, gamma2):
    a1, a0 = decompose(a, gamma2)
    if not hint:
        return a1
    if gamma2 == (Q - 1) // 32:
        return (a1 + 1) & 15 if a0 > 0 else (a1 - 1) & 15
    if a0 > 0:
        return 0 if a1 == 43 else a1 + 1
    return 43 if a1 == 0 else a1 - 1

# Hint correctness, exactly as used by sign/verify:
#   signer:  (w1, w0) = decompose(w); after norm checks it holds
#            |w0 - u| < gamma2 - beta  (u = <c,s2> part)  and |v| < gamma2
#            h = make_hint(w0 - u + v, w1)
#   verifier: has wv = w - u + v (mod Q);  use_hint(wv, h) must equal w1.
for gamma2, beta in [((Q - 1) // 32, 196), ((Q - 1) // 88, 78)]:
    ok = True
    bad = None
    for _ in range(200_000):
        w = random.randint(0, Q - 1)
        w1, w0 = decompose(w, gamma2)
        s = random.randint(-(gamma2 - beta - 1), gamma2 - beta - 1)  # w0 - u
        v = random.randint(-(gamma2 - 1), gamma2 - 1)                # ct0 part
        u = w0 - s
        h = make_hint(s + v, w1, gamma2)
        got = use_hint((w - u + v) % Q, h, gamma2)
        if got != w1:
            ok = False; bad = (w, s, v, h, got, w1); break
    check(f"hint lemma gamma2={gamma2}: UseHint(wv, MakeHint) == HighBits(w) (200k)",
          ok, f"case={bad}")

# ---------------------------------------------------------------- rej_eta trick
ok = all((t - 5 * ((205 * t) >> 10)) == t % 5 for t in range(15))
check("rej_eta: t - 5*((205t)>>10) == t mod 5 for t in [0,15)", ok)

# ---------------------------------------------------------------- ZETAS table
src = open(sys.argv[1]).read()
m = re.search(r"ZETAS: \[i32; N\] = \[(.*?)\];", src, re.S)
zetas = [int(x) for x in m.group(1).replace("\n", " ").split(",") if x.strip()]
check("ZETAS: table has 256 entries", len(zetas) == N, f"len={len(zetas)}")

def brv8(k):
    return int(format(k, "08b")[::-1], 2)

ok = all(zetas[k] % Q == MONT * pow(1753, brv8(k), Q) % Q for k in range(1, 256)) \
     and all(abs(z) < Q for z in zetas)
check("ZETAS[k] == mont * 1753^brv8(k) mod Q for k in [1,256), |z| < Q", ok)

# ---------------------------------------------------------------- NTT roundtrip
def ntt(a):
    a = a[:]
    k, ln = 0, 128
    while ln > 0:
        start = 0
        while start < N:
            k += 1
            zeta = zetas[k]
            for j in range(start, start + ln):
                t = montgomery_reduce(zeta * a[j + ln])
                a[j + ln] = i32(a[j] - t)
                a[j] = i32(a[j] + t)
            start += 2 * ln
        ln >>= 1
    return a

def invntt_tomont(a):
    a = a[:]
    k, ln = 256, 1
    while ln < N:
        start = 0
        while start < N:
            k -= 1
            zeta = -zetas[k]
            for j in range(start, start + ln):
                t = a[j]
                a[j] = i32(t + a[j + ln])
                a[j + ln] = i32(t - a[j + ln])
                a[j + ln] = montgomery_reduce(zeta * a[j + ln])
            start += 2 * ln
        ln <<= 1
    return [montgomery_reduce(41978 * x) for x in a]

ok = True
scal = None
for trial in range(3):
    poly = [random.randint(0, Q - 1) for _ in range(N)]
    rt = invntt_tomont(ntt(poly))
    for orig, out in zip(poly, rt):
        if abs(out) >= Q:
            ok = False; break
        if orig % Q != 0:
            s = out * pow(orig, -1, Q) % Q
            if scal is None:
                scal = s
            elif s != scal:
                ok = False; break
    if not ok:
        break
check("NTT/INTT roundtrip: outputs in (-Q,Q), uniform scalar multiple", ok)
check("NTT/INTT roundtrip scalar == 2^32 mod Q (Montgomery form)", scal == MONT,
      f"scalar={scal}, MONT={MONT}")

# Convolution correctness: NTT-based product of two random polys equals
# schoolbook product in Z_Q[X]/(X^256+1).
def poly_mul_ref(a, b):
    c = [0] * (2 * N)
    for i in range(N):
        for j in range(N):
            c[i + j] += a[i] * b[j]
    return [(c[i] - c[i + N]) % Q for i in range(N)]

a = [random.randint(0, Q - 1) for _ in range(N)]
b = [random.randint(0, Q - 1) for _ in range(N)]
ah, bh = ntt(a), ntt(b)
ch = [montgomery_reduce(x * y) for x, y in zip(ah, bh)]
c = invntt_tomont(ch)
# net scaling: pointwise mont-mul removes one 2^32; invntt_tomont adds one.
ref = poly_mul_ref(a, b)
ok = all((cv - rv * MONT) % Q == 0 for cv, rv in zip(c, ref)) or \
     all((cv - rv) % Q == 0 for cv, rv in zip(c, ref))
scale0 = (c[0] * pow(ref[0], -1, Q)) % Q if ref[0] % Q else None
check("NTT convolution == schoolbook product (up to known Montgomery scale)",
      ok, f"scale={scale0}")

# ------------------------------------------------- AVX2 lane-math simulation
def u64(x): return x & 0xFFFFFFFFFFFFFFFF
def lo32(x): return x & 0xFFFFFFFF
def sext32(x):
    x = lo32(x)
    return x - (1 << 32) if x >= (1 << 31) else x

def mm256_mul_epi32(a_lanes, b_lanes):
    return [u64(sext32(a) * sext32(b)) for a, b in zip(a_lanes, b_lanes)]

def avx2_montgomery_mul(zeta, ys):
    lanes = [u64((lo32(ys[2*i+1]) << 32) | lo32(ys[2*i])) for i in range(4)]
    zl = [u64((lo32(zeta) << 32) | lo32(zeta))] * 4
    qv = [u64((lo32(Q) << 32) | lo32(Q))] * 4
    qiv = [u64((lo32(QINV) << 32) | lo32(QINV))] * 4

    a_even = mm256_mul_epi32(zl, lanes)
    t_even = mm256_mul_epi32(a_even, qiv)
    tq_even = mm256_mul_epi32(t_even, qv)
    r_even_64 = [u64(a - t) for a, t in zip(a_even, tq_even)]
    r_even_32 = [x >> 32 for x in r_even_64]                 # srli (logical)

    z_odd = [x >> 32 for x in zl]
    y_odd = [x >> 32 for x in lanes]
    a_odd = mm256_mul_epi32(z_odd, y_odd)
    t_odd = mm256_mul_epi32(a_odd, qiv)
    tq_odd = mm256_mul_epi32(t_odd, qv)
    r_odd_64 = [u64(a - t) for a, t in zip(a_odd, tq_odd)]
    r_odd_hi = [x & 0xFFFFFFFF00000000 for x in r_odd_64]    # mask high 32

    out = []
    for e, o in zip(r_even_32, r_odd_hi):
        lane = e | o
        out.append(sext32(lane))
        out.append(sext32(lane >> 32))
    return out

ok = True
bad = None
for _ in range(50_000):
    zeta = random.choice(zetas[1:] + [-z for z in zetas[1:]])
    ys = [random.randint(-(2**31) + 1, 2**31 - 1) for _ in range(8)]
    want = [montgomery_reduce(zeta * y) for y in ys]
    got = avx2_montgomery_mul(zeta, ys)
    if want != got:
        ok = False; bad = (zeta, ys[:2], want[:2], got[:2]); break
check("AVX2 montgomery_mul lane math == scalar (50k random, +/- zetas)", ok, f"{bad}")

# ------------------------------------------------- NEON lane-math simulation
def neon_montgomery_mul(zeta, ys):
    out = []
    for y in ys:
        a = zeta * y                        # vmull: exact 64-bit product
        t = i32(sext32(a) * i32(QINV))      # vmovn truncate, vmul wrapping
        r = i64(a - t * Q) >> 32            # vsub 64-bit, vshrn arithmetic
        out.append(sext32(r))
    return out

ok = True
bad = None
for _ in range(50_000):
    zeta = random.choice(zetas[1:] + [-z for z in zetas[1:]])
    ys = [random.randint(-(2**31) + 1, 2**31 - 1) for _ in range(4)]
    want = [montgomery_reduce(zeta * y) for y in ys]
    got = neon_montgomery_mul(zeta, ys)
    if want != got:
        ok = False; bad = (zeta, ys, want, got); break
check("NEON montgomery_mul lane math == scalar (50k random, +/- zetas)", ok, f"{bad}")

# ------------------------------------------- overflow / range bounds
check("acc bound: 7*Q < reduce32 input limit", 7 * Q < 2**31 - 2**22 - 1, f"7Q={7*Q}")
check("NTT growth bound: 9*Q < 2^31", 9 * Q < 2**31, f"9Q={9*Q}")
check("shiftl bound: (2^10-1) << 13 < 2^31", (2**10 - 1) << 13 < 2**31)
# challenge: tau <= 64 sign bits available
check("challenge: max tau (60) <= 64 sign bits", 60 <= 64)
# gamma1 - eta*tau > 0 for all modes (rejection bound sanity)
for g1, eta, tau in [(1 << 17, 2, 39), (1 << 19, 4, 49), (1 << 19, 2, 60)]:
    check(f"gamma1({g1}) - beta({eta*tau}) > 0", g1 - eta * tau > 0)

print()
if FAILS:
    print(f"{len(FAILS)} FAILURES")
    sys.exit(1)
print("ALL CHECKS PASSED")
