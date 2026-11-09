import math

MASK = (1 << 64) - 1          # addition modulo 2^64
BLOCK_BITS = 1024
LENGTH_BITS = 128
ROUNDS_TO_SHOW = 2            # Round 0 and Round 1

# Book's Rotate(E) uses (28, 34, 39). The official SHA-512 uses (14, 18, 41).
# Set to False to follow the book exactly.
USE_STANDARD_E_ROTATION = True


# ---------------- Constants (Table 12.7 and 12.8) ----------------
def first_primes(n):
    primes, c = [], 2
    while len(primes) < n:
        if all(c % p for p in primes if p * p <= c):
            primes.append(c)
        c += 1
    return primes


def icbrt(n):
    lo, hi = 0, 1 << (n.bit_length() // 3 + 2)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** 3 <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo


INITIAL = [math.isqrt(p << 128) & MASK for p in first_primes(8)]   # A0..H0
K = [icbrt(p << 192) & MASK for p in first_primes(80)]             # K0..K79


# ---------------- Padding (Fig. 12.19) ----------------
def sha512_pad(message: bytes):
    m_bits = len(message) * 8
    if m_bits >= 2 ** 128:
        raise ValueError("Message length must be less than 2^128 bits")
    p_bits = (-m_bits - LENGTH_BITS) % BLOCK_BITS
    if p_bits == 0:                      # at least one '1' bit is required
        p_bits = BLOCK_BITS
    padding = (1 << (p_bits - 1)).to_bytes(p_bits // 8, "big")
    length_field = m_bits.to_bytes(LENGTH_BITS // 8, "big")
    return m_bits, p_bits, message + padding + length_field


# ---------------- Basic operations ----------------
def rotr(x, n):
    return ((x >> n) | (x << (64 - n))) & MASK


def majority(x, y, z):
    return (x & y) ^ (y & z) ^ (z & x)


def conditional(x, y, z):
    return (x & y) ^ (~x & MASK & z)


def rotate_a(x):
    return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39)


def rotate_e(x):
    if USE_STANDARD_E_ROTATION:
        return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41)
    return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39)


def rotshift_1_8_7(x):
    return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7)


def rotshift_19_61_6(x):
    return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6)


# ---------------- Word expansion (Fig. 12.21) ----------------
def expand_block(block: bytes):
    W = [int.from_bytes(block[i:i + 8], "big") for i in range(0, 128, 8)]
    for t in range(16, 80):
        w = (W[t - 16] + rotshift_1_8_7(W[t - 15])
             + W[t - 7] + rotshift_19_61_6(W[t - 2])) & MASK
        W.append(w)
    return W


# ---------------- Printing helpers ----------------
def show_state(title, state):
    print(title)
    for name, val in zip("ABCDEFGH", state):
        print(f"    {name} = {val:016x}")


def line(label, val):
    print(f"    {label:<34} = {val:016x}")


# ---------------- One round, step by step (Fig. 12.23) ----------------
def one_round_verbose(round_no, state, w, k):
    a, b, c, d, e, f, g, h = state
    print(f"\n--- Round {round_no} ---")
    line(f"W{round_no}", w)
    line(f"K{round_no}", k)

    print("  Mixer 1 (works on A, B, C):")
    maj = majority(a, b, c)
    line("Majority(A,B,C)", maj)
    rot_a = rotate_a(a)
    line("Rotate(A)", rot_a)
    mixer1 = (maj + rot_a) & MASK
    line("Mixer1 = Majority + Rotate(A)", mixer1)

    print("  Mixer 2 (works on E, F, G, H):")
    cond = conditional(e, f, g)
    line("Conditional(E,F,G)", cond)
    rot_e = rotate_e(e)
    line("Rotate(E)", rot_e)
    mixer2 = (cond + rot_e + w + k + h) & MASK
    line("Mixer2 = Cond + Rot(E) + W + K + H", mixer2)

    print("  New buffers that need computing:")
    x = (mixer1 + mixer2) & MASK
    line("X (new A) = Mixer1 + Mixer2", x)
    y = (mixer2 + d) & MASK
    line("Y (new E) = Mixer2 + D", y)

    print("  Copies: A->B, B->C, C->D, E->F, F->G, G->H")
    new_state = [x, a, b, c, y, e, f, g]
    show_state(f"  Buffers after Round {round_no}:", new_state)
    return new_state


# ---------------- Main ----------------
if __name__ == "__main__":
    text = input("Enter a message: ")
    message = text.encode("utf-8")

    # Step 1: padding
    m_bits, p_bits, padded = sha512_pad(message)
    total_bits = len(padded) * 8
    print("\n=== Step 1: Padding ===")
    print(f"|M| = {m_bits} bits")
    print(f"|P| = (-{m_bits} - 128) mod 1024 = {(-m_bits - 128) % 1024}, "
          f"actual padding used = {p_bits} bits")
    print(f"Total = {m_bits} + {p_bits} + 128 = {total_bits} bits, "
          f"blocks (N) = {total_bits // BLOCK_BITS}")

    # Step 2: Block 1
    block1 = padded[:128]
    print("\n=== Step 2: Block 1 (1024 bits = 16 words) ===")
    print(block1.hex())

    # Step 3: word expansion
    W = expand_block(block1)
    print("\n=== Step 3: Word expansion (W0 to W79) ===")
    for t in range(16):
        print(f"  W{t:<2} = {W[t]:016x}")
    print(f"  W16 = {W[16]:016x}")

    # Step 4: initial digest (input of the compression function)
    print("\n=== Step 4: Compression function input ===")
    state = INITIAL[:]
    show_state("  Initial digest A0..H0:", state)

    # Step 5: save buffers into temporary variables
    saved = state[:]
    print("\n=== Step 5: Save the 8 buffers into temporary variables ===")

    # Step 6: rounds
    print("\n=== Step 6: Rounds ===")
    for r in range(ROUNDS_TO_SHOW):
        state = one_round_verbose(r, state, W[r], K[r])
