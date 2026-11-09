BLOCK_BITS = 1024    # block size
LENGTH_BITS = 128    # length field size


def padding_length(m_bits: int) -> int:
    # Textbook formula: |P| = (-|M| - 128) mod 1024
    return (-m_bits - LENGTH_BITS) % BLOCK_BITS


def sha512_pad(message: bytes):
    m_bits = len(message) * 8

    # Message preparation: length must be less than 2^128 bits
    if m_bits >= 2**128:
        raise ValueError("Message length must be less than 2^128 bits")

    # Step 1: calculate padding length
    p_bits = padding_length(m_bits)

    # Padding needs at least one '1' bit, so if the formula gives 0,
    # a full extra block (1024 bits) is added (as in FIPS 180-4)
    if p_bits == 0:
        p_bits = BLOCK_BITS

    # Step 2: padding = one '1' followed by (p_bits - 1) zeros
    padding_int = 1 << (p_bits - 1)
    padding = padding_int.to_bytes(p_bits // 8, "big")

    # Step 3: 128-bit length field (length of the original message)
    length_field = m_bits.to_bytes(LENGTH_BITS // 8, "big")

    # Step 4: augmented message = message + padding + length field
    padded = message + padding + length_field
    return m_bits, p_bits, padding, length_field, padded


def bits_str(data: bytes) -> str:
    return "".join(f"{b:08b}" for b in data)


if __name__ == "__main__":
    text = input("Enter a message: ")
    message = text.encode("utf-8")

    m_bits, p_bits, padding, length_field, padded = sha512_pad(message)

    print("\n--- Padding Calculation ---")
    print(f"|M| (original length)  = {m_bits} bits")
    print(f"|P| = (-{m_bits} - 128) mod 1024 = {(-m_bits - 128) % 1024}")
    print(f"Actual padding         = {p_bits} bits "
          f"(one 1 followed by {p_bits - 1} zeros)")
    print(f"Length field           = 128 bits (value = {m_bits})")

    total_bits = len(padded) * 8
    print(f"\nTotal augmented length = {m_bits} + {p_bits} + 128 = {total_bits} bits")
    print(f"Number of blocks (N)   = {total_bits // BLOCK_BITS}")

    print("\n--- Augmented message (hex) ---")
    for i in range(0, len(padded), 128):
        print(f"Block {i // 128 + 1}: {padded[i:i + 128].hex()}")

    print("\n--- First 16 bits of padding ---")
    print(bits_str(padding)[:16] + " ...")
