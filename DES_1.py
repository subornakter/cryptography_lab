# --------------------------------------
    # Step 1: Expansion
    # --------------------------------------

    expanded = permute(R0, E)

    print("\n1. Expansion (32 -> 48 bit)")

    print(show(expanded))


    # --------------------------------------
    # Step 2: XOR
    # --------------------------------------

    x = xor(expanded, round_key)

    print("\n2. XOR")

    print("Expanded R0:")
    print(show(expanded))

    print("\nRound Key:")
    print(show(round_key))

    print("\nXOR Result:")
    print(show(x))


    # --------------------------------------
    # Step 3: S Box
    # --------------------------------------

    s = s_box(x)

    print("\n3. S-Box")

    print("First 6 bits:")
    print(x[:6])

    print("\nS-Box Output:")
    print(show(s, 4))


    # --------------------------------------
    # Make 32 bit for simple demo
    # --------------------------------------

    s32 = (s * 8)[:32]

    print("\nS-Box Output (32 bit demo):")
    print(show(s32, 4))


    # --------------------------------------
    # Step 4: P Box
    # --------------------------------------

    p = permute(s32, P)

    print("\n4. P-Box")

    print(show(p))


    # --------------------------------------
    # Step 5: XOR with L0
    # --------------------------------------

    new_R = xor(L0, p)

    print("\n5. XOR with L0")

    print("\nL0:")
    print(show(L0))

    print("\nP:")
    print(show(p))

    print("\nNew R1:")
    print(show(new_R))


    # --------------------------------------
    # Step 6: Swap
    # --------------------------------------

    L1 = R0
    R1 = new_R

    print("\n6. SWAP")

    print("\nL1:")
    print(show(L1))

    print("\nR1:")
    print(show(R1))


    # --------------------------------------
    # FINAL
    # --------------------------------------

    print("\n===================================")
    print(" ROUND 1 COMPLETE")
    print("===================================")

    print("\nL1:")
    print(show(L1))

    print("\nR1:")
    print(show(R1))
