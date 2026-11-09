#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AES-128  -  VISUAL STEP-BY-STEP ENCRYPTION
Textbook : Cryptography and Network Security (Ch. 7)

Mapping   : A=00, B=01, ... Z=25 (0x19)
Padding   : short plaintext / key is padded with 'Z'
State     : filled COLUMN by COLUMN  (Fig. 7.3 / 7.4)
Rounds    : SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
            (round 10 has no MixColumns)
Requires Python 3.10+  (uses match-case)
"""

import os
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass
if os.name == "nt":
    os.system("")                      # enable ANSI colours on Windows

USE_COLOR = sys.stdout.isatty()
WIDTH = 78


# ═════════════════════════════════════════════════════════════════════
#  PART 1 :  Constants  (S-Box, Rcon, MixColumns matrix)
# ═════════════════════════════════════════════════════════════════════
S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,

    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,

    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,

    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,

    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,

    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,

    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,

    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,

    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,

    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,

    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,

    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,

    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,

    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,

    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,

    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

RCON = [
    0x00,
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
    0x40,
    0x80,
    0x1B,
    0x36
]

MIX = [[2, 3, 1, 1],
       [1, 2, 3, 1],
       [1, 1, 2, 3],
       [3, 1, 1, 2]]


def gf_mul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8), modulus x^8+x^4+x^3+x+1."""
    out = 0
    while b:
        if b & 1:
            out ^= a
        a = ((a << 1) ^ 0x11B) if a & 0x80 else (a << 1)
        a &= 0xFF
        b >>= 1
    return out


# ═════════════════════════════════════════════════════════════════════
#  PART 2 :  Pretty-printing toolkit
# ═════════════════════════════════════════════════════════════════════
def paint(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def hx(seq) -> str:
    return " ".join(f"{v:02X}" for v in seq)


def banner(title: str, subtitle: str = "", color: str = "1;36") -> None:
    print()
    print(paint("=" * WIDTH, color))
    print(paint(title.center(WIDTH), color))
    if subtitle:
        print(paint(subtitle.center(WIDTH), color))
    print(paint("=" * WIDTH, color))


def step(title: str) -> None:
    print()
    print(paint(f"  {title}", "1;33"))
    print("  " + "┈" * (WIDTH - 4))


def note(text: str) -> None:
    print(paint(f"    {text}", "2"))


def matrix_box(s) -> list[str]:
    top = "┌" + "┬".join(["────"] * 4) + "┐"
    bot = "└" + "┴".join(["────"] * 4) + "┘"
    rows = ["│" + "│".join(f" {s[r][c]:02X} " for c in range(4)) + "│"
            for r in range(4)]
    return [top] + rows + [bot]


def flow(items, ops) -> None:
    """Draw several 4x4 matrices side by side joined by operators."""
    boxes = [matrix_box(s) for _, s in items]
    print()
    print("   " + "     ".join(t.center(21) for t, _ in items))
    for ln in range(6):
        parts = []
        for i, b in enumerate(boxes):
            parts.append(b[ln])
            if i < len(ops):
                parts.append(f" {ops[i]:^3} " if ln == 3 else "     ")
        print("   " + "".join(parts))


def to_state(block) -> list[list[int]]:
    """16 bytes -> 4x4 matrix, filled column by column."""
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def to_block(state) -> list[int]:
    return [state[r][c] for c in range(4) for r in range(4)]


def show_output(label: str, state) -> None:
    """Print the round output as a hex line AND as a state matrix."""
    print(f"\n    {label} output : {hx(to_block(state))}")
    flow([(f"{label} state", state)], [])


# ═════════════════════════════════════════════════════════════════════
#  PART 3 :  Input handling  (A=0 ... Z=25, pad with Z)
# ═════════════════════════════════════════════════════════════════════
def read_letters(prompt: str) -> str:
    while True:
        raw = input(prompt).replace(" ", "").upper()
        if not raw:
            print(paint("    Input cannot be empty. Try again.", "31"))
        elif not all("A" <= ch <= "Z" for ch in raw):
            print(paint("    Only English letters (A-Z) are allowed.", "31"))
        else:
            return raw


def pad_to(text: str, size: int = 16, cut: bool = False) -> str:
    if len(text) < size:
        return text + "Z" * (size - len(text))
    if cut and len(text) > size:
        return text[:size]
    if not cut and len(text) % size:
        return text + "Z" * (size - len(text) % size)
    return text


def char_table(text: str, label: str) -> None:
    nums = [ord(ch) - 65 for ch in text]
    print(f"    {label}")
    print("      Letter  : " + "  ".join(f"{ch:>2}" for ch in text))
    print("      Decimal : " + "  ".join(f"{n:>2}" for n in nums))
    print("      Hex     : " + "  ".join(f"{n:02X}" for n in nums))


# ═════════════════════════════════════════════════════════════════════
#  PART 4 :  Key expansion  (with full working shown)
# ═════════════════════════════════════════════════════════════════════
def expand_key(key: list[int]) -> list[list[list[int]]]:
    banner("KEY EXPANSION", "16-byte cipher key  →  44 words  →  11 round keys")
    w = [key[i:i + 4] for i in range(0, 16, 4)]

    step("Step A : first four words come straight from the cipher key")
    for i in range(4):
        print(f"      w{i:<2} = {hx(w[i])}")

    for rnd in range(1, 11):
        step(f"Step B : generating Round Key {rnd}   (w{4 * rnd} … w{4 * rnd + 3})")
        base = 4 * rnd
        prev = w[base - 1]
        rot = prev[1:] + prev[:1]
        sub = [S_BOX[b] for b in rot]
        rc = RCON[rnd]
        t = [sub[0] ^ rc] + sub[1:]
        print(f"      g(w{base - 1}) :  {hx(prev)}")
        print(f"        RotWord  →  {hx(rot)}")
        print(f"        SubWord  →  {hx(sub)}")
        print(f"        XOR Rcon →  {sub[0]:02X} XOR {rc:02X} = {t[0]:02X}   "
              f"⇒ t = {hx(t)}")
        w.append([w[base - 4][j] ^ t[j] for j in range(4)])
        print(f"      w{base:<2} = w{base - 4} XOR t     = {hx(w[base])}")
        for k in range(1, 4):
            i = base + k
            w.append([w[i - 4][j] ^ w[i - 1][j] for j in range(4)])
            print(f"      w{i:<2} = w{i - 4} XOR w{i - 1}"
                  f"{' ' if i < 10 else ''}    = {hx(w[i])}")

    keys = []
    for r in range(11):
        words = w[4 * r:4 * r + 4]
        keys.append([[words[c][row] for c in range(4)] for row in range(4)])

    step("Summary : all round keys (byte order = column by column)")
    for r in range(11):
        tag = "Pre-round" if r == 0 else f"Round {r:<2} "
        print(f"      K{r:<2} {tag} │ {hx(to_block(keys[r]))}")
    return keys


# ═════════════════════════════════════════════════════════════════════
#  PART 5 :  The four transformations (each one explains itself)
# ═════════════════════════════════════════════════════════════════════
def do_sub_bytes(s):
    out = [[S_BOX[b] for b in row] for row in s]
    step("1 │ SubBytes   (every byte replaced using the S-Box)")
    note("high hex digit = S-Box row, low hex digit = S-Box column")
    line = "┌" + "┬".join(["───────"] * 4) + "┐"
    print("      " + line)
    for r in range(4):
        cells = "│".join(f" {s[r][c]:02X}→{out[r][c]:02X} " for c in range(4))
        print(f"      │{cells}│")
    print("      " + "└" + "┴".join(["───────"] * 4) + "┘")
    flow([("Before", s), ("After SubBytes", out)], ["➜"])
    return out


def do_shift_rows(s):
    out = [s[r][r:] + s[r][:r] for r in range(4)]
    step("2 │ ShiftRows  (row r rotates r bytes to the LEFT)")
    for r in range(4):
        shift = f"⟵ {r} left" if r else "  no shift"
        print(f"      Row {r}   {hx(s[r])}   {shift:<10}   {hx(out[r])}")
    flow([("Before", s), ("After ShiftRows", out)], ["➜"])
    return out


def do_mix_columns(s):
    out = [[0] * 4 for _ in range(4)]
    step("3 │ MixColumns (each column × constant matrix in GF(2⁸))")
    note("• means GF(2⁸) multiplication, XOR means XOR")
    for c in range(4):
        col = [s[r][c] for r in range(4)]
        print(f"\n      Column {c}  =  [ {hx(col)} ]")
        for r in range(4):
            coeff = MIX[r]
            sym = " XOR ".join(f"{coeff[k]:02X}•{col[k]:02X}" if coeff[k] != 1
                               else f"{col[k]:02X}" for k in range(4))
            prods = [gf_mul(coeff[k], col[k]) for k in range(4)]
            res = prods[0] ^ prods[1] ^ prods[2] ^ prods[3]
            out[r][c] = res
            print(f"        s'[{r},{c}] = {sym}")
            print(f"                = {' XOR '.join(f'{p:02X}' for p in prods)}"
                  f"  =  {paint(f'{res:02X}', '1;32')}")
    flow([("Before", s), ("After MixColumns", out)], ["➜"])
    return out


def do_add_round_key(s, k, rnd: int, number: str):
    out = [[s[r][c] ^ k[r][c] for c in range(4)] for r in range(4)]
    step(f"{number} │ AddRoundKey (state XOR round key {rnd})")
    flow([("State", s), (f"Round key {rnd}", k), ("Result", out)], ["XOR", "="])
    return out


# ═════════════════════════════════════════════════════════════════════
#  PART 6 :  Full encryption of one block
# ═════════════════════════════════════════════════════════════════════
def encrypt_block(block: list[int], keys) -> list[int]:
    state = to_state(block)

    banner("PRE-ROUND", "Initial state  +  AddRoundKey (K0)", "1;35")
    flow([("Plaintext state", state)], [])
    state = do_add_round_key(state, keys[0], 0, "0")
    show_output("Pre-round", state)

    for rnd in range(1, 11):
        last = rnd == 10
        banner(f"ROUND {rnd}", "", "1;32" if not last else "1;31")
        state = do_sub_bytes(state)
        state = do_shift_rows(state)
        if not last:
            state = do_mix_columns(state)
            state = do_add_round_key(state, keys[rnd], rnd, "4")
        else:
            note("Round 10 has only three transformations - MixColumns is missing.")
            state = do_add_round_key(state, keys[rnd], rnd, "3")
        show_output(f"Round {rnd}", state)
    return to_block(state)


# ═════════════════════════════════════════════════════════════════════
#  PART 7 :  Menu actions
# ═════════════════════════════════════════════════════════════════════
def run_encryption() -> None:
    banner("AES-128 ENCRYPTION")
    plain = read_letters("\n    Plaintext : ")
    key_raw = read_letters("    Key       : ")

    key_txt = pad_to(key_raw, cut=True)
    if len(key_raw) > 16:
        note("Key longer than 16 letters - only the first 16 are used.")
    elif len(key_raw) < 16:
        note(f"Key has {len(key_raw)} letters - padded with "
             f"{16 - len(key_raw)} × 'Z'.")

    plain_txt = pad_to(plain)
    if len(plain_txt) != len(plain):
        note(f"Plaintext has {len(plain)} letters - padded with "
             f"{len(plain_txt) - len(plain)} × 'Z'.")

    banner("STEP 0 : TEXT  →  NUMBERS  →  HEX", "A=00  B=01  …  Z=25 (0x19)")
    char_table(key_txt, "KEY")
    blocks = [plain_txt[i:i + 16] for i in range(0, len(plain_txt), 16)]
    for n, blk in enumerate(blocks, 1):
        print()
        char_table(blk, f"PLAINTEXT BLOCK {n}")

    keys = expand_key([ord(ch) - 65 for ch in key_txt])

    cipher: list[int] = []
    cipher_blocks: list[list[int]] = []
    for n, blk in enumerate(blocks, 1):
        banner(f"ENCRYPTING BLOCK {n} of {len(blocks)}", f"input : {blk}")
        out = encrypt_block([ord(ch) - 65 for ch in blk], keys)
        cipher += out
        cipher_blocks.append(out)

    banner("FINAL CIPHERTEXT", "", "1;32")
    print()
    print("Ciphertext Hex:")
    print(hx(cipher))
    for n, out in enumerate(cipher_blocks, 1):
        print()
        if len(cipher_blocks) > 1:
            print(f"Final Ciphertext Matrix (Block {n}):")
        else:
            print("Final Ciphertext Matrix:")
        for line in matrix_box(to_state(out)):
            print(line)
    print()


MENU = """
------------------------------------------
          AES-128  ENCRYPTION
------------------------------------------
      1. Encrypt a message
      2. Exit
------------------------------------------"""


def main() -> None:
    while True:
        print(paint(MENU, "1;36"))
        choice = input("    Select an option : ").strip()
        match choice:
            case "1":
                run_encryption()
            case "2":
                print(paint("\n    Thank you! Program terminated.\n", "1;32"))
                break
            case _:
                print(paint("\n    Invalid option - please enter 1 or 2.", "31"))


if __name__ == "__main__":
    main()
