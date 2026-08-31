def create_matrix(key):
    key = key.upper().replace("J", "I")

    matrix = ""

    for ch in key:
        if ch.isalpha() and ch not in matrix:
            matrix += ch

    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in matrix:
            matrix += ch

    return [matrix[i:i + 5] for i in range(0, 25, 5)]


def find_position(matrix, ch):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == ch:
                return i, j


def prepare_text(text):
    text = text.upper().replace("J", "I")
    text = ''.join(ch for ch in text if ch.isalpha())

    result = ""
    i = 0

    while i < len(text):
        a = text[i]

        if i + 1 < len(text):
            b = text[i + 1]

            if a == b:
                result += a + "X"
                i += 1
            else:
                result += a + b
                i += 2
        else:
            result += a + "X"
            i += 1

    return result


def encrypt(text, matrix):
    result = ""

    for i in range(0, len(text), 2):
        a = text[i]
        b = text[i + 1]

        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)

        # Same row
        if r1 == r2:
            result += matrix[r1][(c1 + 1) % 5]
            result += matrix[r2][(c2 + 1) % 5]

        # Same column
        elif c1 == c2:
            result += matrix[(r1 + 1) % 5][c1]
            result += matrix[(r2 + 1) % 5][c2]

        # Rectangle
        else:
            result += matrix[r1][c2]
            result += matrix[r2][c1]

    return result


def decrypt(text, matrix):
    result = ""

    for i in range(0, len(text), 2):
        a = text[i]
        b = text[i + 1]

        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)

        # Same row
        if r1 == r2:
            result += matrix[r1][(c1 - 1) % 5]
            result += matrix[r2][(c2 - 1) % 5]

        # Same column
        elif c1 == c2:
            result += matrix[(r1 - 1) % 5][c1]
            result += matrix[(r2 - 1) % 5][c2]

        # Rectangle
        else:
            result += matrix[r1][c2]
            result += matrix[r2][c1]

    return result


# Main Program

key = input("Enter key: ")
plaintext = input("Enter plaintext: ")

matrix = create_matrix(key)

print("\nPlayfair Matrix:")
for row in matrix:
    print(" ".join(row))

prepared = prepare_text(plaintext)

print("\nPrepared Text:", prepared)

encrypted = encrypt(prepared, matrix)
print("Encrypted Text:", encrypted)

decrypted = decrypt(encrypted, matrix)
print("Decrypted Text:", decrypted)
