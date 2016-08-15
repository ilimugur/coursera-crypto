import argparse

# XOR two ciphertexts and find out if any value is XOR of ' ' and an alphabetic
# character c. XORing ' ' with an alphabetic character c toggles case of c.
# (i.e. uppercase becomes lowercase, and vice versa) Using that, some bytes of
# the key can be found.
def try_finding_key_characters(ct1, ct2):
    found_keys = []
    minLen = min(len(ct1), len(ct2))
    m1m2 = []
    for i in range(minLen):
        m1m2.append( chr(ord(ct1[i]) ^ ord(ct2[i])) )

    for i in range(minLen):
        c = ord(m1m2[i])
        mX = ord(' ')
        mY = c ^ mX
        if ((ord('a') <= mY and mY <= ord('z')) or \
            (ord('A') <= mY and mY <= ord('Z'))):
            if ord(ct1[i]) ^ mX == ord(ct2[i]) ^ mY:
                found_keys.append((i, chr(ord(ct2[i]) ^ mY)))
            if ord(ct2[i]) ^ mY == ord(ct2[i]) ^ mX:
                found_keys.append((i, chr(ord(ct2[i]) ^ mX)))

    return found_keys

# Read input file. Input file is just a plaintext file containing a single
# ciphertext per line. Additionally, the last ciphertext included in the file
# is the one to be decoded.
def get_input(file_path):
    ciphertexts = []
    with open(file_path) as f:
        for hexline in f:
            line = []
            for i in range(0, len(hexline[:-1]), 2):
                line.append( chr( int (hexline[i:i+2], 16 ) ) )
            ciphertexts.append(line)
    return ciphertexts

# For an single byte of the key to be decoded, take in a list consisting of
# candidate values found for that byte. Return a list consisting of
# (frequency, val) pairs, corresponding to each individual candidate value.
# The returned list is in non-increasing order of frequencies.
def classify_based_on_frequency(key_array):
    key_array.sort()
    frequencies = []
    appearances = 1
    for i in range(1, len(key_array)):
        if key_array[i] != key_array[i-1]:
            frequencies.append((appearances, key_array[i-1]))
            appearances = 0
        appearances += 1
    frequencies.append( (appearances, key_array[len(key_array) - 1]) )
    frequencies.sort()
    return frequencies[::-1]

# Compare each ciphertext to the one to be decoded and return a list of
# lists. The element at index i of the returned list corresponds to the sorted
# list candidate value tuples (frequency, value) for byte i of the key.
def brute_force_ciphertext_pairs(cts):
    found_keys = []
    for i in range(0, len(cts) - 1):
        found_keys += try_finding_key_characters(cts[i], cts[-1])

    keys = [[] for i in range(1024)]
    for index, key in found_keys:
        keys[index].append(key)
    for i in range(len(keys)):
        if len(keys[i]) > 0:
            keys[i] = classify_based_on_frequency(keys[i])
    return keys

# Decode the message and print it, assuming that the most frequent candidate
# value for each byte of key is its correct value.
def print_info_found(ciphertexts, key_info):
    key = ''
    for i in range(len(key_info)):
        if len(key_info[i]) > 0:
            key_array = key_info[i]
            if len(key_array) > 0:
		print str(i) + ": " + str(key_array)
    msg_chars = []
    key = []
    for i in range(len(ciphertexts[-1])):
        if len(key_info[i]) > 0:
            key.append(key_info[i][0][1])
            msg_chars.append(chr(ord(key_info[i][0][1]) ^ ord(ciphertexts[-1][i])))
        else:
            key.append(chr(0))
            msg_chars.append(ciphertexts[-1][i])
    print ciphertexts[-1]
    print key
    print ''.join(msg_chars)

def solve(input_file):
    ciphertexts = get_input(input_file)
    key_info = brute_force_ciphertext_pairs(ciphertexts)
    print_info_found(ciphertexts, key_info)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Find out the key used in two-time pad.')
    parser.add_argument('input', metavar='IN', type=str,
                    help='path to input file')
    args = parser.parse_args()
    solve(args.input)
