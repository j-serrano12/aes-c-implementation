import ctypes
import sys

# Load our C library
try:
    rijndael = ctypes.CDLL('./rijndael.so')
except OSError:
    print("Could not load the C library.")
    sys.exit(1)

# Import the python implementation of AES frm submodule
sys.path.append('./tests/aes-python')
try: 
    import aes
except ImportError:
    print("Could not import the Python AES implementation.")
    sys.exit(1)

# Test the sub_bytes function for AES-128
def test_sub_bytes_128():
    print("Testing sub_bytes for AES-128: ")

    # Create a block of 16 bytes (AES-128 block size)
    original_bytes = bytes(range(16))

    # With the help of the ctypes library, we can create a mutable buffer that we can pass to our C function
    block = ctypes.create_string_buffer(original_bytes)

    # Call the C function to perform the sub_bytes operation
    rijndael.sub_bytes(block, 0)  # 0 corresponds to AES-128

    # Read 16 bytes back from memory (ignores the hidden null-terminator coming from create_string_buffer) and convert it to a list of integers
    extracted_bytes = ctypes.string_at(block, 16)
    c_output = list(extracted_bytes)

    # Perform the same operation using the Python implementation
    matrix = aes.bytes2matrix(original_bytes)
    aes.sub_bytes(matrix)
    python_output = list(aes.matrix2bytes(matrix))

    # Compare the results
    if c_output == python_output:
        print("Test passed: C and Python implementations produce the same result.")
        return True
    else:
        print("Test failed: C and Python implementations produce different results.")
        return False

def test_shift_rows_128():
    print("Testing shift_rows for AES-128: ")

    # Create a block of 16 bytes (AES-128 block size)
    original_bytes = bytes(range(16))
    # With the help of the ctypes library, we can create a mutable buffer that we can pass to our C function
    block = ctypes.create_string_buffer(original_bytes)

    # Call the C function to perform the shift_rows operation
    rijndael.shift_rows(block, 0)  # 0 corresponds to AES-128

    # Read 16 bytes back from memory (ignores the hidden null-terminator coming from create_string_buffer) and convert it to a list of integers
    extracted_bytes = ctypes.string_at(block, 16)
    c_output = list(extracted_bytes)

    # Convert to matrix, apply operation, then convert back to bytes
    matrix = aes.bytes2matrix(original_bytes)

    # Perform the same operation using the Python implementation
    aes.shift_rows(matrix)

    python_output = list(aes.matrix2bytes(matrix))

    # Compare the results
    if c_output == python_output:
        print("Test passed: C and Python implementations produce the same result.")
        return True
    else:
        print("Test failed: C and Python implementations produce different results.")
        return False


def test_mix_columns_128():
    print("Testing mix_columns for AES-128: ")

    # Create a block of 16 bytes (AES-128 block size)
    original_bytes = bytes(range(16))
    block = ctypes.create_string_buffer(original_bytes)

    # Call the C function to perform the mix_columns operation
    rijndael.mix_columns(block, 0)  # 0 corresponds to AES-128

    # Read 16 bytes back from memory and convert to list
    extracted_bytes = ctypes.string_at(block, 16)
    c_output = list(extracted_bytes)

    # Perform the same operation using the Python implementation
    matrix = aes.bytes2matrix(original_bytes)
    aes.mix_columns(matrix)
    python_output = list(aes.matrix2bytes(matrix))

    # Compare the results
    if c_output == python_output:
        print("Test passed: C and Python implementations produce the same result.")
        return True
    else:
        print("Test failed: C and Python implementations produce different results.")
        return False


def test_add_round_key_128():
    print("Testing add_round_key for AES-128: ")

    # Deterministic input block and round key (16 bytes each)
    original_bytes = bytes(range(16))
    round_key_bytes = bytes([0x0F] * 16)
    block = ctypes.create_string_buffer(original_bytes)
    round_key = ctypes.create_string_buffer(round_key_bytes)

    # Call the C function to perform the add_round_key operation
    rijndael.add_round_key(block, round_key, 0)  # 0 corresponds to AES-128

    # Read 16 bytes back from memory and convert to list
    extracted_bytes = ctypes.string_at(block, 16)
    c_output = list(extracted_bytes)

    # AddRoundKey is byte-wise XOR between state and round key
    expected_output = [b ^ k for b, k in zip(original_bytes, round_key_bytes)]

    # Compare the results
    if c_output == expected_output:
        print("Test passed: add_round_key produced the expected XOR result.")
        return True
    else:
        print("Test failed: add_round_key did not produce the expected XOR result.")
        return False


def test_expand_key_128():
    print("Testing expand_key for AES-128: ")

    # Deterministic AES-128 key (16 bytes)
    cipher_key = bytes(range(16))

    # Configure ctypes signature for expand_key.
    rijndael.expand_key.argtypes = [ctypes.c_char_p, ctypes.c_int]
    rijndael.expand_key.restype = ctypes.POINTER(ctypes.c_ubyte)

    # Call C expand_key (AES_BLOCK_128 = 0)
    expanded_key_ptr = rijndael.expand_key(cipher_key, 0)
    c_output = list(ctypes.string_at(expanded_key_ptr, 176))

    # Build expected 176-byte expanded key using Python reference implementation.
    python_aes = aes.AES(cipher_key)
    python_output = []
    for round_key in python_aes._key_matrices:
        for word in round_key:
            python_output.extend(word)

    # Compare the results
    if c_output == python_output:
        print("Test passed: C and Python key expansion outputs match.")
        return True
    else:
        print("Test failed: C and Python key expansion outputs differ.")
        return False


def test_aes_encrypt_block_128():
    print("Testing aes_encrypt_block for AES-128: ")
    # here we will test our aes_encrypt_block function by encrypting a known plaintext with a known key, and comparing the output to both the Python implementation and a known AES-128 test vector.", which should produce the ciphertext "0a940bb5416ef045f1c39458c653ea5a" according to the AES-128 test vectors. We will also compare the output of our C implementation to the output of the Python implementation to ensure they match.
    plaintext = bytes(range(16))
    key = bytes(range(16))
    # Configure ctypes signature for aes_encrypt_block.
    rijndael.aes_encrypt_block.argtypes = [
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_int,
    ]

    rijndael.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)
    # We will create ctypes buffers for our plaintext and key, which will allow us to pass them to our C function. We will use from_buffer_copy to create a new buffer that contains the same data as our original bytes objects.
    pt_buf = (ctypes.c_ubyte * 16).from_buffer_copy(plaintext)
    key_buf = (ctypes.c_ubyte * 16).from_buffer_copy(key)
    # Now we will call our C function to encrypt the block, and we will get a pointer to the ciphertext output. We will then read 16 bytes from that pointer to get our ciphertext as a bytes object.
    c_output_ptr = rijndael.aes_encrypt_block(pt_buf, key_buf, 0)
    if not c_output_ptr:
        print("Test failed: aes_encrypt_block returned NULL.")
        return False

    c_output = bytes(c_output_ptr[i] for i in range(16))

    python_output = aes.AES(key).encrypt_block(plaintext)
    known_output = bytes.fromhex("0a940bb5416ef045f1c39458c653ea5a")
    # Since our C function allocates memory for the output, we need to free that memory after we are done with it. We can use the free function from the C standard library to do this. We will configure the argument types for free to ensure it is called correctly.
    ctypes.CDLL(None).free.argtypes = [ctypes.c_void_p]
    ctypes.CDLL(None).free(c_output_ptr)

    if c_output != python_output:
        print("Test failed: C and Python aes_encrypt_block outputs differ.")
        return False

    if c_output != known_output:
        print("Test failed: aes_encrypt_block does not match the known AES-128 vector.")
        return False

    print("Test passed: aes_encrypt_block matches Python and the known AES-128 vector.")
    return True

# We will also test our aes_encrypt_block function for AES-256, using a known plaintext, key, and expected ciphertext from the AES-256 test vectors. The plaintext and key will both be 32 bytes long, and the expected ciphertext will be "6760ba39d092c7713caf8a8b94f7ef33bc0dbe7281d33917ccfc0c2f59a3f2a3". We will compare the output of our C implementation to both the Python implementation and the known test vector to ensure correctness.
def test_aes_encrypt_block_256():
    print("Testing aes_encrypt_block for AES_BLOCK_256: ")

    plaintext = bytes(range(32))
    key = bytes(range(32))

    rijndael.aes_encrypt_block.argtypes = [
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_int,
    ]
    rijndael.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)

    pt_buf = (ctypes.c_ubyte * 32).from_buffer_copy(plaintext)
    key_buf = (ctypes.c_ubyte * 32).from_buffer_copy(key)

    c_output_ptr = rijndael.aes_encrypt_block(pt_buf, key_buf, 1)
   

    c_output = bytes(c_output_ptr[i] for i in range(32))
    known_output = bytes.fromhex("6760ba39d092c7713caf8a8b94f7ef33bc0dbe7281d33917ccfc0c2f59a3f2a3")

    ctypes.CDLL(None).free.argtypes = [ctypes.c_void_p]
    ctypes.CDLL(None).free(c_output_ptr)

    if c_output != known_output:
        print("Test failed: aes_encrypt_block does not match the known AES_BLOCK_256 vector.")
        return False

    print("Test passed: aes_encrypt_block matches the known AES_BLOCK_256 vector.")
    return True




if __name__ == "__main__":
    results = [
        test_sub_bytes_128(),
        test_shift_rows_128(),
        test_mix_columns_128(),
        test_add_round_key_128(),
        test_expand_key_128(),
        test_aes_encrypt_block_128(),
        test_aes_encrypt_block_256(),
    ]

    if all(results):
        print("All tests passed.")
        sys.exit(0)

    print("One or more tests failed.")
    sys.exit(1)