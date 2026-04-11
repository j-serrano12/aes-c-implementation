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
    else:
        print("Test failed: C and Python implementations produce different results.")

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
    else:
        print("Test failed: C and Python implementations produce different results.")


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
    else:
        print("Test failed: C and Python implementations produce different results.")


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
    else:
        print("Test failed: add_round_key did not produce the expected XOR result.")

    # Execute the test
if __name__ == "__main__":
    test_sub_bytes_128()
    test_shift_rows_128()
    test_mix_columns_128()
    test_add_round_key_128()