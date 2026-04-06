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
    python_output = [aes.s_box[b] for b in original_bytes]

    # Compare the results
    if c_output == python_output:
        print("Test passed: C and Python implementations produce the same result.")
    else:
        print("Test failed: C and Python implementations produce different results.")

    # Execute the test
if __name__ == "__main__":
    test_sub_bytes_128()