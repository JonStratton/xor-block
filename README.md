# xor-block
This script uses a series of digits to xor byte arrays. Supported formats are: ps1, csharp, c and vbapplication.

	cat pre.csharp | python3 ./xor_block.py -i - -f csharp -k "2,4,6,8,10,12"

Will I post decoding logic for each of these languages? No; this is for use to help shellcode bypass AV, and writing your own custom decode logic will make it harder for AV to fingerprint. You can refer to “xOrBlock()” for one way. For reference, xor is “^” in C and Csharp, “Xor” for VB, and “-bxor” for Powershell.
