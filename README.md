# CSE4057_InformationSystemSecurity_Project1



In this homework, you are expected to implement the following (in any programming
language):
1) Generation of public-private key pairs.
a. Generate an RSA public-private key pair. KA
+ and KA
−. The length of the keys should be at
least 1024 bits (the number of bits in the modulus). Provide a screenshot to show the
generated keys.
b. Generate two Elliptic-Curve Diffie Helman public-private key pairs. (KB
+, KB
−) and (KC
+,

KC
−).
2) Generation of Symmetric keys
a. Generate two symmetric keys using a secure key derivation function: 128 bit K1 and 256 bit
K2. Print values of the keys on the screen. Encypt them with KA

+, print the results, and then

decrypt them with KA

−. Again print the results. Provide a screenshot showing your results.

b. Generate a 256 bit symmetric key using Elliptic key Diffie Helman using KC
+ and KB
−. This

is K3. Generate a symmetric key using KB
+ and KC
− and show that the generated key is the

same. Print value of the generated keys and provide a screenshot.
3) Generation and Verification of Digital Signature
Choose any image file. Apply SHA256 Hash algorithm to the contents of the image file
(Obtain the message digest, H(m)). Then encrypt it with KA

−. (Thus generate a digital

signature.) Then verify the digital signature. (Decrypt it with KA

+ , apply Hash algorithm to the
image, compare). Print H(m) and digital signature on the screen. Provide a screenshot. (Or
you may print in a file and provide the file).
4) AES Encryption
Find an image file with a size of at least 5MB. Now consider the following three algorithms:
i) AES (128 bit key) in CBC mode.
ii) AES (256 bit key) in CBC mode.
iii) AES (256 bit key) in CTR mode.
For each of the above algorithms, do the following:
a) Encrypt the file. Store the results (and submit it with the homework) (Note: Initialization
Vector (IV) in CBC mode and nonce in CTR mode should be generated randomly, For 128 bit
use K1 as the symmetric key. For 256 bit you may use either K2 or K3).
b) Decrypt the ciphertexts and store the results. Show that they are the same as the original
files.
c) Measure the time elapsed for encryption. Write it in your report. Comment on the result.
d) For the first algorithm, change Initialization Vector (IV) and show that the corresponding
ciphertext changes for the same plaintext (Give the result for both).

5) Message Authentication Codes
a) Choose a text message and generate a message authentication code (HMAC-SHA256)
using any of the symmetric keys.
b) Apply HMAC-SHA256 to K2 in order to generate a new 256 bit key.
You may do this homework in groups of two or three.
What to submit: Submit all your commented codes, output files and a report including your
results, screenshots and comments via google classroom. In your codes, please clearly
describe which code parts do which job. If you do not complete all the items asked above,
please clearly indicate which items are completed.
