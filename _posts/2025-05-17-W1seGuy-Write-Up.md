---
layout: post
title: W1seGuy Write up
date: 2025-05-19 13:23:49 +0100
categories: TryHackMe Rooms
---


W1seGuy is a room which explores XOR cryptography. Using a TCP server to serve an encrypted hexadecimal string, we must utilise both the source code and some light programming knowledge to obtain both the key and plaintext data.


# What is XOR cryptography?

Before we crack the room, it's best we understand what XOR encryption is and how it works. 

In short, XOR cryptography uses the bitwise XOR logical operation to encrypt data. It is not really used in todays cryptography standards, but it serves as a low-level demonstration of how cryptography works.

Weaknesses of this encryption method is that the same key is used for both the encryption and decryption. It also loops through the key if the plaintext is longer, making it easy to find repetitions as we will see later. 

If the key length is the same as the plaintext however, and truly random, XOR cipher is mathematically impossible to break. Despite this, it's very rarely used as transferring a key the same length to another person has it's own practically issues.

**Example**

Let's say we want to encrypt the message 'Test' , we first must select an encryption key to use. In this example, we will use the key 'Pass' . The plaintext will be 'XORed' (⊕) with the key, converting the word 'Test' into ciphertext

We need to represent each character of both the plaintext and the key as ASCII which will look like this:

| Plaintext | ASCII | Binary     || Key  | ASCII | Binary     |
|-----------|-------|------------||------|--------|------------|
| T         | 84    | 01010100   || P    | 80     | 01010000   |
| e         | 101   | 01100101   || a    | 97     | 01100001   |
| s         | 115   | 01110011   || s    | 115    | 01110011   |
| t         | 116   | 01110100   || s    | 115    | 01110011   |


Now, we need to XOR each byte and convert them into Binary. So we would T ⊕ P , e ⊕ a , s ⊕ s , and t ⊕ s . 

In this example, the key is the same length as the password, so only one iteration of the key needs to be used. 

As we will later see, the text in the CTF room is longer than the key itself. The key will be used again for each byte of the plaintext if this is the case.

We could do this one by one, although for longer text as seen in the room and keys, this would take way too long. 

Python has a built in function to XOR characters so we can write a script to do this for us, as well as convert the output to hexadecimal 


{% highlight ruby %}

plaintext = "Test" # Plaintext to encrypt
key = "Pass"  # Key we will be using to encrypt

key = key[:len(plaintext)] # Ensuring the key is the same as the plaintext, this will be different in the actual code

for i in range(len(plaintext)): 
    p = ord(plaintext[i])  # Using the ord() function to convert plaintext into it's Unicode code point
    k = ord(key[i])
    xor_result = p ^ k  # Using the ^ function to XOR the outputs of p and k 
    print(f"{plaintext[i]} ^ {key[i]} = {xor_result} -> \\x{xor_result:02x}") # Return the XORed result in hexidecimal format using \x

{% endhighlight %}

This will then output the following:

{%highlight ruby %}
T ^ P = 4 -> \x04
e ^ a = 4 -> \x04
s ^ s = 0 -> \x00
t ^ s = 7 -> \x07

{% endhighlight %}

Returning a hexidecimal value of \x04\x04\x00\x07 (04-04-00-07)

**So how do we decrypt this?**

The nice thing about XOR operations is that they are reversable, for example

A ⊕ B = C 

and

C ⊕ B = A

To decrypt 04-04-00-07 using the key 'Pass' , we just have to reverse the operation, using the ASCII values in the table above:

4 ⊕ 112 = 84 'T'

4 ⊕ 97 = 101 'e'

0 ⊕ 115 = 115 's'

7 ⊕ 115 =   116 't'

End result = 'Test'


# Accessing the room / recon

Now we have a rough idea of how XOR encryption works - we can now begin to crack the room.

We are provided with an open TCP port of 1337 and the source code. Lets netcat into the room and see what it gives us:

![screenshot](/images/wiseguy/netcat.png)

Connecting to this returns the Hexadecimal string '6027291e07050e080b037117102403405b070e14750116561658231d0d22461b1d550246172b170a'

Let's also take a look at the source code found in Task 1:

{%highlight ruby%}
import random  
import socketserver   
import socket, os  
import string  
  
flag = open('flag.txt','r').read().strip()  
  
def send_message(server, message):  
    enc = message.encode()  
    server.send(enc)  
  
def setup(server, key):  
    flag = 'THM{thisisafakeflag}'   
xored = ""  
  
    for i in range(0,len(flag)):  
        xored += chr(ord(flag[i]) ^ ord(key[i%len(key)]))  
  
    hex_encoded = xored.encode().hex()  
    return hex_encoded  
  
def start(server):  
    res = ''.join(random.choices(string.ascii_letters + string.digits, k=5))  
    key = str(res)  
    hex_encoded = setup(server, key)  
    send_message(server, "This XOR encoded text has flag 1: " + hex_encoded + "\n")  
      
    send_message(server,"What is the encryption key? ")  
    key_answer = server.recv(4096).decode().strip()  
  
    try:  
        if key_answer == key:  
            send_message(server, "Congrats! That is the correct key! Here is flag 2: " + flag + "\n")  
            server.close()  
        else:  
            send_message(server, 'Close but no cigar' + "\n")  
            server.close()  
    except:  
        send_message(server, "Something went wrong. Please try again. :)\n")  
        server.close()  
  
class RequestHandler(socketserver.BaseRequestHandler):  
    def handle(self):  
        start(self.request)  
  
if __name__ == '__main__':  
    socketserver.ThreadingTCPServer.allow_reuse_address = True  
    server = socketserver.ThreadingTCPServer(('0.0.0.0', 1337), RequestHandler)  
    server.serve_forever()

{% endhighlight %}


The first thing to note is that the key length is stated here, being 5 (k=5). 

We also know, this being a CTF on TryHackMe, that the flag must contain THM{ and end with } . This would be exponentially more difficult if we did not have a general idea of what the plaintext contains.

Because of this, we can narrow down the keys in our brute force to those that only return values that contain this text. This will help later as brute forcing all possible keys would take a long time.

We can also see that the XOR cipher loops through each character of the flag:

{% highlight ruby %}

(ord(key[i % len(key)])) # Takes the ASCII value of each key character , cycling through it

{% endhighlight %}


This is really all we need to know from the source code in order to start building our decoder.

# Building the decoder and getting the flags



First , lets import string and define a few variables. We need to import the string module so we can use string.printable later on to try all possible printable characters:

{% highlight ruby %}

import string

encrypted = ("6027291e07050e080b037117102403405b070e14750116561658231d0d22461b1d550246172b170a") # The encrypted hexidecmal given to us when we nc'd into the room

ciphertext = bytes.fromhex(encrypted) # Converts the encrypted hexadecimal text into bytes for XOR decryption

header = b"THM{" # Defining the start of the plaintext, using the b function to convert to bytes
footer = b"}" # Defining the end of the plaintext, using the b function again to convert to bytes

{% endhighlight %}

Now, we should create a key byte array to hold the bytes of the XOR key. We know this is 5, and for now, we will define each element as 'None' 

After that, we'll XOR the corresponding cypher text with the header and footerbytes

{% highlight ruby %}

key_bytes = [None] * 5  # Creates an array with 5  'None' values
for i in range(len(header)):  
    key_bytes[i] = ciphertext[i] ^ header[i] # XORs the Ciphertext with the header bytes

footer_pos = (len(ciphertext) - 1) % 5  
expected_footer_xor = ciphertext[-1] ^ footer[0] # XOR the last byte of ciphertext with footer byte to find the expected key byte for that position.

{% endhighlight %}

Next, we'll use the string.printable function to generate a list of all printable ASCII characters that we can use to brute force. We'll save this to a variable, in this case I'll call it list, and we'll assign this to the array we made earlier. 

{% highlight ruby %}

list = string.printable.strip()  # Creates a variable called list containing all printable ASCII values
for ch in list:  
    key_bytes[4] = ord(ch) # Assigns the ASCII value to the last byte in the array

{% endhighlight %}

So now we have a list of printable ASCII values (list) , and a last byte to compare it to being expected_footer_xor. Remember, we're only looking for keys that end in '}' due to the nature of flags on TryHackMe's CTFs, so we just need to write a function to check if the list matches the expected_footerxor:

{% highlight ruby %}

if key_bytes[4] != expected_footer_xor:  
    continue  # Skip this list if it doesn't match, though in this case it won't be needed

{% endhighlight%}

Lets now create a full key variable that constructs the decryption key, we'll need to repeat the key for the length of the ciphertext:

{% highlight ruby %}

full_key = bytes(key_bytes[i % 5] for i in range(len(ciphertext))) # Constructs a full key which is repeated throughout the length of the ciphertext

{% endhighlight %}

Finally, we now just need to decrypt the cyphertext using the key we've just generated, and check to see if the text contains the footer, in this case '}' . We will define the key as plaintext in this example:

{% highlight ruby %}

plaintext = bytes(c ^ k for c, k in zip(ciphertext, full_key)) # Defines and XORs c and k using the zip function to pair both the ciphertext and full_key values

if plaintext.endswith(footer):
    print("Found Key:", bytes(key_bytes).decode()) # Returns what key was used to decrypt
    print("Plaintext:", plaintext.decode()) # Returns the plaintext that was decrypted by the key
    break # Ends the loop

{% endhighlight %}

After running this code with the encrypted hexidecimal given to us in the beginning, it should return both the key used and plaintext values:

{%  highlight ruby %}

Found Key: 4odew
Plaintext: THM{p1alntExtAtt4ckcAnr3alLyhUrty0urxOr}

{% endhighlight%}

So, there's the first flag. And to get the second one all we need to do is input the key back into the prompt that we nc'd into in the beginning. *My key is different to the one in the example as I had to start the box again*

![screenshot2](/images/wiseguy/decryption.png)

And we get the final flag - THM{BrUt3_ForC1nG_XOR_cAn_B3_FuN_nO?} !!


Thanks for reading. Took me 10x as long to create this site but I'm just using it to post future CTF write ups. I will provide the full version of the code if all you want to do is copy paste the whole thing.

# Full Decryption code

{% highlight ruby%}
import string  
  
encrypted = input("Enter the Encrypted String: ")  
ciphertext = bytes.fromhex(encrypted)  
  
header = b"THM{"  
footer = b"}"  
  
key_bytes = [None] * 5  
for i in range(len(header)):  
    key_bytes[i] = ciphertext[i] ^ header[i]  
  
footer_pos = (len(ciphertext) - 1) % 5  
expected_footer_xor = ciphertext[-1] ^ footer[0]  
  
  
list = string.printable.strip()  
for ch in list:  
    key_bytes[4] = ord(ch)  
    
    if key_bytes[4] != expected_footer_xor:  
        continue 
  
    full_key = bytes(key_bytes[i % 5] for i in range(len(ciphertext)))  
    plaintext = bytes(c ^ k for c, k in zip(ciphertext, full_key))  
  
   
    if plaintext.endswith(footer):  
        print("Found Key:", bytes(key_bytes).decode())  
        print("Plaintext:", plaintext.decode())  
        break  
else:  
    print("No valid key found.")


{% endhighlight %}







