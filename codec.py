# Author: Preethi Ann Jacob
# 14 Nov 2023

# Python GUI Program to Encode and Decode with Vigenere

# ------------Tkinter - main keywords used:-----------------
# pack() - Tkinter literally packs all the widgets one after the other in a window.
# Relief styles - FLAT, RAISED, SUNKEN, GROOVE, RIDGE
# Anchors are used to define where text is positioned relative to a reference point. e.g. N,E,W,S,NE,NW,SE,SW,CENTER. So w means west. 
# bd = border width in pixels
# fg = foreground colour of the tkinter widget
# Text insertion cursors are used to indicate where text can be inserted. They are usually blinking lines that appear at the beginning or end of a text box. 
# insertwidth= Specifies a value indicating the total width of the insertion cursor. 
# StringVar - a class from Tkinter - used to manipulate data from Tkinter widgets. 
# Special note on StringVar: It is getting executed when the class is first defined. You cannot create an instance of StringVar until after the root window i.e. Tkinter() has been created.
# textvariable : In order to be able to retrieve the current text from your entry widget, you must set this option to an instance of the StringVar class.
#-----------------------------------------------------------

# ---------------Time: Preliminaries---------------------
# time.time() returns the number of seconds passed since epoch (the point where time begins)
# time.localtime() is used to convert a time expressed in seconds since the epoch to a time.struct_time object in local time. 
# time.asctime() used to convert a tuple or a time.struct_time object representing a time as returned by time.gmtime() or time.localtime() method to a string of the following form: Day Mon Date Hour:Min:Sec Year. For example: Thu 08 22 10:46:56 2019
#-------------------------------------------------------

# ----------------Encoding and Decoding: Preliminaries--------------------

# Vignere cipher: XOR each char in plaintext with corresponding character in keystream(Duplicate the key to match the plaintext length) to get ciphertext

# Meaning of join()
# string.join(iterable) - where iterable is any iterable object where all the returned values are strings. Iterable is required.
# e.g. "#".join(('John','Peter','Vicky')) returns --- John#Peter#Vicky

# encode() method encodes the string, using the specified encoding. If no encoding is specified, UTF-8 will be used.
# "My name is Ståle".encode() returns ---- b'My name is St\xc3\xe5le' 

# b character before string is used in Python to spedify that the string as a byte string]
# '0b' is used to tell the computer that the number you typed is a base-2 number not a base-10 number. e.g 0b1110010 means binary1110010.

# decode() method --opposite to encode()

# Base 64 Encode and Decode details along with the base64 Encoding chart: https://www.geeksforgeeks.org/encoding-and-decoding-base64-strings-in-python/
# Gist: Get ascii of each character. Convert to 8 bit. Group into 6 bit. Encode it according to the chart. The value will be any of {Capital letters, small letters, 10 digits, +, / }

# Meaning of = in base 64 encoding: 
# Details in: https://medium.com/@partha.pratimnayak/understanding-base64-encoding-7764b4ecce3c#:~:text=The%20%3D%20sign%20is%20used%20to,add%20two%20characters%20of%20padding.
# Gist: 8 chunks = 6 chunks. 8x=6y. Means 4x=3y. Means x should be a multiple of 3. Extra note: One byte = 8 bits
# The = sign is used to indicate padding if the input string length is not a multiple of 3 bytes.
# "ABC".encode("base64) ---'QUJD\n' --- 3 bytes
# "ABCD".encode("base64) ---'QUJDRA==\n' --- 4 bytes + 2 padding bytes make a multiple of 3 bytes
# "ABCDE".encode("base64) ---'QUJDREU=\n' --- 5 bytes + 1 padding bytes make a multiple of 3 bytes
# "ABCDEF".encode("base64) ---'QUJDREVG\n' --- 6 bytes + 0 padding bytes make a multiple of 3 bytes

# Working of Base 64 Encoding: 
# e.g. "ABCD".encode("base64) gives 'QUJDRA==\n'
# 4bytes Add 2 padding bytes to make 6 bytes which is a multiple of 3 bytes. So now ABCD+2padding bytes
# Converting Each character to 8 bit binary: (A=01000001) (B=01000010) (C=01000011) (D=01000100) (Padding = 00000000) (Padding = 00000000)
# So ABCD means 01000001010000100100001101000100,0000000000000000  (Using , to indicate where the original ABCD ends and padding starts)
# Grouping to 6 bit chunks: 010000 010100 001001 000011 010001 00,0000 000000 000000
# (010000=Q) (010100=U) (001001=J) (000011=D) (010001=R) (00,0000=A) (000000=Full of Padding bits) (000000 = Full of padding bytes)
# SO QUJDRA==

# Meaning of urlsafe:
# It means simply "safe to put in a URL" (e.g., doesn't have unencoded / or ? or & characters, etc.).
# Base64 encoded strings may contain the characters a-z A-Z 0-9 + / =.
# Urlsafe_base64 means we are replacing + with - and / with _.
# So in urlsafe_base64, the possible characters are a-z A-Z 0-9 - _
# base64.urlsafe_b64encode(s): Encode bytes-like object s using the URL- and filesystem-safe alphabet, which substitutes - instead of + and _ instead of / in the standard Base64 alphabet, and return the encoded bytes. The result can still contain =.

# Output of encode(key="12",plaintext="ABCD") in the program is "cnR0dg==". How?:
# '1'+'A' = 49+65 =  114 = 114 in mod256 also = 'r' in ascii = 0b1110010
# '2'+'B' = 50+66 =  112 = 112 in mod256 also = 't' in ascii = 0b1110100
# '1'+'C' = 49+67 =  112 = 112 in mod256 also = 't' in ascii = 0b1110100
# '2'+'D' = 50+68 =  118 = 118 in mod256 also = 'v' in ascii = 0b1110110
# So far was Vigenere
# encode('rttv') gives the byte string: b'rttv'
# Using b64encoding scheme: rttv => rttv(Pad)(Pad) => Using ASCII chart, (01110010)(01110100)(01110100)(01110110)(oooooooo)(oooooooo) => [011100][100111][010001][110100][011101][10oooo][oooooo][oooooo] => Using base 64 chart, cnR0dg==
# So urlsafe_b64encode(b'rttv') gives byte string: b'cnR0dg=='
# encode(b'cnR0dg==') gives normal string 'cnR0dg=='.

# Output of decode(key ="12",ciphertext="cnR0dg==") in the program is "ABCD". How?:
# "cnR0dg==" => Using base64 chart, [011100][100111][010001][110100][011101][10oooo][oooooo][oooooo] => Grouping to 8 chunks: (01110010)(01110100)(01110100)(01110110)(oooooooo)(oooooooo) => Using ASCII, rttv(pad)(pad) => rttv
# So urlsafe_b64decode("cnR0dg==") gives the bytestring b'rttv'
# decode(b'rttv') gets the normal string 'rttv'
# 'r' - '1' + 256 = 114 - 49 + 256 = 321 = 65 in mod256 also = 'A' in ascii
# 't' - '2' + 256 = 112 - 50 + 256 = 322 = 66 in mod256 also = 'B' in ascii
# 't' - '1' + 256 = 112 - 49 + 256 = 323 = 67 in mod256 also = 'C' in ascii
# 'v' - '2' + 256 = 118 - 50 + 256 = 324 = 68 in mod256 also = 'D' in ascii
# So ABCD

#----------------------------------------------------------

import tkinter
import random
import time
import datetime
import base64 

# Function to encode
def encode(key, plaintext):
	enc = []
	# print("plaintext=",plaintext)
	# print("key=",key)
	for i in range(len(plaintext)):
		key_c = key[i%len(key)]
		enc_c = chr( ( ord(plaintext[i]) + ord(key_c) ) % 256)
		# print("key_c=",key_c)
		# print("enc_c=",enc_c, plaintext[i], ord(plaintext[i]), key_c, ord(key_c), ( ord(plaintext[i]) + ord(key_c) ), ( ord(plaintext[i]) + ord(key_c) )%256, bin(( ord(plaintext[i]) + ord(key_c) )%256))
		enc.append(enc_c)
	# print("enc=",enc)
	# print("ascii(''.join(enc)) = ",ascii(''.join(enc)))
	# print("''.join(enc).encode() = ",''.join(enc).encode())
	# print("(base64.urlsafe_b64encode(''.join(enc).encode())) = ", (base64.urlsafe_b64encode(''.join(enc).encode())) )
	# print("base64.urlsafe_b64encode(''.join(enc).encode()).decode() = ",base64.urlsafe_b64encode(''.join(enc).encode()).decode())
	return base64.urlsafe_b64encode(''.join(enc).encode()).decode()

# Function to decode
def decode(key, ciphertext):
	dec = []
	# print ("ciphertext = ",ciphertext)
	# print("key = ", key)
	# print ("base64.urlsafe_b64decode(ciphertext) = ",base64.urlsafe_b64decode(ciphertext))
	ciphertext = base64.urlsafe_b64decode(ciphertext).decode()
	# print("base64.urlsafe_b64decode(ciphertext).decode()", ciphertext)
	for i in range(len(ciphertext)):
		key_c = key[i%len(key)]
		dec_c = chr((256 + ord(ciphertext[i]) - ord(key_c)) % 256)
		dec.append(dec_c)
		# print("key_c=",key_c)
		# print("dec_c=",dec_c, ciphertext[i], ord(ciphertext[i]), key_c, ord(key_c), (256 + ord(ciphertext[i]) - ord(key_c)), (256 + ord(ciphertext[i]) - ord(key_c))%256, chr( (256 + ord(ciphertext[i]) - ord(key_c))%256 ) )
	# print(dec)
	# print(''.join(dec))
	return ''.join(dec)

# Runbutton - Encrypt/Decrypt Driver
def Run():
	# print('Message = ',(Msg.get()))
	m = message.get() # either plaintext/ciphertext received from MessageEntry
	k = key.get()
	if (mode.get()=='e'):
		output.set(encode(k,m))
	else:
		output.set(decode(k,m))

# Exit function
def Exit():
	root.destroy()

# Function to reset the window
def Reset():
	# rand.set('')
	message.set('')
	key.set('')
	mode.set('')
	output.set('')

# Creating a GUI window. Set title and size to the window
root = tkinter.Tk() 
root.title('CODEC - Encrypt & Decrypt your message with Vigenere!')
root.geometry('1200x500')

# Creating variables for storing Entries for plaintext/ciphertext, key, mode as e or d, output
message = tkinter.StringVar()
key = tkinter.StringVar()
mode = tkinter.StringVar()
output = tkinter.StringVar()

# Set initial time
localtime = time.asctime(time.localtime(time.time()))

# Function to continuously update time
def Timer():
	localtime = time.asctime(time.localtime(time.time()))
	TimeLabel.config(text = localtime)
	TimeLabel.after(1000, Timer) # Call the Timer after 1 second

# Frames - HeadingFrame, BodyFrame{InputFrame & OutputFrame}
HeadingFrame = tkinter.Frame(root, width = 1200, relief = tkinter.SUNKEN)
BodyFrame = tkinter.Frame(root, width = 800, relief = tkinter.SUNKEN)
InputFrame = tkinter.Frame(BodyFrame, width = 200, relief = tkinter.SUNKEN,bg="#d3cbd6")
OutputFrame = tkinter.Frame(BodyFrame, width = 300, relief = tkinter.SUNKEN,bg="#9ee897")
HeadingFrame.pack(side = tkinter.TOP)
BodyFrame.pack(side = tkinter.LEFT)
InputFrame.pack(side = tkinter.LEFT, padx=20)
OutputFrame.pack(side = tkinter.RIGHT, padx=20)

# In HeadingFrame, set Labels - Heading & Time
HeadingLabel = tkinter.Label(HeadingFrame, font = ('helvetica', 30, 'bold'), text = 'CODEC \n Encrypt & Decrypt with Vigenere!', fg = 'Black', bd = 10, anchor = 'w')
TimeLabel = tkinter.Label(HeadingFrame, font = ('arial', 20, 'bold'), text = localtime, fg = 'Steel Blue', bd = 10, anchor = 'w')
HeadingLabel.grid(row = 0, column = 0)
TimeLabel.grid(row = 1, column = 0) 

# In InputFrame - set Label & Entry for Message, Key and Mode
MessageLabel = tkinter.Label(InputFrame, font = ('arial', 12, 'bold'), text = 'Message', bd = 12, anchor = 'w')
MessageEntry = tkinter.Entry(InputFrame, font = ('arial', 12, 'bold'), textvariable = message, bd = 10, insertwidth = 4, bg = 'powder blue', justify = 'right')
KeyLabel = tkinter.Label(InputFrame, font = ('arial', 12, 'bold'), text = 'Key', bd = 12, anchor = 'w')
KeyEntry = tkinter.Entry(InputFrame, font=('arial', 12, 'bold'), textvariable=key, bd=10, insertwidth=4, bg = 'powder blue', justify = 'right')
ModeLabel = tkinter.Label(InputFrame, font = ('arial', 12, 'bold'), text = 'Mode(e for encrypt, d for decrypt)', bd = 12, anchor = 'w')
ModeEntry = tkinter.Entry(InputFrame, font = ('arial', 12, 'bold'), textvariable = mode, bd = 10, insertwidth = 4, bg = 'powder blue', justify = 'right')

MessageLabel.grid(row=0, column = 0, pady=10)
MessageEntry.grid(row = 0, column = 1, pady=10)
KeyLabel.grid(row=1, column=0, pady=10)
KeyEntry.grid(row=1, column=1, pady=10)
ModeLabel.grid(row=2, column=0, padx=10, pady=10)
ModeEntry.grid(row=2, column=1, padx=10, pady=10)

# In OutputFrame - set Label & Entry for Result
ResultLabel = tkinter.Label(OutputFrame, font = ('arial', 12, 'bold'), text = 'Output - ', bd = 12, anchor = 'w')
ResultEntry = tkinter.Entry(OutputFrame, font = ('arial', 12, 'bold'), textvariable = output, bd = 10, insertwidth = 4, bg = 'powder blue', justify = 'right')
ResultLabel.grid(row=0, column=0, pady = 110, padx= 10)
ResultEntry.grid(row=0, column=1, pady = 110, padx= 30)

# In InputFrame - set Buttons for Run, Reset, Exit
RunButton = tkinter.Button(InputFrame, padx = 12, pady = 8, bd = 8, fg = 'Black', font = ('arial', 12, 'bold'), width = 10, text = 'Encrypt/Decrypt', bg = 'powder blue', command = Run)
ResetButton = tkinter.Button(InputFrame, padx = 12, pady = 8, bd = 8, fg = 'Black', font = ('arial', 12, 'bold'), width = 10, text = 'Reset', bg = 'green', command = Reset)
ExitButton = tkinter.Button(InputFrame, padx = 12, pady = 8, bd = 8, fg = 'Black', font = ('arial', 12, 'bold'), width = 10, text = 'Exit', bg = 'red', command = Exit)
RunButton.grid(row =8, column=0, pady = 12, sticky = 'n', ipadx=8)
ResetButton.grid(row =8, column=1, pady = 12, sticky = 'w')
ExitButton.grid(row =8, column=2, pady = 12, padx= 15)

Timer() # Call timer to continuously move the clock
root.mainloop() # Start the GUI 
