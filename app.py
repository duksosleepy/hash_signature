#pip install Pillow
#pip install pycryptodome
#pip install textract
#pip install pdfminer
import tkinter.font as font
import tkinter as tk
import gmpy2
from tkinter import ttk
from tkinter.simpledialog import askstring
from tkinter import filedialog 
from PIL import Image, ImageTk
import docx2txt
import pandas
import textract    
import os
import binascii
import docx2txt
import io
import hashlib
import random
import time
import pandas as pd
from pdfminer.converter import TextConverter
from pdfminer.pdfinterp import PDFPageInterpreter
from pdfminer.pdfinterp import PDFResourceManager
from pdfminer.pdfpage import PDFPage
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import poly1305
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
def startsimu():
    pathserver = os.path.abspath(os.getcwd()).replace("\\","\\") + "\\dist1\\server.exe"
    os.system(f'start /B start cmd.exe @cmd /k ""{pathserver}""')
    time.sleep(3)
    pathclient = os.path.abspath(os.getcwd()).replace("\\","\\") + "\\dist2\\client.exe"
    os.system(f'start /B start cmd.exe @cmd /k ""{pathclient}""')
def descrip(container):
    description = ttk.Frame(container)
    text=tk.Text(description, width = 100, height = 20, 
              wrap = tk.WORD,
              font=("Times New Roman",8),
        )
    text.tag_configure("tag_name", justify='center')
    text.focus()
    text.pack()
    text.insert(1.0, '''\n\n\n\nThis application create MAC and Signature.\nPlease use it to study, dont use for reality!!!\nThanks for using application\nNguyen Tinh Song Khoi aka DUK
                        ''')
    text.tag_add("tag_name", "1.0", "end")
    text['state'] = 'disabled'
    return description
def simulation():
    frame = ttk.Frame(root)
    text=tk.Text(frame, width = 100, height = 20, 
              wrap = tk.WORD,
              font=("Times New Roman", 8),
)
    text.tag_configure("tag_name", justify='center')
    text.focus()
    text.grid(column=0, row=0, sticky=tk.W)
    text.insert('1.0', '''This function use the 4 file create before in folder: \nalice certificate, bob certificate,\nalice public key, bob public key.\n\nUsing RSA scheme signature and PKI.
                        ''')
    text.tag_add("tag_name", "1.0", "end")
    text['state'] = 'disabled'
    button = ttk.Button(
                    frame,
                    text='Start',
                    command=startsimu,
    )
    button.grid(column=0, row=1, sticky=tk.EW)
    return frame
def Extended_Eulid(a, m):
    if a == 0: 
        return 1, 0, m
    else:
        x, y, gcd = Extended_Eulid(m % a, a) 
        x, y = y, (x - (m // a) * y) 
        return x, y, gcd
def Sign(x, p, alpha, d):
    temp_key = random.randint(0, p - 2)
    while gcd(temp_key, p - 1) != 1:
        temp_key = random.randint(0, p - 2)
        r = gmpy2.powmod(alpha, temp_key, p)
        s = (x - d * r) * Extended_Eulid(temp_key, p - 1) % (p - 1)
    return r, s
def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')
def int_to_bytes(i):
    i = int(i)
    return i.to_bytes((i.bit_length()+7)//8, byteorder='big')
def Generate_private_key(p):
    pri = random.randint(2, p - 2)
    while gcd(pri, p) != 1:
        pri = random.randint(2, p - 2)
    return pri
def power(a, b, c):
    ans = 1
    while b != 0:
        if b & 1:
            ans = (ans * a) % c
            b >>= 1
            a = (a * a) % c
    return ans
def Generate_alpha(p):
    return random.randint(2, p)
def quick_power(a, b):
    ans = 1
    while b != 0:
        if b & 1:
            ans = ans * a
            b >>= 1
            a = a * a
    return ans
def Generate_prime(key_size):
    while True:
        num = random.randrange(quick_power(2, key_size - 1), quick_power(2, key_size))
        if Miller_Rabin(num):
            return num
def Miller_Rabin(n):
    a = random.randint(2,n-2) 
    s = 0
    d = n - 1
    while (d & 1) == 0:
        s += 1
        d >>= 1
        x = gmpy2.powmod(a, d, n)
        for i in range(s): 
            newX = gmpy2.powmod(x, 2, n)
            if newX == 1 and x != 1 and x != n - 1:
                return False 
            x = newX
            if x != 1: 
                return False
    return True
def create_new_file():
    global public
    if signcomboExample.get() == "Elliptic Curve":
        private_key = ec.generate_private_key(ec.SECP384R1())
        serialized_private = private_key.private_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                    encryption_algorithm=serialization.NoEncryption()
        )
        public_key = private_key.public_key()
        public = public_key.public_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
    if signcomboExample.get() == "RSA":
        private_key = rsa.generate_private_key(
                                    public_exponent =65537,
                                    key_size =4096,
                        )
        public_key = private_key.public_key()
        public = public_key.public_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
        serialized_private = private_key.private_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                    encryption_algorithm=serialization.NoEncryption()
                        )
    if signcomboExample.get() == "DSA":
        private_key = dsa.generate_private_key(
                                    key_size=4096,
                                    )
        serialized_private = private_key.private_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                    encryption_algorithm=serialization.NoEncryption()
                        )
        public_key = private_key.public_key()
        public = public_key.public_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
    if signcomboExample.get() == "Elgamal":
        public = {}
        p = Generate_prime(512)
        alpha = Generate_alpha(p)
        a = Generate_private_key(p)
        beta = gmpy2.powmod(alpha, a, p)
        serialized_private = int_to_bytes(a)
        public["p"] = p
        public["alpha"] = alpha
        public["beta"] = beta
        public = json.dumps(public).encode('utf-8')
    if signcomboExample.get() == "Schnorr":
        public = {}
        p = Generate_prime(512)
        q = Generate_private_key(p)
        r  = Generate_alpha(p)
        h = random.choice([h for h in range(1, p) if gmpy2.powmod(h, r, p) != 1 ])
        g = gmpy2.powmod(h, r, p)
        k = Generate_private_key(q)
        y = gmpy2.powmod(g, k, q)
        serialized_private = int_to_bytes(k)
        public["g"] = g
        public["y"] = y
        public["q"] = q
        public = json.dumps(public).encode('utf-8')
    pri = askstring("Input", "Input private file name")
    if pri:
        pul = askstring("Input", "Input public file name")
    if os.path.exists(pri) or os.path.exists(pul):
        print("File already exists.")
    else:
        with open(pri, "wb+") as private_key_file_obj:
            with open(pul, "wb+") as public_key_file_obj:
                private_key_file_obj.write(serialized_private)
                public_key_file_obj.write(public)
                public_key_file_obj.close()
                private_key_file_obj.close()
def Create_Signature():
    if signal.get() == "Elliptic Curve":
        chosen_hash = hashes.SHA256()
        hasher = hashes.Hash(chosen_hash)
        hasher.update(binarydata)
        digest = hasher.finalize()
        sig = private_key.sign(
                        digest,
                        ec.ECDSA(utils.Prehashed(chosen_hash))
        )
    if signal.get() == "RSA":
        chosen_hash = hashes.SHA256()
        hasher = hashes.Hash(chosen_hash)
        hasher.update(binarydata)
        digest = hasher.finalize()
        sig = private_key.sign(
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(chosen_hash)
        )
    if signal.get() == "DSA":
        chosen_hash = hashes.SHA256()
        hasher = hashes.Hash(chosen_hash)
        hasher.update(binarydata)
        digest = hasher.finalize()
        sig = private_key.sign(
            digest,
            utils.Prehashed(chosen_hash)
        )
    if signal.get() == "Elgamal":
        p = public["p"] 
        alpha = public["alpha"] 
        x = bytes_to_int(binarydata)
        r, s = Sign(x, p, alpha, private_key)
        sig = {}
        sig["r"] = (binascii.hexlify(int_to_bytes(r))).decode()
        sig["s"] = (binascii.hexlify(int_to_bytes(s))).decode()
        sig = json.dumps(sig)
    if signal.get() == "Schnorr":
        g = public["g"]
        q = public["q"]
        t = Generate_alpha(q)
        r = gmpy2.powmod(g, t, q)
        e = int(hashlib.sha1(str(r) + str(m)).hexdigest(), 16) % q
        s = (t - private_key*e)
        sig["e"] = (binascii.hexlify(int_to_bytes(e))).decode()
        sig["s"] = (binascii.hexlify(int_to_bytes(s))).decode()
        sig = json.dumps(sig)
    if isinstance(sig,str):
        resultSign.delete("1.0","end")
        resultSign.insert(tk.END, sig)
    else:
        sig = binascii.hexlify(sig)
        resultSign.delete("1.0","end")
        resultSign.insert(tk.END, sig)
def Create_key():
    global signcomboExample
    newWindow = tk.Toplevel(root)
    signcomboExample = ttk.Combobox(newWindow, 
                            values=[
                                    "Elliptic Curve", 
                                    "RSA",
                                    "DSA",
                                    "Elgamal",
                                    "Schnorr",
                                    ],)
    signcomboExample.grid(column=0, row=0, sticky=tk.W)
    signbutton = ttk.Button(
                    newWindow,
                    text='Choose place to create: ',
                    command=create_new_file
    )
    signbutton.grid(column=1, row=0, sticky='w')
    return newWindow
def Input_file():
    global private_key,public
    path = filedialog.askopenfilename(initialdir="/", title="Select file",
                    filetypes=(("all files", "*.*"),))
    with open(path, "rb") as private_key_file_object:
        private_key = serialization.load_pem_private_key(
                        private_key_file_object.read(),
                        password = None)
        if isinstance(private_key, rsa.RSAPrivateKey):
            public_key = private_key.public_key()
            private_key_raw = private_key.private_numbers().d
        elif isinstance(private_key, dsa.DSAPrivateKey):
            public_key = private_key.public_key()
            private_key_raw = private_key.private_numbers().x
        elif isinstance(private_key,ec.EllipticCurvePrivateKey):
            public_key = private_key.public_key()
            private_key_raw = private_key.private_numbers().private_value
        else:
            path2 = filedialog.askopenfilename(initialdir="/", title="Select public file",
                    filetypes=(("all files", "*.*"),))
            with open(path2, "rb") as public_key_file_object:
                public = public_key_file_object.read()
                public = json.loads(public.decode('utf-8'))
                private_key = private_key_file_object.read()
                private_key_raw = bytes_to_int(private_key)
                f.close()
        keysi.delete("1.0","end")
        keysi.insert(tk.END, private_key_raw)
def Create_MAC():
    sharedinfo = b"Demoexample"
    xkdf = X963KDF(
        algorithm=hashes.SHA256(),
        length=16,
        sharedinfo=sharedinfo,
    )
    iv = X963KDF(
        algorithm=hashes.SHA256(),
        length=16,
        sharedinfo=b"randomsalt",
    )
    xkdf2 = X963KDF(
        algorithm=hashes.SHA256(),
        length=32,
        sharedinfo=sharedinfo,
    )
    keys = xkdf.derive(bytes(key.get("1.0","end"),'utf-8'))
    keysh = xkdf2.derive(bytes(key.get("1.0","end"),'utf-8'))
    ivs = iv.derive(bytes(key.get("1.0","end"),'utf-8'))
    if comboExample.get() == "CCM":
        cipher = AES.new(keys, AES.MODE_CCM)
        ciphertext, tag = cipher.encrypt_and_digest(binarydata)
        nonce = cipher.nonce
    if comboExample.get() == "CMAC":
        c = cmac.CMAC(algorithms.AES(keys))
        c.update(binarydata)
        tag = c.finalize()
    if comboExample.get() == "HMAC":
        h = hmac.HMAC(keysh, hashes.SHA256())
        h.update(binarydata)
        tag = h.finalize()
    if comboExample.get() == "Poly1305":
        p = poly1305.Poly1305(keysh)
        p.update(binarydata)
        tag = p.finalize()
    if comboExample.get() == "EAX":
        cipher = AES.new(keys, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(binarydata)
        nonce = cipher.nonce
    if comboExample.get() == "GCM":
        cipher = AES.new(keys, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(binarydata)
        nonce = cipher.nonce
    if comboExample.get() == "SIV":
        nonce = get_random_bytes(16)
        cipher = AES.new(keysh, AES.MODE_SIV, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(binarydata)
    tag = binascii.hexlify(tag)
    tag = tag.decode()
    resultMAC.delete("1.0","end")
    resultMAC.insert(tk.END, tag)
def rgb_to_hex(*args):
    return '{:X}{:X}{:X}'.format(args[0][0],args[0][1], args[0][2])
def open_text_file():
    textMAC.delete("1.0","end")
    textSign.delete("1.0","end")
    global binarydata
    path = filedialog.askopenfilename(initialdir="/", title="Select file",
                    filetypes=(("all files", "*.*"),))
    tail = path.split("/")[-1]
    for a in [".ppm", ".png", ".jpeg", ".gif", ".tiff", ".bmp",".jpg"]:
	    if a in tail.lower():
                load = Image.open(path)
                load.resize((100, 100))
                render = ImageTk.PhotoImage(load)
                textMAC.image_create("end", image = render)
                textSign.image_create("end", image = render)
                pixels = list(load.getdata())
                b = "".join(rgb_to_hex(element) for element in pixels)
                binarydata = bytes(b,'utf-8')
    if ".txt" in tail.lower():
        with open(path, 'r') as tf:
            datacontent = tf.read()
            binarydata = bytes(datacontent.replace(" ",""),'utf-8')
            tf.close()
    for a in [".doc", ".docx"]:
        if a in tail.lower():
            datacontent = docx2txt.process(path)
            binarydata = bytes(datacontent.replace(" ",""),'utf-8')
    for a in [".xlsx", ".xls"]:
        if a in tail.lower():
            xlsdata = pd.read_excel(path)
            datacontent = xlsdata.to_csv(index=False)
            binarydata = bytes(datacontent.replace(" ",""),'utf-8')
    if ".pdf" in tail.lower():
        resource_manager = PDFResourceManager()
        fake_file_handle = io.StringIO()
        converter = TextConverter(resource_manager, fake_file_handle)
        page_interpreter = PDFPageInterpreter(resource_manager, converter)
        with open(path, 'rb') as fh:
            for page in PDFPage.get_pages(fh, 
                                      caching=True,
                                      check_extractable=True):
                page_interpreter.process_page(page)
            
            datacontent = fake_file_handle.getvalue()
        binarydata = bytes(datacontent.replace(" ",""),'utf-8')
    textMAC.insert(tk.END, datacontent)
    textSign.insert(tk.END, datacontent)
def create_MAC_frame(container):
    global text,comboExample,key,result,textMAC,resultMAC
    MACframe = ttk.Frame(container)
    # Find what
    frame = ttk.Frame(MACframe)
    frame.grid(column=0, row=0, sticky=tk.EW)
    ttk.Label(frame, text='Input content here: ',).pack(side = tk.LEFT)
    scrollV = tk.Scrollbar(MACframe, orient = tk.VERTICAL)
    textMAC=tk.Text(MACframe, width = 100, height = 20, 
              wrap = tk.WORD,
              font=("Times New Roman", 8),yscrollcommand = scrollV.set)
    textMAC.focus()
    textMAC.grid(column=0, row=1, sticky=tk.W,rowspan=2)
    scrollV.config(command = textMAC.yview)
    textMAC.configure(yscrollcommand = scrollV.set)
    scrollV.grid(column=1, row=1, sticky=tk.NS,rowspan=2)
    ttk.Button(
                    frame,
                    text='Open a File',
                    command=open_text_file,
    ).pack(side = tk.RIGHT)
    ttk.Label(MACframe, text='Input key(password) here: ',).grid(column=0, row=3, sticky=tk.W)
    key=tk.Text(MACframe, width = 100, height = 1, 
              wrap = tk.WORD,
              font=("Times New Roman", 8))
    key.focus()
    key.grid(column=0, row=4, sticky=tk.W)
    frame2 = ttk.Frame(MACframe)
    frame2.grid(column=0, row=5,sticky=tk.EW)
    labelTop = tk.Label(frame2,text = "Choose MAC algorithm",)
    labelTop.pack(side = tk.LEFT)
    ttk.Button(
                    frame2,
                    text='Create',
                    command=Create_MAC,
    ).pack(side = tk.RIGHT)
    comboExample = ttk.Combobox(frame2, 
                            values=[
                                    "CCM", 
                                    "CMAC",
                                    "HMAC",
                                    "Poly1305",
                                    "EAX",
                                    "GCM",
                                    "SIV"],)
    comboExample.pack(side = tk.RIGHT)
    resultMAC=tk.Text(MACframe, width = 100, height = 1, 
              wrap = tk.WORD,
              font=("Times New Roman", 8))
    resultMAC.grid(column=0, row=6, sticky=tk.W)
    return MACframe
def create_Signature_frame(container):
    global keysi,signal,Signframe,result,textSign,resultSign
    Signframe = ttk.Frame(container)
    # Find what
    frame = ttk.Frame(Signframe)
    frame.grid(column = 0,row = 0,sticky=tk.EW)
    ttk.Label(frame, text='Input content here: ',).pack(side = tk.LEFT)
    scrollV = tk.Scrollbar(Signframe, orient = tk.VERTICAL)
    textSign=tk.Text(Signframe, width = 100, height = 20, 
              wrap = tk.WORD,
              font=("Times New Roman", 8))
    textSign.focus()
    textSign.grid(column=0, row=1, sticky=tk.W,rowspan=2)
    scrollV.config(command = textSign.yview)
    textSign.configure(yscrollcommand = scrollV.set)
    scrollV.grid(column=1, row=1, sticky=tk.NS,rowspan=2)
    ttk.Button(
                    frame,
                    text='Open a File',
                    command=open_text_file,
    ).pack(side = tk.RIGHT)
    ttk.Label(Signframe, text='Input private key here: ',).grid(column=0, row=3, sticky=tk.W)
    keysi=tk.Text(Signframe, width = 100, height = 1, 
              wrap = tk.WORD,
              font=("Times New Roman", 8))
    keysi.focus()
    keysi.grid(column=0, row=4, sticky=tk.W)
    frame2 = ttk.Frame(Signframe)
    frame2.grid(column=0, row=5,sticky=tk.EW)
    labelTop = tk.Label(frame2,text = "Choose Signature algorithm",)
    labelTop.pack(side = tk.LEFT)
    ttk.Button(
                    frame2,
                    text='Or input key file(PEM) here',
                    command=Input_file,
    ).pack(side = tk.RIGHT)
    ttk.Button(
                    frame2,
                    text='Create',
                    command=Create_Signature,
    ).pack(side = tk.RIGHT)
    signal = ttk.Combobox(frame2, 
                            values=[
                                    "Elliptic Curve", 
                                    "RSA",
                                    "DSA",
                                    "Elgamal",
                                    "Schnorr",
                                    ],)
    signal.pack(side = tk.RIGHT)
    ttk.Button(
                    Signframe,
                    text='If you have not key yet, create here',
                    width = 10,
                    command=Create_key,
    ).grid(column=0, row=6, sticky=tk.EW, padx=10, pady=10)
    resultSign=tk.Text(Signframe, width = 100, height = 1, 
              wrap = tk.WORD,
              font=("Times New Roman", 8))
    resultSign.grid(column=0, row=7, sticky=tk.W)
    return Signframe
def perform_simulation():
    descriptionapp.grid_forget()
    Signframe.grid_forget()
    MAC.grid_forget()
    SIMU.grid(column=1, row=0,rowspan=2)
def perform_MAC():
    SIMU.grid_forget()
    descriptionapp.grid_forget()
    Signframe.grid_forget()
    MAC.grid(column=1, row=0,rowspan=2)
def perform_sign():
    SIMU.grid_forget()
    descriptionapp.grid_forget()
    MAC.grid_forget()
    Sign.grid(column=1, row=0,rowspan=2)
def create_button_frame(container):
    frame = ttk.Frame(container)
    a = ttk.Button(frame, text='Create MAC',width=25, command=perform_MAC).grid(column=0, row=0, sticky=tk.N,pady = 10)
    b = ttk.Button(frame, text='Create digital signature',width=25, command=perform_sign).grid(column=0, row=1, sticky=tk.EW,pady = 10)
    c = ttk.Button(frame, text='Simulation',width=25, command=perform_simulation).grid(column=0, row=2, sticky=tk.S,pady = 10)
    return frame
def create_main_window():
    global descriptionapp,root,MAC,Sign,SIMU
    root = tk.Tk()
    root.title('Message')
    root.geometry('800x450')
    root.resizable(True, True)
    root.columnconfigure(0, weight=1)
    root.columnconfigure(1, weight=4)
    frame = create_button_frame(root)
    frame.grid(column=0, row=0)
    descriptionapp = descrip(root)
    descriptionapp.grid(column=1, row=0,rowspan=2)
    MAC = create_MAC_frame(root)
    Sign = create_Signature_frame(root)
    SIMU = simulation()
    root.mainloop()
if __name__ == "__main__":
    create_main_window()
