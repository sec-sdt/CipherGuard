import customtkinter
from Crypto.Cipher import Blowfish
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from PIL import Image, ImageTk
import os
import re
import random
import string

# importing the two algorithms
import Finalised_Modified_Vernam as vm
import Blowfish_Final as bf

# creating a class for the tabs 
class MyTabView(customtkinter.CTkTabview):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        
        # Load the background images
        self.bg_image1 = Image.open(r"D:\Coded\CipherGuard\img_2.jpg")
        self.bg_photo1 = ImageTk.PhotoImage(self.bg_image1)
        self.bg_image2 = Image.open(r"D:\Coded\CipherGuard\img_2.jpg")
        self.bg_photo2 = ImageTk.PhotoImage(self.bg_image2)

        # create tabs
        self.tab1=self.add("ENCRYPTION")
        self.tab2=self.add("DECRYPTION")

        # Create a canvas for each tab and set the background image
        self.tab1_canvas = customtkinter.CTkCanvas(self.tab1)
        self.tab1_canvas.create_image(0, 0, image=self.bg_photo1, anchor="nw")
        self.tab1_canvas.place(relwidth=1, relheight=1)  # Make the canvas fill the tab

        self.tab2_canvas = customtkinter.CTkCanvas(self.tab2)
        self.tab2_canvas.create_image(0, 0, image=self.bg_photo2, anchor="nw")
        self.tab2_canvas.place(relwidth=1, relheight=1)  # Make the canvas fill the tab
        
        # Add widgets to encryption frame
        self.create_encryption_widgets()

        # Add widgets to decryption frame
        self.create_decryption_widgets()

    def create_encryption_widgets(self):
        # add encryption widgets on tabs
        # Label for input text
        self.T_label= customtkinter.CTkLabel(self.tab("ENCRYPTION"), text="ENTER THE TEXT", font=("Bahnschrift", 25))
        #Text entry for input text
        self.T_entry=customtkinter.CTkEntry(self.tab("ENCRYPTION"), width=850, height= 50, font=("Bahnschrift", 25), corner_radius=20)
        #Create check box for whether to enter key or not
        #function to toggle checkbox click
        def click():
            if check_var.get()=="on":
                self.kentry.grid(row=4, column=0, pady=5, padx=50, sticky="w")
                self.k_result.delete("0.0","end")
                self.k_result.grid_forget()
                self.k_res_label.grid_forget()
            if check_var.get()=="off":
                self.k_res_label.grid(row=10, column=0, pady=5, padx=50, sticky="w")
                self.k_result.grid(row=11, column=0, pady=5, padx=50, sticky="w")
                self.kentry.delete("0", "end")
                self.kentry.grid_forget()
        # perform function which is the logic in performing the operations
        def perform():
            plaintext = self.T_entry.get()
            algorithm = self.E_Alg_select.get()

            if algorithm == "MODIFIED VERNAM CIPHER":
                if check_var.get()=="on":
                    passphrase=self.kentry.get()
                    key=vm.get_key_from_user(len(plaintext),passphrase)
                    encrypted_text = vm.vernam_encrypt(plaintext, key)
                    self.e_result.delete("0.0", "end")
                    self.e_result.insert("0.0", encrypted_text)
                else:
                    key = vm.generate_key(len(plaintext))
                    self.k_result.delete("0.0","end")
                    self.k_result.insert("0.0",key)
                    encrypted_text = vm.vernam_encrypt(plaintext, key)
                    self.e_result.delete("0.0", "end")
                    self.e_result.insert("0.0", encrypted_text)
            elif algorithm == "BLOWFISH IN CBC MODE":
                if  check_var.get()=="on":  
                    passphrase=self.kentry.get()
                    plaintext = pad(plaintext.encode(), Blowfish.block_size)
                    encrypted_text = bf.encrypt_blowfish_cbc(plaintext,passphrase)
                    self.e_result.delete("0.0", "end")
                    self.e_result.insert("0.0", encrypted_text.hex())
                else:
                    passphrase=bf.generate_key(16)
                    self.k_result.delete("0.0","end")
                    self.k_result.insert("0.0",passphrase)
                    plaintext = pad(plaintext.encode(), Blowfish.block_size)
                    encrypted_text = bf.encrypt_blowfish_cbc(plaintext,passphrase)
                    self.e_result.delete("0.0", "end")
                    self.e_result.insert("0.0", encrypted_text.hex())



        #creating the checkbox
        check_var=customtkinter.StringVar(value="off")
        self.checkbox=customtkinter.CTkCheckBox(self.tab("ENCRYPTION"), text="CLICK TO ENTER PASSPHRASE", font=("Bahnschrift", 25), command=click, variable=check_var,  onvalue="on", offvalue="off")
        #text entry to enter key
        self.kentry=customtkinter.CTkEntry(self.tab("ENCRYPTION"), font=("Bahnschrift", 25), width=850,height=50, corner_radius=20)
        
        #combobox to select from the algorithms
        self.E_Alg_select=customtkinter.CTkComboBox(self.tab("ENCRYPTION"), values=["MODIFIED VERNAM CIPHER", "BLOWFISH IN CBC MODE"],font=("Bahnschrift", 25), width= 400, corner_radius=20)

        #creating a label for algorithm select
        self.Alg_label=customtkinter.CTkLabel(self.tab("ENCRYPTION"), text="SELECT THE ALGORITHM", font=("Bahnschrift", 25))

        #creating a button to perform the operation
        self.Button=customtkinter.CTkButton(self.tab("ENCRYPTION"), text="PERFORM", font=("Bahnschrift", 25), command=perform, width=400, corner_radius=20)

        #creating a label for result
        self.r_label=customtkinter.CTkLabel(self.tab("ENCRYPTION"), text="RESULT", font=("Bahnschrift", 25))

        #creating the textbox to display the result

        self.e_result=customtkinter.CTkTextbox(self.tab("ENCRYPTION"), width=850, height=200, font=("Bahnschrift", 25), corner_radius=20)
        #creating label for result key

        self.k_res_label=customtkinter.CTkLabel(self.tab("ENCRYPTION"), text="KEY", font=("Bahnschrift", 25))
        #creating the textbox to display the result

        self.k_result=customtkinter.CTkTextbox(self.tab("ENCRYPTION"), width=850, height=100, font=("Bahnschrift", 25), corner_radius=20)
        #Positioning the elements using grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0,weight=1)
        self.grid_rowconfigure(1,weight=1)
        self.grid_rowconfigure(2,weight=1)
        self.grid_rowconfigure(3,weight=1)
        self.grid_rowconfigure(4,weight=1)
        self.grid_rowconfigure(5,weight=1)
        self.grid_rowconfigure(6,weight=1)
        self.grid_rowconfigure(7,weight=1)
        self.grid_rowconfigure(8,weight=1)
        self.grid_rowconfigure(9,weight=1)
        self.grid_rowconfigure(10,weight=1)
        self.grid_rowconfigure(11,weight=1)

        
        self.T_label.grid(row=1, column=0, pady=5,padx=50, sticky="w")
        self.T_entry.grid(row=2, pady=5, padx=50, sticky="w")
        self.checkbox.grid(row=3, column=0, pady=5, padx=50, sticky="w")
        self.Alg_label.grid(row=5, column=0, padx=50,pady=5, sticky="w")
        self.E_Alg_select.grid(row=6, column=0, pady=5, padx=50,)
        self.Button.grid(row=7, column=0, pady=5, padx=50)
        self.r_label.grid(row=8, column=0, pady=5, padx=50, sticky="w")
        self.e_result.grid(row=9, column=0, pady=5, padx=50, sticky="w")
        self.k_res_label.grid(row=10, column=0, pady=5, padx=50, sticky="w")
        self.k_result.grid(row=11, column=0, pady=5, padx=50, sticky="w")

    def create_decryption_widgets(self):
        #performing decryption
        # Perform function to do the oprerations
        def perform():
            ciphertext = self.I_entry.get()
            algorithm = self.D_Alg_select.get()
            if algorithm == "MODIFIED VERNAM CIPHER":
                if check_var.get() =="on":
                    passphrase=self.bk_entry.get()
                    key= vm.get_key_from_user(len(ciphertext),passphrase)
                    Decrypted_text=vm.vernam_decrypt(ciphertext,key)
                    self.d_result.delete("0.0","end")
                    self.d_result.insert("0.0",Decrypted_text)
                else:
                    key=self.vk_entry.get()
                    Decrypted_text=vm.vernam_decrypt(ciphertext,key)
                    self.d_result.delete("0.0","end")
                    self.d_result.insert("0.0",Decrypted_text)

            elif algorithm == "BLOWFISH IN CBC MODE":
                if check_var.get() == "on":
                    ciphertext=bytes.fromhex(ciphertext)
                    passphrase = self.bk_entry.get()
                    Decrypted_text=bf.decrypt_blowfish_cbc(ciphertext, passphrase)
                    self.d_result.delete("0.0","end")
                    self.d_result.insert("0.0",Decrypted_text)
                else:
                    ciphertext=bytes.fromhex(ciphertext)
                    passphrase=self.vk_entry.get()
                    Decrypted_text=bf.decrypt_blowfish_cbc(ciphertext, passphrase)
                    self.d_result.delete("0.0","end")
                    self.d_result.insert("0.0",Decrypted_text)

        #add decryption widgets to tab
        # Function to check whether the checkbox is clicked or not
        def click():
            if check_var.get()=="on":
                self.bk_entry.grid(row=4, column=0, pady=5, padx=50, sticky="w")
                self.vk_entry.delete("0","end")
                self.vk_entry.grid_forget()
                self.vk_label.grid_forget()
            if check_var.get()=="off":
                self.bk_entry.delete("0", "end")
                self.bk_entry.grid_forget()
                self.vk_label.grid(row=3, column=0, pady=5,padx=50, sticky="w")
                self.vk_entry.grid(row=4, column=0, pady=5, padx=50, sticky="w")


        
        #Creating label and entry for random key generation
        self.vk_label=customtkinter.CTkLabel(self.tab("DECRYPTION"), text="ENTER THE KEY", font=("Bahnschrift", 25))
        self.vk_entry=customtkinter.CTkEntry(self.tab("DECRYPTION"), font=("Bahnschrift", 25), width =850, height=50, corner_radius=20)

        #  Creating label and entry for passphrase generation
        self.bk_label=customtkinter.CTkLabel(self.tab("DECRYPTION"), text="ENTER THE PASSPHRASE", font=("Bahnschrift", 25))
        self.bk_entry=customtkinter.CTkEntry(self.tab("DECRYPTION"), font=("Bahnschrift", 25), width =850, height=50, corner_radius=20)

        
        #creating label and text entry for input text 
        self.I_label=customtkinter.CTkLabel(self.tab("DECRYPTION"), text="ENTER THE TEXT", font=("Bahnschrift", 25))
        self.I_entry=customtkinter.CTkEntry(self.tab("DECRYPTION"), font=("Bahnschrift", 25),width =850, height=50, corner_radius=20)

        #creating the checkbox
        check_var=customtkinter.StringVar(value="off")
        self.D_checkbox=customtkinter.CTkCheckBox(self.tab("DECRYPTION"), text="CLICK TO ENTER PASSPHRASE", font=("Bahnschrift", 25), command=click, variable=check_var,  onvalue="on", offvalue="off")

        #creating a button to perform the operations
        self.Button=customtkinter.CTkButton(self.tab("DECRYPTION"), text="PERFORM", font=("Bahnschrift", 25), command= perform, corner_radius=20, width=400)

        #creating the dropdown box label to select the  type of cipher method
        self.D_Alg_label=customtkinter.CTkLabel(self.tab("DECRYPTION"), text="SELECT THE ALGORITHM", font=("Bahnschrift", 25))

        #creating alg select dropdown box
        self.D_Alg_select=customtkinter.CTkComboBox(self.tab("DECRYPTION"), values=["MODIFIED VERNAM CIPHER", "BLOWFISH IN CBC MODE"], width=400, font=("Bahnschrift", 25), corner_radius=20)
        #creating label for result
        self.r_label=customtkinter.CTkLabel(self.tab("DECRYPTION"), text="RESULT", font=("Bahnschrift", 25))

        #Creatng the field for result
        self.d_result=customtkinter.CTkTextbox(self.tab("DECRYPTION"), font=("Bahnschrift", 25), width=850, height=200, corner_radius=20)




        #grid positioning

        #Positioning the elements using grid
        self.grid_columnconfigure(0, weight=1)
        #self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0,weight=1)
        self.grid_rowconfigure(1,weight=1)
        self.grid_rowconfigure(2,weight=1)
        self.grid_rowconfigure(3,weight=1)
        self.grid_rowconfigure(4,weight=1)
        self.grid_rowconfigure(5,weight=1)
        self.grid_rowconfigure(6,weight=1)
        self.grid_rowconfigure(7,weight=1)
        self.grid_rowconfigure(8,weight=1)
        self.grid_rowconfigure(9,weight=1)


        self.I_label.grid(row=0, column=0, pady=5,padx=50, sticky="w")
        self.I_entry.grid(row=1, column=0, pady=5, padx=50, sticky="w")
        self.D_checkbox.grid(row=2, column=0, pady=5, padx=50, sticky="w")
        self.vk_label.grid(row=3, column=0, pady=5,padx=50, sticky="w")
        self.vk_entry.grid(row=4, column=0, pady=5, padx=50, sticky="w")
        self.D_Alg_label.grid(row=5, column=0, padx=50,pady=5, sticky="w")
        self.D_Alg_select.grid(row=6, column=0, pady=5, padx=50)
        self.Button.grid(row=7, column=0, pady=5, padx=50)
        self.r_label.grid(row=8, column=0, pady=5, padx=50, sticky="w")
        self.d_result.grid(row=9, column=0, pady=5, padx=50, sticky="w")
    
class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        customtkinter.set_appearance_mode("light")
        self.title("CipherGuard")
        self.geometry("1024x768")

        # Creating the Tabview and positioning it
        self.tab_view = MyTabView(master=self, width=800, height=300, corner_radius=20)
        self.tab_view.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        self.grid_rowconfigure(0,weight=0)
        self.grid_columnconfigure(0, weight=1)


app = App()
app.mainloop()