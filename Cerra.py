import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import pyperclip
import random
import string
import winsound
import copy
import json
import os
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64
import pathlib
import webbrowser
import gspread
import csv
import rsa
import re
import io
import zipfile
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import pickle
import google.auth.exceptions
from googleapiclient.errors import HttpError
from google_auth_oauthlib.flow import Flow, InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from google.auth.transport.requests import Request

root = tk.Tk()
root.title("Cerra")
appwidth = 925
appheight = 500
globalx = (root.winfo_screenwidth()/2) - (appwidth/2)
globaly = (root.winfo_screenheight()/2) - (appheight/2)
root.geometry(f"{appwidth}x{appheight}+{int(globalx)}+{int(globaly)}")
root.configure(bg="#fff")
root.resizable(False, False)
root.iconbitmap("app.ico")

startbtny = 100
btncolor = "#b04848"

card_prompts = ["Bank","email","Account Number","CVC","Password"]
password_prompts = ["Item Name","email","Username","URL","Password"]

remember = False
icon_view = True
settings_dict = {"remember":remember,"username":None,"icon_view":icon_view}

try:
    with open("user_settings.json", "r+") as f:

        if not f.read():
            f.seek(0)
            json.dump(settings_dict,f,indent=4)
        else:
            f.seek(0)
            try:
                settings = json.load(f)
            except Exception as err:
                settings = settings_dict
                f.seek(0)
                json.dump(settings_dict,f,indent=4)
            settings_dict = settings
            icon_view = settings_dict["icon_view"]
            print(icon_view)
            remember = settings_dict["remember"]
            print(remember)
except FileNotFoundError:
    with open("user_settings.json", "w") as f:
        json.dump(settings_dict,f,indent=4)

def RSA_encryption(txt,public_key):
    txt = json.dumps(txt.decode())
    result = []
    for n in range(0,len(txt),117):
        part = txt[n:n+117]
        result.append(rsa.encrypt(part.encode(), public_key))
    print(len(result),len(result[0]))
    return b''.join(result)

def RSA_decryption(RSA_content,private_key):
    result = []
    for n in range(0,len(RSA_content),128):
        part = RSA_content[n:n+128]
        result.append(rsa.decrypt(part, private_key).decode())
    print(result)
    result = json.loads(''.join(result))
    return result

def Create_Service(client_secret_file, api_name, api_version, *scopes):
    print(client_secret_file, api_name, api_version, scopes, sep='-')
    CLIENT_SECRET_FILE = client_secret_file
    API_SERVICE_NAME = api_name
    API_VERSION = api_version
    SCOPES = [scope for scope in scopes[0]]
    print(SCOPES)

    cred = None

    pickle_file = f'token_{API_SERVICE_NAME}_{API_VERSION}.pickle'
    # print(pickle_file)

    if os.path.exists(pickle_file):
        with open(pickle_file, 'rb') as token:
            cred = pickle.load(token)

    if not cred or not cred.valid:
        if cred and cred.expired and cred.refresh_token:
            cred.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET_FILE, SCOPES)
            flow.redirect_uri = 'http://localhost:8080'

            cred = flow.run_local_server(timeout_seconds=120)


        with open(pickle_file, 'wb') as token:
            pickle.dump(cred, token)

    try:
        service = build(API_SERVICE_NAME, API_VERSION, credentials=cred)
        print(API_SERVICE_NAME, 'service created successfully')
        return service
    except Exception as e:
        print('Unable to connect.')
        print(e)
        return None

class DataEncryption:

    @staticmethod
    def save_to_file(data,file):
        with open(file, "wb") as binary_file:
            binary_file.write(data)

    @staticmethod
    def get_encrypted_data(file):
        with open(file, "rb") as binary_file:
                return binary_file.read()

    @staticmethod
    def is_file_empty(file):
        try:
            with open(file, "rb") as binary_file:
                read_file = binary_file.read()
                if read_file != b"":
                    return False
                else:
                    return True
        except FileNotFoundError:
            with open(file, "wb") as binary_file:
                return True

    @classmethod
    def get_salt(cls,salt_file,from_file=False):
        cls.is_file_empty(salt_file)

        with open(salt_file, "rb+") as binary_file:
            if from_file:
                saved_salt = binary_file.read()
                if saved_salt != b"":
                    cls.salt = saved_salt
                    return saved_salt
                else:
                    raise IOError("Salt file is empty")
            else:
                salt = os.urandom(16)
                binary_file.write(salt)
                return salt

    @classmethod
    def encrypt(cls,password,data,salt_file):
        password = password.encode()
        data = data.encode()
        cls.password = password
        cls.data = data
        # Generate a key from the password using a key derivation function
        cls.salt = cls.get_salt(salt_file,from_file=True)
        kdf = cls.make_kdf(cls.salt)
        cls.key = base64.urlsafe_b64encode(kdf.derive(cls.password))

        # Encrypt the data
        fernet = Fernet(cls.key)
        encrypted_data = fernet.encrypt(cls.data)

        return encrypted_data

    @classmethod
    def encrypt_fast(cls,password,data,salt):
        password = password.encode()
        data = data.encode()
        salt = salt.encode("latin-1")
        # Generate a key from the password using a key derivation function
        kdf = cls.make_kdf(salt)
        key = base64.urlsafe_b64encode(kdf.derive(password))

        # Encrypt the data
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data)

        return encrypted_data

    @staticmethod
    def make_kdf(salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256,
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )

        return kdf

    @classmethod
    def decrypt(cls,password,encrypted_data,salt):
        password = password.encode()
        # Generate the key from the password
        key = cls.derive_key(password,salt)

        # Decrypt the data
        fernet = Fernet(key)
        #print(password)
        #print(salt.decode().encode())
        #print(encrypted_data)
        decrypted_data = fernet.decrypt(encrypted_data)
        return decrypted_data.decode()

    @staticmethod
    def decrypt_fast(key,items):
        #print(key)
        #print(items)
        key = key
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(items.encode())
        return decrypted_data.decode()

    @classmethod
    def derive_key(cls,password,salt):
        # Derive a key from the password
        kdf = cls.make_kdf(salt)
        key = base64.urlsafe_b64encode(kdf.derive(password))
        #print(key)
        return key

    @classmethod
    def check_password(cls,password,encrypted_data,salt):
        password = password.encode()
        # Derive the key from the password
        key = cls.derive_key(password, salt)

        # Try to decrypt the data using the key
        fernet = Fernet(key)
        try:
            fernet.decrypt(encrypted_data)
            return True
        except Exception:
            return False

class Preset:

    def __init__(self,card,website,email,username,url,password,image):
        self.card = card
        self.website = website
        self.email = email
        self.username = username
        self.url = url
        self.password = password
        self.image = image

        self.dictionary = {
          "Card":card,
          "Website":website,
          "email":email,
          "Username":username,
          "url":url,
          "password":password,
          "image":image
        }

    @staticmethod
    def obj_list_to_dict(lst):
        new_lst = []
        for object in lst:
            new_lst.append(object.dictionary)

        return new_lst

    @staticmethod
    def short_dicts(lst):
        new_lst = []
        for object in lst:
            beg = "" if object.url == None or object.url == "" else "https://"
            print(type(object.url),beg)
            obj_dict = {"name":object.website,
            "url":beg+object.url,
            "username":object.email,
            "password":object.password}
            new_lst.append(obj_dict)

        return new_lst

    @classmethod
    def dict_list_to_obj(cls,lst):
        new_lst = []
        for dict in lst:
            params = dict.values()
            new_lst.append(cls(*params))

        return new_lst

pres_list = [Preset(False,"",None,"",None,None,"password.png")]

try:
    with open("presets.json","r") as f:
        try:
            file_pres_list = json.load(f)
            pres_list.extend(Preset.dict_list_to_obj(file_pres_list))
        except Exception as err:
            print(err)
except FileNotFoundError:
    with open("presets.json","w") as f:
        pass

print(pres_list)
options = {pre.website: pre for pre in pres_list}

added_items = []

print(options)

def copyButton(parent,label):
    def on_enter(e):
        myBtn["bg"] = "#bdbdbd"

    def on_leave(e):
        myBtn["bg"] = "#dedede"

    myBtn = tk.Button(parent,
        width=5,
        pady=7,
        text="copy",
        bg="#dedede",
        fg="black",
        border=0,
        command=lambda :pyperclip.copy(label.label_text))

    myBtn.bind("<Enter>", on_enter)
    myBtn.bind("<Leave>", on_leave)
    return myBtn

def itemShower(parent,item):
    color = "#73ccff"
    #color = btncolor

    def on_enter(e):
        frame["bg"] = color
        button1["bg"] = color
        button2["bg"] = color

    def on_leave(e):
        frame["bg"] = "white"
        button1["bg"] = "white"
        button2["bg"] = "white"

    def check_item_info():
        e.item_info(item)

    frame = tk.Frame(parent)

    try:
        photo = tk.PhotoImage(file="icons/" + item.dictionary["image"])
    except Exception:
        try:
            photo = tk.PhotoImage(file="icons/notfound.png")
        except Exception:
            photo = ""

    label = tk.Label(frame,image=photo)
    label.image = photo

    dim1 = 14 if photo == "" else 0
    dim2 = 6 if photo == "" else 0

    button1 = tk.Button(frame,
        image=photo,
        command=check_item_info,
        bd=0,
        bg="white",
        width=dim1,
        height=dim2)
    button1.pack()

    button2 = tk.Button(frame,
        text=item.dictionary["Website"]+"\n"+item.dictionary["Username"],
        command=check_item_info,
        width=5,
        height=2,
        bd=0,
        bg="white")

    button2.pack(fill=tk.X)

    frame.bind("<Enter>", on_enter)
    frame.bind("<Leave>", on_leave)

    return frame

def returnButton(parent,x,y,cmd):

    myBtn = tk.Button(parent,
        width=5,
        pady=7,
        text="⇐",
        bg="#dedede",
        fg="black",
        border=0,
        command=cmd)

    myBtn.place(x=x,y=y)
    return myBtn

def eyeButton(parent,x,y,entry):

    def on_enter(e):
        myBtn["bg"] = "#bdbdbd"

    def on_leave(e):
        myBtn["bg"] = "#dedede"

    def toggle():

        if entry["show"] == "" and entry["fg"] == "black":
            entry.showVariable = "●"
            entry["show"] = "●"
            myBtn["text"] = "show"

        elif entry.showVariable == "":
            entry.showVariable = "●"
            myBtn["text"] = "show"

        elif entry.showVariable == "●":
            entry.showVariable = ""
            entry["show"] = ""
            myBtn["text"] = "hide"

    myBtn = tk.Button(parent,
        width=5,
        pady=7,
        text="show",
        bg="#dedede",
        fg="black",
        border=0,
        command=toggle)

    myBtn.bind("<Enter>", on_enter)
    myBtn.bind("<Leave>", on_leave)

    myBtn.place(x=x,y=y)
    return myBtn

def toggleButton(parent):

    def on_enter(e):
        myBtn["bg"] = "#bdbdbd"

    def on_leave(e):
        myBtn["bg"] = "#dedede"

    def toggle():
        global icon_view
        with open("user_settings.json", "w") as f:
            if icon_view:
                settings_dict["icon_view"] = False
                print(settings_dict)
                icon_view = False
                myBtn["text"] = "="
            else:
                settings_dict["icon_view"] = True
                icon_view = True
                myBtn["text"] = "::"

            json.dump(settings_dict,f,indent=4)

        e.all_items()

    myBtn = tk.Button(parent,
        width=2,
        height=0,
        pady=7,
        text="::",
        bg="#dedede",
        fg="black",
        font="Arial 16 bold",
        border=0,
        command=toggle)

    myBtn.bind("<Enter>", on_enter)
    myBtn.bind("<Leave>", on_leave)

    return myBtn

def cerraButton(parent,x,y,width,fontsize,text,cmd):

    def on_enter(e):
        myBtn["bg"] = "#6d2c2c"

    def on_leave(e):
        myBtn["bg"] = btncolor

    myBtn = tk.Button(parent,
        width=width,
        pady=7,
        text=text,
        bg=btncolor,
        fg="white",
        border=0,
        cursor="hand2",
        font='Arial {}'.format(fontsize),command=cmd)

    myBtn.bind("<Enter>", on_enter)
    myBtn.bind("<Leave>", on_leave)

    myBtn.place(x=x,y=y)
    return myBtn

def stripButton(parent,text,cmd,bg="#333333",hbg="#525252",width=25,font=("Arial 10 bold")):

    def on_enter(e):
        myBtn["bg"] = hbg

    def on_leave(e):
        myBtn["bg"] = bg

    myBtn = tk.Button(parent,
        width=width,
        height=2,
        pady=7,
        text=text,
        bg=bg,
        fg="white",
        font=font,
        border=0,
        cursor="hand2",
        command=cmd)

    myBtn.bind("<Enter>", on_enter)
    myBtn.bind("<Leave>", on_leave)
    return myBtn

def cerraEntry(parent,x,y,text,width,lineWidth,fontsize,show="",focolor="black"):

    def temp_text(e):
        myLine.configure(bg=focolor)
        myEntry["show"] = myEntry.showVariable
        name=myEntry.get()
        #print(name)
        if myEntry["fg"] == "grey":
            myEntry.delete(0,"end")
            myEntry["fg"] = "black"

    def leave_text(e):
        myLine.configure(bg="black")
        name=myEntry.get()
        if name=="":
            myEntry["show"] = ""
            myEntry.insert(0, myEntry.originaltext)
            myEntry["fg"] = "grey"

    myEntry = tk.Entry(parent,fg="grey",width=width,font=('Arial {}'.format(fontsize)),bd=0)
    myEntry.insert(0, text)
    myEntry.place(x=x,y=y)

    myEntry.bind("<FocusIn>", temp_text)
    myEntry.bind("<FocusOut>", leave_text)

    myEntry.showVariable = show
    myEntry.originaltext = text

    myLine = tk.Frame(parent,width=lineWidth,height=1,bg="black")
    myLine.place(x=x-5,y=y+fontsize*2)
    return myEntry

def rechange(entry):
    entry.delete(0,"end")
    entry.insert(0,entry.originaltext)
    entry["show"] = ""
    entry["fg"] = "grey"

def set_preview(image_object,image):
    try:
        thumbnail = tk.PhotoImage(file="icons/"+image)
    except Exception as e:
        print(e)
        try:
            thumbnail = tk.PhotoImage(file="icons/notfound.png")
        except Exception:
            thumbnail = ""
    image_object.configure(image=thumbnail)
    image_object.image=thumbnail

class Start:
    def __init__(self, master):
        self.online = False
        self.inputed_password = ""
        self.salt = b''
        self.master = master
        self.benefactor_list = None
        self.inheritor_index = None
        self.inheritor_public_key = None

        self.frame = tk.Frame(self.master,width=350,height=350,bg="white")
        self.frame.place(x=480,y=70)

        try:
            self.img = tk.PhotoImage(file=f"startup/start{random.randint(1,5)}.png")
        except:
            self.img = ""
        tk.Label(self.master,image=self.img,bg="white").place(x=50,y=30)

        self.create_menu()
        self.startMenu()

    def create_menu(self,parent=root):
        root.unbind("<Button-3>")
        print("good luck")
        self.m = tk.Menu(parent,tearoff=0)
        self.m.add_command(label="Cut",command=lambda:self.m_action(action="cut"))
        self.m.add_command(label="Copy",command=lambda:self.m_action(action="copy"))
        self.m.add_command(label="Paste",command=lambda:self.m_action(action="paste"))
        self.m.add_separator()
        self.m.add_command(label="Select All",command=lambda:self.m_action(action="select"))
        parent.bind("<Button-3>", self.do_popup)

    def m_action(self,action=None):
        widget = root.focus_get()
        if isinstance(widget,tk.Entry):
            if action == "paste":
                widget.event_generate("<<Paste>>")
            elif action == "cut":
                widget.event_generate("<<Cut>>")
            elif action == "copy":
                widget.event_generate("<<Copy>>")
            elif action == "select":
                widget.event_generate("<<SelectAll>>")

    def do_popup(self,event):
        try:
            self.m.tk_popup(event.x_root, event.y_root)
        #except Exception:
        #    print("error")
        finally:
            self.m.grab_release()

    def startMenu(self):
        self.clear(self.frame)
        self.localbtn = cerraButton(self.frame,25,startbtny,30,15,"Local",self.golocal)
        self.loginbtn = cerraButton(self.frame,25,startbtny+60,30,15,"Login",self.logon)

    def golocal(self):
        self.clear(self.frame)

        self.goback = returnButton(self.frame,0,0,self.startMenu)
        self.password = cerraEntry(self.frame,60,100,"Password",13,250,24,show="●",focolor="#00a2ff")
        self.password.bind('<Return>',self.check_entry)
        self.password.focus_set()
        self.show = eyeButton(self.frame,310,100,self.password)
        self.enterpassword = cerraButton(self.frame,70,200,20,15,"Enter",self.check_entry)
        self.errorLabel = tk.Label(root,text="",fg="red",bg="white")
        self.errorLabel.place(x=540,y=400)
        self.frame.bind("<Button-1>",lambda e: self.frame.focus_set())

    def check_entry(self,e=None):

        if self.password["fg"] == "black":
            self.inputed_password = self.password.get()
        else:
            self.errorLabel.configure(text="You must enter password")
            return

        if len(self.inputed_password) < 8:
            self.errorLabel.configure(text="For security, make your password atleast 8 characters long")
            return

        if not DataEncryption.is_file_empty("normal.bin"):
            if DataEncryption.is_file_empty("salt.bin"):
                tk.messagebox.showinfo(title="corrupted files",
                message="Sadly one of the files is empty,\nyou'll have to delete normal.bin \nwhere your passwords are stored to continue")
                return

            my_items = DataEncryption.get_encrypted_data("normal.bin")
            self.salt = DataEncryption.get_salt("salt.bin",from_file=True).decode("latin-1")

            if DataEncryption.check_password(self.password.get(),my_items,self.salt.encode("latin-1")):
                global added_items
                print("good")
                dec_itms = DataEncryption.decrypt(self.password.get(),my_items,self.salt.encode("latin-1"))
                added_items = Preset.dict_list_to_obj(json.loads(dec_itms))
                #print(added_items)
                self.inanout()
            else:
                self.errorLabel.configure(text="The password you have entered is incorrect")
        else:
            tk.messagebox.showinfo(title="No files", message="Once a password is saved your master password will be saved")
            if DataEncryption.is_file_empty("salt.bin"):
                self.salt = DataEncryption.get_salt("salt.bin").decode("latin-1")
            else:
                self.salt = DataEncryption.get_salt("salt.bin",from_file=True).decode("latin-1")
            self.inanout()


    def logon(self):
        try:
            sa = gspread.service_account(filename="secret.json")
            sh = sa.open("normal")
            self.wks = sh.worksheet("Sheet1")
        except Exception as e:
            tk.messagebox.showinfo(title="Connection Failed", message=e)
            return

        print("online")

        self.loginWindow = tk.Toplevel(root, bg="white")
        self.loginWindow.geometry(f"300x500+{int(globalx)+520}+{int(globaly)-20}")
        self.loginWindow.resizable(False, False)
        self.loginWindow.transient(root)
        self.loginWindow.iconbitmap("app.ico")

        self.loginWindow.focus_force()

        self.siginLbl = tk.Label(self.loginWindow,bg="white",fg=btncolor,text="Sign In",font=("Microsoft YaHei UI Light",24))
        self.siginLbl.place(x=40,y=20)

        self.username = cerraEntry(self.loginWindow,50,100,"Username",16,200,14,focolor="#00a2ff")
        self.password = cerraEntry(self.loginWindow,50,170,"Password",16,200,14,show="●",focolor="#00a2ff")
        self.password.bind('<Return>',self.check_login)

        self.show = eyeButton(self.loginWindow,200,217,self.password)

        self.saveusername = tk.Checkbutton(self.loginWindow,text="remember username",bg="#fff",command=self.remember_function)
        self.saveusername.place(x=50,y=220)
        if remember:
            #print(settings_dict["username"])
            self.saveusername.select()
            if settings_dict["username"] != None:
                self.username.delete(0,"end")
                self.username.insert(0,settings_dict["username"])
                self.username.configure(fg="black")
                self.password.focus_set()

        self.warningLabel = tk.Label(self.loginWindow,fg="red",bg="white")
        self.warningLabel.place(x=50,y=300)

        self.signin = cerraButton(self.loginWindow,50,430,10,10,"Sign in",self.check_login)
        self.cancel = cerraButton(self.loginWindow,160,430,10,10,"Cancel",lambda:[self.create_menu(),self.closeSignin()])

        self.changeState(self.frame,tk.DISABLED)

        root.bind("<FocusIn>", self.windowfoc)
        self.loginWindow.protocol("WM_DELETE_WINDOW",lambda:[self.create_menu(),self.closeSignin()])
        self.create_menu(parent=self.loginWindow)

    def check_login(self,e=None):
        username = self.username.get()
        password = self.password.get()
        users = self.wks.row_values(1)

        if (self.username["fg"] == "grey") or (username == ""):
            self.warningLabel.configure(text="You must enter a username")
            return

        if (self.password["fg"] == "grey") or (password == ""):
            self.warningLabel.configure(text="You must enter a password")
            return

        if bool(users.count(username)):
            self.myindex = users.index(username) + 1
            #print(self.myindex)
            #print(self.wks.cell(2,self.myindex).value)
        else:
            self.warningLabel.configure(text="Wrong username or password")
            return

        if self.wks.cell(2,self.myindex).value == None:
            print("hello")
            if self.wks.cell(4,self.myindex).value != None:
                self.warningLabel.configure(text="Something went wrong... contact us")
                return
            elif len(password) < 8:
                self.warningLabel.configure(text="8 characters minimum for password")
                return
            else:
                self.wks.update_cell(2,self.myindex,os.urandom(16).decode('latin-1'))
                answer = tk.messagebox.askquestion("master password","Are you sure you want to save this password")
                if answer == "yes":
                    self.inputed_password = password
                    self.salt = self.wks.cell(2,self.myindex).value
                    self.create_rsa()
                    self.online = True
                    self.save_username(username)
                    self.inanout()
                    return
                else:
                    print("no go")
                    return
        elif len(password) < 8:
            self.warningLabel.configure(text="8 characters minimum for password")
            return
        elif self.wks.cell(4,self.myindex).value == None:
            answer = tk.messagebox.askquestion("master password","Are you sure you want to save this password")
            if answer == "yes":
                self.inputed_password = password
                self.salt = self.wks.cell(2,self.myindex).value
                self.create_rsa()
                self.online = True
                self.save_username(username)
                self.inanout()
                return
            else:
                print("no go")
                return

        salt = self.wks.cell(2,self.myindex).value.encode('latin-1')
        priv = self.wks.cell(4,self.myindex).value.encode()

        if DataEncryption.check_password(password,priv,salt):
            print("correct password")
            #print(salt)
            priv = DataEncryption.decrypt(password,priv,salt)
            #print(priv)
            self.private_key = rsa.PrivateKey.load_pkcs1(priv)

            if self.wks.cell(5,self.myindex).value != None:
                self.inputed_password = password
                self.salt = salt.decode('latin-1')
                #data = self.wks.cell(5,self.myindex).value.encode()
                data = self.download_input(self.myindex).encode()
                #print(DataEncryption.check_password(password,data,salt))
                global added_items
                decri = DataEncryption.decrypt(password,data,salt)
                dec_itms = json.loads(decri)
                added_items = Preset.dict_list_to_obj(dec_itms)
                self.online = True
                self.save_username(username)
                self.inheritance_settings()
                self.inanout()
            else:
                self.inputed_password = password
                self.salt = self.wks.cell(2,self.myindex).value
                self.online = True
                self.save_username(username)
                self.inheritance_settings()
                self.inanout()
        else:
            self.warningLabel.configure(text="Wrong username or password")
            return

    def inheritance_settings(self):
        users = self.wks.row_values(1)
        inheritor = self.wks.cell(7,self.myindex).value
        benefactors = self.wks.cell(6,self.myindex).value

        if inheritor != None:
            inheritor = DataEncryption.decrypt(self.inputed_password,inheritor.encode(),self.salt.encode("latin-1"))
            self.inheritor_index = users.index(json.loads(inheritor)["contact"]) + 1
            self.inheritor_public_key = rsa.PublicKey.load_pkcs1(self.wks.cell(3,self.inheritor_index).value)
        else:
            self.inheritor_index = None
            self.inheritor_public_key = None

        if benefactors != None:
            self.benefactor_list = json.loads(benefactors)
        else:
            self.benefactor_list = None

    def save_username(self,username):
        global remember
        if remember:
            with open("user_settings.json", "w") as f:
                settings_dict["username"] = username
                json.dump(settings_dict,f,indent=4)
        else:
            with open("user_settings.json", "w") as f:
                settings_dict["username"] = None
                json.dump(settings_dict,f,indent=4)

    def create_rsa(self):
        public_key, private_key = rsa.newkeys(1024)
        self.wks.update_cell(3,self.myindex,public_key.save_pkcs1("PEM").decode())
        encpk = DataEncryption.encrypt_fast(self.inputed_password,private_key.save_pkcs1("PEM").decode(),self.salt)
        self.wks.update_cell(4,self.myindex,encpk.decode())
        self.private_key = private_key

    def remember_function(self):
        global remember
        if remember:
            remember = False
            settings_dict["username"] = None
        else:
            remember = True
        with open("user_settings.json", "w") as f:
            settings_dict["remember"] = remember
            json.dump(settings_dict,f,indent=4)

    def inanout(self):
        #print(self.salt)
        reset_timer()
        root.bind_all('<Any-KeyPress>', reset_timer)
        root.bind_all('<Any-ButtonPress>', reset_timer)
        #print(added_items)
        self.clear(root)
        root.resizable(True, True)
        root.minsize(925,500)

        menubar = tk.Menu(root)
        root.config(menu=menubar)

        fileMenu = tk.Menu(menubar,tearoff=0)
        fileMenu.add_command(label="Exit",command=root.destroy)
        fileMenu.add_command(label="Download File",command=self.downloadpasswords)

        sub_menu = tk.Menu(fileMenu, tearoff=0)
        sub_menu.add_command(label='Web CSV',command=self.to_csv)
        sub_menu.add_command(label='Full CSV',command=lambda:self.to_csv(lst=Preset.obj_list_to_dict(added_items)))

        fileMenu.add_cascade(label="Export CSV",menu=sub_menu)#self.to_csv
        fileMenu.add_command(label="Import CSV",command=self.from_csv)
        menubar.add_cascade(label="File",menu=fileMenu)

        accountMenu = tk.Menu(menubar,tearoff=0)
        accountMenu.add_command(label="Leave",command=user_is_inactive)
        accountMenu.add_command(label="Inheritance",command=self.emergency)
        accountMenu.add_command(label="Change passphrase",command=self.change_passphrase)
        menubar.add_cascade(label="Account",menu=accountMenu)

        if not self.online:
            accountMenu.entryconfig(1, state=tk.DISABLED)

        editMenu = tk.Menu(menubar,tearoff=0)
        editMenu.add_command(label="Cut",command=lambda:self.m_action(action="cut"))
        editMenu.add_command(label="Copy",command=lambda:self.m_action(action="copy"))
        editMenu.add_command(label="Paste",command=lambda:self.m_action(action="paste"))
        editMenu.add_separator()
        editMenu.add_command(label="Select all",command=lambda:self.m_action(action="select"))
        menubar.add_cascade(label="Edit", menu=editMenu)

        darkStrip = tk.Frame(root,bg="#3b3b3b",pady=20)
        darkStrip.pack(side=tk.LEFT,fill=tk.Y)

        topStrip = tk.Frame(root,height=100)
        topStrip.pack(side=tk.TOP,fill=tk.X)

        self.frame2 = tk.Frame(root,bg="white")
        self.frame2.pack(side=tk.TOP,expand=True,fill=tk.BOTH)

        self.toggle_view = toggleButton(topStrip)
        if not icon_view:
            self.toggle_view["text"] = "="
        self.toggle_view.pack(side=tk.RIGHT,padx=10)

        add_item = stripButton(topStrip,"add item",self.add_form,bg="#00a2ff",hbg="#73ccff",font="Arial 10 bold", width=10)
        add_item.pack(side=tk.RIGHT,pady=10)

        self.search_bar = cerraEntry(topStrip,50,20,"Search",16,200,14,focolor="#00a2ff")
        self.search_bar.configure(bg="#F0F0F0")
        self.search_bar.bind("<KeyRelease>", self.search_item)

        topStrip.bind("<Button-1>",lambda e: self.frame2.focus_set())
        self.frame2.bind("<Button-1>",lambda e: topStrip.focus_set())

        stripButton1 = stripButton(darkStrip,"All Items",self.all_items).pack(fill=tk.X)
        stripButton2 = stripButton(darkStrip,"Passwords",self.folder_view).pack(fill=tk.X,pady=3)
        stripButton3 = stripButton(darkStrip,"Cards",self.cards).pack(fill=tk.X)
        stripButton4 = stripButton(darkStrip,"Help",self.openHelp).pack(fill=tk.X, side=tk.BOTTOM)
        stripButton5 = stripButton(darkStrip,"Legal",self.openLegal).pack(fill=tk.X, side=tk.BOTTOM,pady=3)

        self.canvas_y = 0.
        self.canvas_x = 0.
        self.all_items()
        self.create_menu()

    def change_passphrase(self):
        self.pasWindow = tk.Toplevel(root)
        self.pasWindow.geometry(f"500x350+{root.winfo_x()+200}+{root.winfo_y()+50}")
        self.pasWindow.transient(root)
        self.pasWindow.resizable(False,False)
        self.pasWindow.grab_set()
        self.pasWindow.iconbitmap("app.ico")

        frame4 = tk.Frame(self.pasWindow,bg="white")
        frame4.pack(expand=True,fill=tk.BOTH)
        frame4.bind("<Button-1>",lambda e: frame4.focus_set())

        self.pasWindow.protocol("WM_DELETE_WINDOW",lambda:[self.create_menu(),self.pasWindow.destroy()])

        tk.Label(frame4,text="Change Passphrase",bg="white",fg=btncolor,font=("Microsoft YaHei UI Light",24)).place(x=120,y=10)

        self.oldpassword = cerraEntry(frame4,150,100,"Old Password",16,200,14,focolor="#00a2ff",show="●")
        eyeButton(frame4,350,100,self.oldpassword)
        self.newpassword = cerraEntry(frame4,150,200,"New Password",16,200,14,focolor="#00a2ff",show="●")
        eyeButton(frame4,350,200,self.newpassword)
        cerraButton(frame4,155,290,20,12,"Change Password",self.redo_all)

        self.warningLabel = tk.Label(frame4,text="",bg="white",width=68)
        self.warningLabel.place(x=10,y=260)
        self.create_menu(self.pasWindow)

    def redo_all(self):
        if self.oldpassword["fg"] == "grey" or self.newpassword["fg"] == "grey":
            self.warningLabel.configure(text="All fields must be entered",fg="red")
            return

        oldpassword = self.oldpassword.get()
        newpassword = self.newpassword.get()

        if not oldpassword or not newpassword:
            self.warningLabel.configure(text="All fields must be entered",fg="red")
            return

        if oldpassword != self.inputed_password:
            self.warningLabel.configure(text="Old password doesn't match",fg="red")
            return

        if len(newpassword) < 8:
            self.warningLabel.configure(text="For safety the password should be 8 characters long",fg="red")
            return

        if oldpassword == newpassword:
            self.warningLabel.configure(text="Your new password can't be the same as your old one",fg="red")
            return

        ans = tk.messagebox.askokcancel("Change Password?","Are you sure you want to change your passphrase?")
        if not ans:
            return


        self.inputed_password = newpassword
        if self.online and (self.inheritor_index != None):
            inheritor_id = self.wks.cell(7,self.myindex).value.encode()
            inheritor_id = DataEncryption.decrypt(oldpassword,inheritor_id,self.salt.encode("latin-1"))

            inh_dict = json.loads(self.wks.cell(6,self.inheritor_index).value)
            newKey = DataEncryption.derive_key(self.inputed_password.encode(),self.salt.encode("latin-1"))
            enc_inheritor_id = DataEncryption.encrypt_fast(self.inputed_password,inheritor_id,self.salt)
            inh_dict[str(self.myindex)]["items"] = RSA_encryption(newKey,self.inheritor_public_key).decode("latin-1")

            self.wks.update_cell(6,self.inheritor_index,json.dumps(inh_dict))
            self.wks.update_cell(7,self.myindex,enc_inheritor_id.decode())

        if self.online:
            priv = DataEncryption.encrypt_fast(self.inputed_password,self.private_key.save_pkcs1("PEM").decode(),self.salt)
            self.wks.update_cell(4,self.myindex,priv.decode())

        self.save_all()
        self.pasWindow.destroy()
        user_is_inactive()

    def emergency(self):
        self.inheritance_settings()
        willWindow = tk.Toplevel(root)
        willWindow.geometry(f"500x350+{root.winfo_x()+100}+{root.winfo_y()+50}")
        willWindow.transient(root)
        willWindow.resizable(False,False)
        willWindow.iconbitmap("app.ico")
        willWindow.grab_set()

        frame3 = tk.Frame(willWindow,bg="white")
        frame3.pack(expand=True,fill=tk.BOTH)
        frame3.bind("<Button-1>",lambda e: frame3.focus_set())

        willWindow.protocol("WM_DELETE_WINDOW",lambda:[self.create_menu(),willWindow.destroy()])
        benefactors = self.benefactor_list

        self.yourEmail = cerraEntry(frame3,30,100,"Your Email",16,200,14,focolor="#00a2ff")
        self.contact = cerraEntry(frame3,30,180,"Contact",16,200,14,focolor="#00a2ff")
        cerraButton(frame3,20,290,15,12,"Deny Request",self.deny_request)
        cerraButton(frame3,175,290,15,12,"Send To contact",self.send_to_iheritor)
        requestThem = cerraButton(frame3,330,290,15,12,"Request",self.request_access)
        stripButton(frame3,"Remove inheritor",self.rid_annoyance,font=("Arial 9")).place(x=280,y=200)

        self.n = tk.StringVar()

        if self.wks.cell(7,self.myindex).value != None:
            inh_dict = DataEncryption.decrypt(self.inputed_password,self.wks.cell(7,self.myindex).value.encode(),self.salt.encode("latin-1"))
            inh_dict = json.loads(inh_dict)
            self.yourEmail.delete(0,"end")
            self.contact.delete(0,"end")
            self.yourEmail["fg"] = "black"
            self.contact["fg"] = "black"
            self.yourEmail.insert(0,inh_dict["email"])
            self.contact.insert(0,inh_dict["contact"])

        self.requestStatus = tk.Label(frame3,text="No Request made or request denied",fg="red",bg="white")
        self.requestStatus.place(x=280,y=130)

        if benefactors == None:
            requestThem.configure(state="disabled")
            self.requestStatus.configure(text="")
            benefactors = ["None"]
            self.n.set("None")
        else:
            benefactors = [self.wks.cell(1,d).value for d in self.benefactor_list.keys()]
            self.n.set(benefactors[0])
            self.get_tminus(perp=next(iter(self.benefactor_list)))

        self.benDrop = tk.OptionMenu(frame3,self.n,*benefactors,command=self.get_tminus)
        self.benDrop.configure(width=8)
        self.benDrop.place(x=400,y=70)

        tk.Label(frame3,text="Your benefactors:",bg="white").place(x=290,y=75)
        tk.Label(frame3,text="Inheritance Form",bg="white",fg=btncolor,font=("Microsoft YaHei UI Light",24)).place(x=20,y=10)

        self.inheritor_status = tk.Label(frame3,text="No inheritor",bg="white")
        self.inheritor_status.place(x=20,y=230)

        if self.inheritor_index != None:
            timer = json.loads(self.wks.cell(6,self.inheritor_index).value)[str(self.myindex)]["timer"]
            if timer != None:
                timer = datetime.strptime(timer,"%d/%m/%Y")
                tminus = 0 if timer < datetime.now() else (timer - datetime.now()).days + 1
                self.inheritor_status.configure(text=f"Inheritor will have your items in {tminus} day(s)",fg="red")
            else:
                self.inheritor_status.configure(text="Inheritor has not requested",fg="black")

        self.warningLabel = tk.Label(frame3,text="",bg="white")
        self.warningLabel.place(x=20,y=250)
        self.create_menu(parent=willWindow)

    def deny_request(self):
        if self.inheritor_index == None:
            return
        their_list = json.loads(self.wks.cell(6,self.inheritor_index).value)
        their_list[str(self.myindex)]["timer"] = None
        self.inheritor_status.configure(text="Inheritor has not requested",fg="black")
        self.wks.update_cell(6,self.inheritor_index,json.dumps(their_list))

    def rid_annoyance(self):
        self.inheritance_settings()
        print("hello")
        if self.inheritor_index == None:
            return
        old_inheritor = json.loads(self.wks.cell(6,self.inheritor_index).value)
        del old_inheritor[str(self.myindex)]
        #print("THIS IS THE LIST NOW: ",old_inheritor,self.inheritor_index)
        self.wks.update_cell(6,self.inheritor_index,"" if old_inheritor == {} else json.dumps(old_inheritor))
        self.wks.update_cell(7,self.myindex,"")
        self.yourEmail.delete(0,"end")
        self.contact.delete(0,"end")
        self.yourEmail["fg"] = "grey"
        self.contact["fg"] = "grey"
        self.yourEmail.insert(0,self.yourEmail.originaltext)
        self.contact.insert(0,self.contact.originaltext)
        self.inheritor_status.configure(text="No inheritor",fg="Black")

    def get_tminus(self,perp=True):
        users = self.wks.row_values(1)
        benf_choice = self.n.get()

        if self.n.get() == "None":
            return

        if perp:
            perp = str(users.index(benf_choice)+1)

        timer = self.benefactor_list[perp]["timer"]
        if timer != None:
            tminus = datetime.strptime(timer,"%d/%m/%Y") - datetime.today()
            print(tminus)
            if tminus.days < 0:
                self.requestStatus.configure(text="You can download their items",fg="green")
            else:
                self.requestStatus.configure(text=f"You'll receive their items in {tminus.days+1} day(s)",fg="blue")
        else:
            self.requestStatus.configure(text="No Request made or request denied",fg="red")

    def send_notification(self,sender,receiver,email,benf):
        CLIENT_SECRET_FILE = 'email_secret.json'
        API_NAME = 'gmail'
        API_VERSION = 'v1'
        SCOPES = ['https://www.googleapis.com/auth/gmail.send']

        try:
            service = Create_Service(CLIENT_SECRET_FILE, API_NAME, API_VERSION, SCOPES)
        except Exception as e:
            self.warningLabel.configure(text="Couldn't send email to request",fg="red")
            print(f"There was a problem authorizing: {e}")
            return

        emailMsg = (f'Hello {receiver}, it appears {sender} has requested access to your Cerra account, you have 30 days to reject.')
        mimeMessage = MIMEMultipart()
        mimeMessage['to'] = email
        mimeMessage['subject'] = 'Cerra Passwords'
        mimeMessage.attach(MIMEText(emailMsg, 'plain'))
        raw_string = base64.urlsafe_b64encode(mimeMessage.as_bytes()).decode()

        message = service.users().messages().send(userId='me', body={'raw': raw_string}).execute()
        print(message)

        offset = datetime.now() + timedelta(days=30)
        self.benefactor_list[str(benf)]["timer"] = offset.strftime('%d/%m/%Y')
        print(json.dumps(self.benefactor_list))
        self.wks.update_cell(6,self.myindex,json.dumps(self.benefactor_list))
        self.requestStatus.configure(text="You'll receive their items in 30 day(s)",fg="blue")
        self.warningLabel.configure(text="successfully requested",fg="green")

    def request_access(self):
        self.inheritance_settings()
        print(self.benefactor_list)
        if self.benefactor_list == None:
            tk.messagebox.showerror('404', 'It appears the benefactor removed you as an inheritor')
            return

        their_name = self.n.get()
        users = self.wks.row_values(1)
        benf = users.index(their_name) + 1

        try:
            data = self.benefactor_list[str(benf)]
        except KeyError:
            tk.messagebox.showerror('404', 'It appears the benefactor removed you as an inheritor')
            return

        if data["timer"] == None:
            benf_email = RSA_decryption(data["benf_email"].encode("latin-1"),self.private_key)
            print("bye")
            print("Hello")
            try:
                self.send_notification(users[self.myindex-1],their_name,benf_email,benf)
            except Exception as err:
                tk.messagebox.showerror("Error", f"There was an error while sending email: {err}")
            return
        elif datetime.strptime(data["timer"],"%d/%m/%Y") > datetime.now():
            tminus = datetime.strptime(data["timer"],"%d/%m/%Y") - datetime.now()
            print(tminus)
            self.requestStatus.configure(text=f"You'll receive their items in {tminus.days+1} day(s)")
            return

        #their_items = self.wks.cell(5,benf).value
        their_items = self.download_input(benf)
        if their_items == None:
            tk.messagebox.showinfo("Empty",f"No items found in {their_name}'s library")
            return
        visible = DataEncryption.decrypt_fast(RSA_decryption(data["items"].encode("latin-1"),self.private_key),their_items)
        #print(visible)
        self.to_csv(lst=json.loads(visible),perp=their_name)

    def send_to_iheritor(self):
        email_regex = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
        users = self.wks.row_values(1)
        successText = "Passwords shared successfully"
        warningFg = "green"

        if (self.yourEmail["fg"] == "grey") or (self.contact["fg"] == "grey"):
            self.warningLabel.configure(text="All fields must be filled",fg="red")
            return
        if (self.yourEmail.get() == "") or (self.contact.get() == ""):
            self.warningLabel.configure(text="All fields must be filled",fg="red")
            return
        if not email_regex.match(self.yourEmail.get()):
            self.warningLabel.configure(text="Enter a valid email",fg="red")
            return
        if users.index(self.contact.get()) + 1 == self.myindex:
            self.warningLabel.configure(text="Inheritor can't be yourself",fg="red")
            return
        if not bool(users.count(self.contact.get())):
            self.warningLabel.configure(text="User does not exist",fg="red")
            return

        self.inheritor_index = users.index(self.contact.get()) + 1
        self.inheritor_public_key = rsa.PublicKey.load_pkcs1(self.wks.cell(3,self.inheritor_index).value)

        inherit_cell = self.wks.cell(6,self.inheritor_index).value
        ref_cell = self.wks.cell(7,self.myindex).value
        items = json.dumps(Preset.obj_list_to_dict(added_items))
        myKey = DataEncryption.derive_key(self.inputed_password.encode(),self.salt.encode("latin-1"))
        encr_data = RSA_encryption(myKey,self.inheritor_public_key)
        data = {"benf_email":RSA_encryption(self.yourEmail.get().encode("latin-1"),self.inheritor_public_key).decode("latin-1"),
        "timer":None,
        "items":encr_data.decode("latin-1")}

        inheritor_id = {"contact":self.contact.get(),"email":self.yourEmail.get()}

        if ref_cell != None:
            ref_cell = json.loads(DataEncryption.decrypt(self.inputed_password,ref_cell.encode(),self.salt.encode("latin-1")))

            if ref_cell["contact"] != inheritor_id["contact"]:
                oi_index = users.index(ref_cell["contact"])+1
                old_inheritor = json.loads(self.wks.cell(6,oi_index).value)
                del old_inheritor[str(self.myindex)]
                self.wks.update_cell(6,oi_index,None if old_inheritor == {} else json.dumps(old_inheritor))

            elif ref_cell["email"] != inheritor_id["email"]:
                print("THE EMAIL IS NOT THE SAME")
                successText = "Email has changed"
                warningFg = "blue"
            else:
                self.warningLabel.configure(text=successText,fg=warningFg)
                print("Already there you fool")
                return

        if inherit_cell == None:
            self.wks.update_cell(6,self.inheritor_index,json.dumps({self.myindex:data}))
            inheritor_id = DataEncryption.encrypt_fast(self.inputed_password,json.dumps(inheritor_id),self.salt)
            self.wks.update_cell(7,self.myindex,inheritor_id.decode())
        else:
            inherit_cell = json.loads(inherit_cell)
            inherit_cell[str(self.myindex)] = data
            self.wks.update_cell(6,self.inheritor_index,json.dumps(inherit_cell))
            inheritor_id = DataEncryption.encrypt_fast(self.inputed_password,json.dumps(inheritor_id),self.salt)
            self.wks.update_cell(7,self.myindex,inheritor_id.decode())

        self.warningLabel.configure(text=successText,fg=warningFg)

    def save_msg(self,filename):
        tk.messagebox.showinfo("Saved", f"Passwords exported to \n {filename}")

    def downloadpasswords(self):
        toDownloads = pathlib.Path.home()/"Downloads"
        filename = toDownloads/"UnZipInCerra"
        tojson = json.dumps(Preset.obj_list_to_dict(added_items))
        #print(self.inputed_password,self.salt)
        newFile = DataEncryption.encrypt_fast(self.inputed_password,tojson,self.salt)

        buffer = io.BytesIO()
        if not os.path.exists(f"{filename}.zip"):

            with zipfile.ZipFile(buffer, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("salt.bin", self.salt.encode("latin-1"))
                zf.writestr("normal.bin", newFile)
            with open(f"{filename}.zip", "wb") as f:
                f.write(buffer.getvalue())
            print(f"Files zipped to '{filename}'.zip")
            self.save_msg(f"{filename}.zip")
        else:
            i = 1
            while os.path.exists(f"{filename}({i}).zip"):
                i += 1
            new_filename = f"{filename}({i}).zip"
            with zipfile.ZipFile(buffer, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("salt.bin", self.salt.encode("latin-1"))
                zf.writestr("normal.bin", newFile)
            with open(new_filename, "wb") as f:
                f.write(buffer.getvalue())
            print(f"Files zipped to '{new_filename}'")
            self.save_msg(new_filename)

    def to_csv(self,lst=None,perp="Cerra"):
        toDownloads = pathlib.Path.home()/"Downloads"
        filename = toDownloads/f"{perp} Passwords"
        if lst != None and lst:
            data = lst
        elif added_items:
            lst = added_items
            data = Preset.short_dicts(lst)
        else:
            tk.messagebox.showerror("Error","No items to export")
            return

        if not os.path.exists(f"{filename}.csv"):
            with open(f"{filename}.csv", 'w', newline='') as file:
                writer = csv.DictWriter(file, fieldnames=data[0].keys())
                writer.writeheader()
                for row in data:
                    writer.writerow(row)
            print(f"Data written to '{filename}'.csv")
            self.save_msg(f"{filename}.csv")
        else:
            i = 1
            while os.path.exists(f"{filename}({i}).csv"):
                i += 1
            new_filename = f"{filename}({i}).csv"
            with open(new_filename, 'w', newline='') as file:
                writer = csv.DictWriter(file, fieldnames=data[0].keys())
                writer.writeheader()
                for row in data:
                    writer.writerow(row)
            print(f"Data written to '{new_filename}'.")
            self.save_msg(new_filename)

    def from_csv(self):
        ans = tk.messagebox.askokcancel("Import CSV","Import from: "+os.getcwd()+"\Passwords.csv?")

        if not ans:
            return

        if not os.path.exists("Passwords.csv"):
            tk.messagebox.showerror("Error",os.getcwd()+"\Passwords.csv not found")
            return

        global added_items
        old_at = added_items.copy()

        with open("Passwords.csv", 'r') as file:
            try:
                reader = csv.DictReader(file)
            except Exception as err:
                tk.messagebox.showerror("Error",f"Unexpected Error: {err}")
            data = [row for row in reader]
            lst = ["name","username","url","password"]

            if data[0].keys() == list(options.values())[0].dictionary.keys():
                print("works")
                pass
            elif set(list(data[0].keys())) == set(lst):
                print("works")
                pass
            else:
                tk.messagebox.showerror("Error","Passwords.csv in wrong format, please refer to documentation")
                return

            print(list(data[0].values()))

            for p in data:
                if len(p) > 6:
                    obj_values = [val if val != None else "" for val in p.values()]
                    newItem = Preset(True if obj_values[0] == "True" else False,*obj_values[1:])
                else:
                    p = {key: value if value != None else "" for key, value in p.items()}
                    newItem = Preset(False,p["name"],p["username"],"",p["url"],p["password"],"password.png")

                added_items.append(newItem)

        try:
            self.save_all()
        except Exception as err:
            added_items = old_at
            tk.messagebox.showerror("Error",f"There was an error saving: {err}")
            return
        self.all_items()

    def openLegal(self):
        webbrowser.open("https://github.com/ffmech/Cerra/blob/main/LICENSE",new=1)

    def openHelp(self):
        webbrowser.open("https://github.com/ffmech/Cerra/blob/main/README.md",new=1)

    def search_item(self,e=None):
        self.canvas_x = 0
        self.canvas_y = 0
        querie = self.search_bar.get()

        if querie == "":
            self.all_items()
            return

        searched_objects = []
        for myobj in added_items:
            mylist = list(myobj.dictionary.values())[1:-1]
            newlist = [string for string in mylist if querie.lower() in string.lower()]
            if newlist != []:
                searched_objects.append(myobj)
                #print(newlist)

        #print(searched_objects)
        if searched_objects != []:
            self.all_items(jects=searched_objects)
        else:
            self.clear(self.frame2)

    def set_icons(self,jects,filter,category,ontrue):
        self.clear(self.frame2)
        main_frame = tk.Frame(self.frame2,bg="white")
        main_frame.pack(fill=tk.BOTH,expand=True)

        def set_poz():
            self.canvas_x = my_canvas.xview()[0]
            self.canvas_y = my_canvas.yview()[0]

        my_canvas = tk.Canvas(main_frame,bg="white")
        mx_scrollbar = ttk.Scrollbar(main_frame,orient=tk.HORIZONTAL,command=lambda *args:[my_canvas.xview(*args),set_poz()])
        mx_scrollbar.pack(side=tk.BOTTOM,fill=tk.X)
        my_scrollbar = ttk.Scrollbar(main_frame,orient=tk.VERTICAL,command=lambda *args:[my_canvas.yview(*args),set_poz()])
        my_scrollbar.pack(side=tk.RIGHT,fill=tk.Y)
        my_canvas.pack(side=tk.TOP,fill=tk.BOTH,expand=True)

        my_canvas.configure(yscrollcommand=my_scrollbar.set)
        my_canvas.configure(xscrollcommand=mx_scrollbar.set)

        def _on_mouse_wheel(event):
            shift = (event.state & 0x1) != 0
            scroll = -1 if event.delta > 0 else 1

            if shift:
                scroll = 0 if my_canvas.xview()[0] == 0. and event.delta > 0 else scroll
                my_canvas.xview_scroll(scroll, "units")
                self.canvas_x = my_canvas.xview()[0]
            else:
                scroll = 0 if my_canvas.yview()[0] == 0. and event.delta > 0 else scroll
                my_canvas.yview_scroll(scroll, "units")
                self.canvas_y = my_canvas.yview()[0]

        my_canvas.bind_all("<MouseWheel>", _on_mouse_wheel)
        second_frame = tk.Frame(my_canvas,bg="white")
        my_canvas.create_window((0,0),window=second_frame,anchor="nw")

        t = 0
        x = 0
        for item in jects:
            if not filter or (str(item.dictionary[category]).lower() == str(ontrue).lower()):
                itemShower(second_frame,item).grid(row=t,column=x,padx=10,pady=10)
                x += 1
                if x > 10:
                    t += 1
                    x = 0

        my_canvas.bind("<Configure>",lambda e: my_canvas.configure(scrollregion=my_canvas.bbox("all")))
        main_frame.bind("<Destroy>",lambda e: my_canvas.unbind_all("<MouseWheel>"))

        if not filter:
            my_canvas.update_idletasks()
            my_canvas.yview_moveto(self.canvas_y)
            my_canvas.xview_moveto(self.canvas_x)

    def all_items(self,filter=False,category="Card",ontrue=True,jects=None):
        if jects == None:
            jects = added_items

        self.toggle_view["state"] = "normal"
        if icon_view:
            self.set_icons(jects,filter,category,ontrue)
        else:
            self.tree_view(jects,filter,category,ontrue)

    def item_info(self,items):
        items_dict = items.dictionary
        self.toggle_view["state"] = "disabled"
        self.clear(self.frame2)
        portrait = tk.Frame(self.frame2, bg="white")
        self.class_items = items

        for i in list(items_dict.keys())[1:5]:
            frame = tk.Frame(self.frame2)
            frame.pack(pady=10,anchor="center")
            print(i)

            t = tk.Label(frame,text=items_dict[i],height=1,width=30,anchor="nw",font="Arial 24")
            t.label_text = items_dict[i]
            t.pack(side=tk.LEFT)
            copyButton(frame,t).pack(side=tk.RIGHT)

        last_frame = tk.Frame(self.frame2)
        last_frame.pack()
        data = "●"*len(items_dict["password"])
        #print(data)
        self.label_show = tk.Label(last_frame,text=data,height=1,width=30,anchor="nw",font="Arial 24")
        self.label_show.label_text = items_dict["password"]
        self.label_show.pack(side=tk.LEFT)
        copyButton(last_frame,self.label_show).pack(side=tk.RIGHT)

        delete = stripButton(portrait,"Delete",self.delete_obj,width=10,bg=btncolor,hbg="#6d2c2c")
        delete.pack(side=tk.RIGHT)
        self.button_show = stripButton(portrait,"Show",self.password_unveil,width=10,bg=btncolor,hbg="#6d2c2c")
        self.button_show.pack(side=tk.RIGHT,padx=10,pady=30)
        edit = stripButton(portrait,"Edit",lambda:self.add_form(update=True,itmobj=items),width=10,bg=btncolor,hbg="#6d2c2c")
        edit.pack(side=tk.RIGHT)
        portrait.pack()

    def password_unveil(self):
        if self.button_show["text"] == "Show":
            self.label_show["text"] = self.class_items.dictionary["password"]
            self.button_show.configure(text="Hide")
        else:
            self.label_show["text"] = "●"*len(self.label_show["text"])
            self.button_show.configure(text="Show")

    def tree_view(self,jects,filter=False,category="Card",ontrue=True):
        self.clear(self.frame2)
        self.tree_y = self.canvas_y

        def set_poz():
            self.canvas_y = self.tree.yview()[0]

        tree_scroll = tk.Scrollbar(self.frame2)
        tree_scroll.pack(side=tk.RIGHT,fill=tk.Y)

        self.tree = ttk.Treeview(self.frame2,show="headings",yscrollcommand=lambda *args:[tree_scroll.set(*args),set_poz()])
        self.tree["columns"] = ("Card","Name","Email","ID")

        tree_scroll.configure(command=self.tree.yview)

        for column in self.tree["columns"]:
            self.tree.column(column,anchor="w",width=100)
            self.tree.heading(column,text=column,anchor="w")

        self.tree.pack(expand=True,side=tk.LEFT,fill=tk.BOTH)

        for i in jects:
            if not filter or (str(i.dictionary[category]).lower() == str(ontrue).lower()):
                objlst = list(i.dictionary.values())[0:4]
                objlst.append(jects.index(i))
                #print(objlst)
                self.tree.insert("", "end", values=tuple(objlst))

        self.tree.bind("<Double-1>", lambda e:self.OnDoubleClick(jects))
        self.tree.update_idletasks()
        self.tree.yview_moveto(self.tree_y)

    def OnDoubleClick(self,jects):
        item = self.tree.selection()[0]
        print("you clicked on", self.tree.item(item,"values")[0])
        self.item_info(jects[int(self.tree.item(item,"values")[-1])])

    def folder_view(self):
        self.all_items(filter=True,category="Card",ontrue=False)

    def cards(self):
        self.all_items(filter=True)

    def windowfoc(self, e):
        try:
            self.loginWindow.focus_force()
        except Exception:
            pass
        else:
            winsound.PlaySound("SystemAsterisk", winsound.SND_ALIAS | winsound.SND_ASYNC)
            print("trouble")

    def closeSignin(self):
        self.loginWindow.destroy()
        self.changeState(self.frame,tk.NORMAL)

    def changeState(self,parent,state):
        for widget in parent.winfo_children():
            if isinstance(widget, tk.Button):
                widget["state"] = state

    def clear(self,parent):
        for child in parent.winfo_children():
            child.destroy()

    def vide(self):
        pass

    def add_form(self,update=False,itmobj=None):
        self.clear(self.frame2)
        self.toggle_view["state"] = "disabled"
        self.card_status = False
        self.itmobj = itmobj
        btn_cmd = self.create_item
        btn_text = "Add it"
        self.default_preview = "password.png"

        entryX = 100
        entryY = 40

        self.item_name = cerraEntry(self.frame2,entryX,entryY,"Item Name",16,200,14)
        self.email = cerraEntry(self.frame2,entryX,entryY+80,"email",16,200,14)
        self.nickname = cerraEntry(self.frame2,entryX,entryY+160,"Username",16,200,14)
        self.webaddress = cerraEntry(self.frame2,entryX,entryY+240,"URL",16,200,14)
        self.addpassword = cerraEntry(self.frame2,entryX,entryY+320,"Password",16,200,14,show="●")
        self.showbutton = eyeButton(self.frame2,300,360,self.addpassword)

        self.entries = [self.item_name,self.email,self.nickname,self.webaddress,self.addpassword]

        self.clicked = tk.StringVar()

        self.website_list = list(options.keys())
        #print(type(self.website_list))
        self.clicked.set("Presets")

        self.drop = tk.OptionMenu(self.frame2,self.clicked,*self.website_list,command=self.preset_form)
        self.drop.configure(width=8)
        self.drop.place(x=400,y=40)


        if update == True:
            self.card_status = itmobj.dictionary["Card"]
            btn_cmd = self.update_item_obj
            btn_text = "Update"
            self.default_preview = itmobj.dictionary["image"]
            self.clicked.set(itmobj.dictionary["Website"])
            if self.card_status:
                for entry,prompt in zip(self.entries,card_prompts):
                    entry.originaltext = prompt
                    if entry["fg"] == "grey":
                        rechange(entry)
                self.drop["state"] = "disabled"
            for entry,value in zip(self.entries,list(itmobj.dictionary.values())[1:-1]):
                if (value != None) and (value != ""):
                    entry.delete(0, "end")
                    entry["fg"] = "black"
                    entry.insert(0, value)
                    if entry.originaltext == "Password":
                        entry["show"] = "●"

        self.r = tk.IntVar()
        print(type(self.card_status),self.card_status)
        self.r.set(self.card_status+1)

        R1 = tk.Radiobutton(self.frame2,text="Password",variable=self.r,value=1,command=self.toggle_card,bg="white")
        R1.place(x=500,y=40)
        R2 = tk.Radiobutton(self.frame2,text="Bank Card",variable=self.r,value=2,command=self.toggle_card,bg="white")
        R2.place(x=600,y=40)

        try:
            thumbnail = tk.PhotoImage(file="icons/"+self.default_preview)
        except Exception:
            try:
                thumbnail = tk.PhotoImage(file="icons/notfound.png")
            except Exception:
                thumbnail = ""

        self.thumbnail_preview = tk.Label(self.frame2,image=thumbnail,bg="white")
        self.thumbnail_preview.image = thumbnail
        self.thumbnail_preview.place(x=500,y=150)

        self.webaddress.bind("<KeyRelease>", lambda a: self.callback(self.webaddress))
        self.item_name.bind("<KeyRelease>", lambda a: self.callback(self.item_name))

        self.add_it = cerraButton(self.frame2,405,350,18,15,btn_text,btn_cmd)
        cancel_btn = stripButton(self.frame2,"Cancel",self.all_items,bg="#dedede",hbg="#bdbdbd",font="Arial 9",width=8)
        cancel_btn.configure(height=2,fg="black")
        cancel_btn.place(x=630,y=350)

        generate_btn = stripButton(self.frame2,
            "Generate password",
            self.generate_password,
            bg="#dedede",
            hbg="#bdbdbd",
            font="Arial 9 bold",
            width=18)
        generate_btn.configure(height=1,fg="black")
        generate_btn.place(x=488,y=290)

    def generate_password(self):
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for i in range(16))

        if self.addpassword.showVariable == "●":
            self.addpassword["show"] = "●"

        self.addpassword["fg"] = "black"
        self.addpassword.delete(0,"end")
        self.addpassword.insert(0,password)

    def update_item_obj(self):
        global added_items
        old_at = added_items.copy()
        params = []
        for entry in self.entries:
            if entry["fg"] == "black":
                params.append(entry.get())
            else:
                params.append("")

        newobj = Preset(self.card_status,*params,self.default_preview)
        #print(newobj.dictionary)
        added_items[added_items.index(self.itmobj)] = newobj
        try:
            self.save_all()
        except Exception as err:
            added_items = old_at
            tk.messagebox.showerror("Error",f"There was an error saving: {err}")
            return
        self.all_items()

    def delete_obj(self):
        global added_items
        old_at = added_items.copy()
        answer = tk.messagebox.askquestion(
            "Delete",
            "Are you sure you want to delete this password? It can't be recovered after",
            icon="question"
        )
        if answer == "yes":
            added_items.remove(added_items[added_items.index(self.class_items)])
            try:
                self.save_all()
            except Exception as err:
                added_items = old_at
                tk.messagebox.showerror("Error",f"There was an error saving: {err}")
                return
            #print(added_items)
            self.all_items()

    def callback(self,e):
        try:
            a = options[self.clicked.get()].dictionary
        except KeyError:
            return

        if (self.clicked.get() != "" or "Presets") and (e.get() != a["url"]) and (self.r.get() == 1):
                self.clicked.set("")
                self.default_preview = "password.png"
                set_preview(self.thumbnail_preview,self.default_preview)

    def create_item(self):
        global added_items
        old_at = added_items.copy()
        lst = [self.card_status]
        for entry in self.entries:
            if entry["fg"] != "grey":
                lst.append(entry.get())
            else:
                lst.append("")

        lst.append(self.default_preview)
        #print(lst)
        new = Preset(*lst)
        added_items.append(new)
        #print(added_items)
        try:
            self.save_all()
        except Exception as err:
            added_items = old_at
            tk.messagebox.showerror("Error",f"There was an error saving: {err}")
            return
        self.all_items()

    def download_input(self,index):
        data = self.wks.cell(5,index).value

        if len(data) >= 49000:
            overflow_row = 8
            more_data = True

            while more_data:
                part = self.wks.cell(overflow_row,index).value

                if part == None:
                    more_data = False
                    break
                else:
                    data = data + part
                    overflow_row += 1

        return data

    def upload_input(self,data):
        max_size = 49000

        if len(data) > max_size:

            self.wks.update_cell(5,self.myindex,data[0:max_size])

            data_chunks = []
            for i in range(max_size,len(data),max_size):
                part = data[i:i+max_size]
                data_chunks.append(part)

            overflow_row = 8
            for i in data_chunks:
                self.wks.update_cell(overflow_row,self.myindex,i)
                overflow_row += 1

        else:
            self.wks.update_cell(5,self.myindex,data)

    def save_all(self):
        mylst = Preset.obj_list_to_dict(added_items)
        mystr = json.dumps(mylst,indent=4)
        if self.online:
            #print(self.inputed_password)
            encmystr = DataEncryption.encrypt_fast(self.inputed_password,mystr,self.salt)
            #self.wks.update_cell(5,self.myindex,encmystr.decode())
            self.upload_input(encmystr.decode())
        else:
            try:
                encmystr = DataEncryption.encrypt(self.inputed_password,mystr,"salt.bin")
            except IOError:
                DataEncryption.get_salt("salt.bin")
                encmystr = DataEncryption.encrypt(self.inputed_password,mystr,"salt.bin")

            self.salt = DataEncryption.get_salt("salt.bin",from_file=True).decode("latin-1")
            DataEncryption.save_to_file(encmystr,"normal.bin")

    def toggle_card(self):

        if self.r.get() == 2:
            self.card_status = True
            self.clicked.set(self.website_list[0])
            self.drop.configure(state="disabled")
            self.default_preview = "card.png"
            set_preview(self.thumbnail_preview,self.default_preview)

            for entry,prompt in zip(self.entries,card_prompts):
                entry.originaltext = prompt
                if entry["fg"] == "grey":
                    rechange(entry)

        elif self.r.get() == 1:
            self.card_status = False
            self.drop.configure(state="normal")
            self.default_preview = "password.png"
            set_preview(self.thumbnail_preview,self.default_preview)

            for entry,prompt in zip(self.entries,password_prompts):
                entry.originaltext = prompt
                if entry["fg"] == "grey":
                    rechange(entry)

        self.drop.focus()


    def preset_form(self,e):
        sticks = list(options[self.clicked.get()].dictionary.values())[1:6]

        image_file = options[self.clicked.get()].dictionary["image"]

        if image_file != None:
            self.default_preview = image_file
            set_preview(self.thumbnail_preview,self.default_preview)

        else:
            self.default_preview = "password.png"
            set_preview(self.thumbnail_preview,self.default_preview)

        for entry,value in zip(self.entries,sticks):

            if (value == None) or (value == ""):
                self.drop.focus()
                if (entry["fg"] == "grey") or (entry.get() == ""):
                    rechange(entry)
                if entry.originaltext == "Password":
                    entry.showVariable = "●"
                    self.showbutton["text"] = "show"
            else:
                entry.delete(0,"end")
                entry["fg"] = "black"
                entry.insert(0,value)
                if entry.originaltext == "Password":
                    entry["show"] = "●"
                    entry.showVariable = "●"
                    self.showbutton["text"] = "show"


def user_is_inactive():
    pyperclip.copy('')
    global e
    global added_items
    root.unbind_all('<Any-KeyPress>')
    root.unbind_all('<Any-ButtonPress>')
    added_items = []
    #print(added_items)
    root.deiconify()
    root.state("normal")
    root.geometry(f"{appwidth}x{appheight}+{int(globalx)}+{int(globaly)}")
    root.resizable(False, False)
    e.clear(root)
    e = Start(root)
    tk.messagebox.showinfo(title="Logged out", message="User logged out successfully")

timer = None
def reset_timer(event=None):
    global timer
    #print("unlog averted")

    if timer is not None:
        root.after_cancel(timer)

    timer = root.after(1800000, user_is_inactive)
#1800000

e = Start(root)
root.mainloop()
