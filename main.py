import PySimpleGUI as sg
import pyAesCrypt
import cryptocode
import os
import shutil
import io

import pyperclip
import hashlib
import requests
import re
import json
import base64
import secrets,string
global temp_directory

current_directory = os.getcwd()
temp_directory = os.path.join(current_directory, r'temp')
if not os.path.exists(temp_directory):
   os.makedirs(temp_directory)


def encrypt_file(file,password):
    enc=file+".enc"
    pyAesCrypt.encryptFile(file, enc, password)
    return enc

def encrypt_text(text,password):
    myEncryptedMessage = cryptocode.encrypt(text, password)
    return myEncryptedMessage

def decrypt_text(text,password):
    ddMessage =  cryptocode.decrypt(text, password)
    return ddMessage

def total_text_encrypt(text,password):
    text=encrypt_text(text, password)
    text=base64.b64encode(bytes(text,'utf-8'))
    return text.decode('utf-8')

def total_text_decrypt(text,password):
    text=base64.b64decode(text).decode('utf-8')
    text=decrypt_text(text, password)
    return text

def decrypt_file(file,password):
    nonenc=file[:-4]
    try:
        pyAesCrypt.decryptFile(file, nonenc, password)
        return nonenc
    except ValueError:
        return "ERRORPASS"
    

def progress_bar():
    sg.theme('LightBlue2')
    layout = [[sg.Text('Creating your account...')],
            [sg.ProgressBar(1000, orientation='h', size=(20, 20), key='progbar')],
            [sg.Cancel()]]

    window = sg.Window('Working...', layout)
    for i in range(1000):
        event, values = window.read(timeout=1)
        if event == 'Cancel' or event == sg.WIN_CLOSED:
            exit()
        window['progbar'].update_bar(i + 1)
    window.close()

def passgen():
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(16))
    return password


def savepass(win,file,password):
    layout = [[sg.Text("Password Manager - Save Password", font=50)],
            [sg.Text("Website", font=16),sg.InputText(key='-Website-', font=16)],
            [sg.Text("Email", font=16),sg.InputText(key='-Email-', font=16)],
            [sg.Text("Password", font=16),sg.InputText(key='-Pass-', password_char='*', font=16), sg.Button('Generate Password',font=7)],
            [sg.Text("Additional Notes", font=16),sg.InputText(key='-notes-', font=16)],
            [sg.Button('Save', font=15),sg.Button("Cancel",font=15)],
            ]
    window = sg.Window("Password Manager", layout,size=(850, 500))
    while True:
        event,values = window.read()
        if event == 'Cancel' or event == sg.WIN_CLOSED:
            window.close()
            break
        elif event == 'Generate Password':
            p=passgen()
            window['-Pass-'].update(p, password_char='')
        else:
            if event=="Save":
                W=values['-Website-']
                E=total_text_encrypt(values['-Email-'],password)
                P=total_text_encrypt(values['-Pass-'],password)
                N=total_text_encrypt(values['-notes-'],password)
                if N==" " or N=="":
                    N="None"
                W=W.capitalize()
                d={
                    W: {
                        "username": E,
                        "password":P,
                        "note":N,
                    },
                }
            fp = open(file,"r")
            data = json.load(fp)
            data.update(d)
            fp.close()
            fp=open(file,"w")
            json.dump(data, fp, indent=4)
            fp.close()
            sg.Popup('Password Saved Successfully', keep_on_top=True)
            window.close()

def close_vault(win,file,password):
    win.close()
    sg.theme("LightBlue2")
    encrypt_file(file,password)
    os.remove(file)
    sg.Popup('Vault Closed Successfully', keep_on_top=True)

def popup(text,email,passw,note):
    sg.theme("LightBlue2")
    layout = [[sg.Text(text, font=25,)],
    [sg.Button('OK'),sg.Button('Copy email to clipboard'),sg.Button('Copy Password to clipboard'), sg.Button('Copy Note to clipboard')],
    ]
    window = sg.Window('Password', layout)
    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, 'OK'):
            window.close()
            break
        elif  event=="Copy email to clipboard":
            pyperclip.copy(email)
        elif  event=="Copy Password to clipboard":
            pyperclip.copy(passw)
        elif  event=="Copy Note to clipboard":
            pyperclip.copy(note)


def viewpasswords(win, file,password):
    with open(file, encoding='utf-8') as json_file:
        data = json.load(json_file)
    td=[]
    wnames=[]
    for x in data:
        d=data.get(x)
        dd={
            "W":x,
            "E":d.get("username"),
            "P":d.get("password"),
            "N":d.get("note")
        }
        wnames.append(x.lower())
        td.append(dd)
    ctd=[]
    for x in td:
        dd={
            "W":x.get("W"),
            "E":total_text_decrypt(x.get("E"),password),
            "P":total_text_decrypt(x.get("P"),password),
            "N":total_text_decrypt(x.get("N"),password)
        }
        ctd.append(dd)
    sg.theme("LightBlue2")
    new_dict = {item['W']:item for item in ctd}
    layout = [[sg.Text("Password Manager - Website Search", font=40,)],
          [sg.Input(font=16, size=(50),enable_events=True, key='-INPUT-')],
          [sg.Listbox(wnames, size=(50,15),font=16, enable_events=True, key='-LIST-')],
          [sg.Button('Exit')]]
    window = sg.Window('Listbox with Search', layout,size=(600,500))
    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, 'Exit'):
            window.close()
            break
        if values['-INPUT-'] != '':                 
            search = values['-INPUT-'].lower()
            new_values = [x for x in wnames if search in x]
            window['-LIST-'].update(new_values)
        else:
            window['-LIST-'].update(wnames)
        if event == '-LIST-' and len(values['-LIST-']):
            ff=f"Website: {values['-LIST-'][0].capitalize()}\nEmail: {(new_dict.get(values['-LIST-'][0].capitalize())).get('E')}\nPassword: {(new_dict.get(values['-LIST-'][0].capitalize())).get('P')}\nNote: {(new_dict.get(values['-LIST-'][0].capitalize())).get('N')}"
            popup(ff,(new_dict.get(values['-LIST-'][0].capitalize())).get('E'),(new_dict.get(values['-LIST-'][0].capitalize())).get('P'),(new_dict.get(values['-LIST-'][0].capitalize())).get('N'))

def use_regex(input_text,s):
    pattern = re.compile(fr"{s}:[0-9]+", re.IGNORECASE)
    b=pattern.search(input_text)
    if b:
        return (b.group(0))
    else:
        return "None"

def pwnedpasswords(win, file,password):
    with open(file, encoding='utf-8') as json_file:
        data = json.load(json_file)
    pp=[]
    for x in data:
        d=data.get(x)
        pp.append(total_text_decrypt(d.get("password"),password))
    anyBreach=False
    breachList=[]
    for x in pp:
        d = hashlib.sha1(bytes(x,"utf-8"))
        hash=d.hexdigest()
        f=hash[:5]
        s=hash[5:]
        headers = {
            'Accept': 'application/vnd.haveibeenpwned.v2+json'
        }
        r=requests.get(f"https://api.pwnedpasswords.com/range/{f}")
        r=r.text
        txt= use_regex(r,s.upper())
        if txt==None or txt=="None":
            pass
        else:
            txt=txt.split(":")[1]
            anyBreach=True
            breachList.append([x,txt])
    if anyBreach:
        text="Pwned Passwords\tPwned Count\n"
        layout = [[sg.Table(values=breachList, headings=["Pwned Passwords","Pwned Count"], max_col_width=25,
                    auto_size_columns=True,
                    display_row_numbers=True,
                    justification='center',
                    num_rows=20,
                    alternating_row_color='lightblue',
                    key='-TABLE-',
                    selected_row_colors='red on yellow',
                    enable_events=True,
                    expand_x=False,
                    expand_y=True,
                    vertical_scroll_only=False,
                    enable_click_events=True,
                    tooltip='This is a table')],
          [sg.Button('OK')]]
        window = sg.Window('The Table Element', layout,resizable=True)
        while True:
            event, values = window.read()
            if event == sg.WIN_CLOSED or event=="OK":
                window.close()
                break
def manager(win, file,password):
    win.close()
    sg.theme("LightBlue2")
    layout = [[sg.Text("Password Manager", font=40)],
            [sg.Button("Save A Password", size =(50,4), font=40, key="save")],
            [sg.Button("View Saved Passwords", size =(50,4), font=40, key="viewpasswords")],
            [sg.Button("My Passwords Pwned?", size =(50,4), font=40, key="pwnedpasswords")],
            [sg.Button("Close the vault", size =(50,4), font=40, key="close")]
            ]
    window = sg.Window("Password Manager", layout,size=(500, 450))
    while True:
        event,values = window.read()
        if event == 'Cancel' or event == sg.WIN_CLOSED:
            break
        else:
            if event == "save":
                savepass(window, file, password)
            elif event=="viewpasswords":
                viewpasswords(window, file, password)
            elif event=="close":
                close_vault(window,file,password)
            elif event=="pwnedpasswords":
                pwnedpasswords(window,file,password)



def login(win):
    win.close()
    sg.theme("LightBlue2")
    if os.path.isfile('config.json'):
        with open('config.json', 'r') as fcc_file:
            fcc_data = json.load(fcc_file)
        l=(fcc_data.get("location"))
        
        layout = [[sg.Text("Password Manager - Log In", font=40)],
                [sg.Text(f"Vault Location: {str(l)}", font=16)],
                [sg.Text("Password", font=16),sg.InputText(key='-password-', password_char='*', font=16)],
                [sg.Button('Login'),sg.Button('Cancel')]]
        window = sg.Window("Log In", layout)
        while True:
            event,values = window.read()
            if event == "Cancel" or event == sg.WIN_CLOSED:
                    break
            else:
                if event == "Login":
                    password=values['-password-']
                    shutil.copy2(l,temp_directory)
                    p=decrypt_file(l,password)
                    if p=="ERRORPASS":
                        sg.Popup('Wrong Password!', keep_on_top=True)
                    else:
                        os.remove(l)
                        manager(window,p,password)

    else: 
        layout = [[sg.Text("Password Manager - Log In", font=40)],
                [sg.Text("Select Vault:", size =(15, 1), font=16), sg.Input(key='vaultaddress'), sg.FileBrowse('FileBrowse', )],
                [sg.Text("Password", size =(15, 1), font=16),sg.InputText(key='-pwd-', password_char='*', font=16)],
                [sg.Button('Login', font=7),sg.Button('Cancel',font=7)]]

        window = sg.Window("Log In", layout)

        while True:
            event,values = window.read()
            if event == "Cancel" or event == sg.WIN_CLOSED:
                break
            else:
                if event == "Login":
                    password=values['-pwd-']
                    l=values['vaultaddress']
                    shutil.copy2(l,temp_directory)
                    p=decrypt_file(l,password)
                    os.remove(l)
                    if p=="ERRORPASS":
                        sg.Popup('Wrong Password!', keep_on_top=True)
                    else:
                        manager(window,p)

        window.close()

def create_account(win):
    win.close()
    layout = [[sg.Text("Create Vault", size =(15, 1), font=40, justification='c')],
              [sg.Text("Vault Location:", size =(15, 1), font=16), sg.Input(key='vaultaddress'), sg.FolderBrowse('FolderBrowse', )],
             [sg.Text("Create Password", size =(15, 1), font=16), sg.InputText(key='-password-', font=16, password_char='*')],
             [sg.Button("Submit"), sg.Button("Cancel")]]

    window = sg.Window("Password Manager - Create Vault", layout)

    while True:
        event,values = window.read()
        if event == 'Cancel' or event == sg.WIN_CLOSED:
            break
        else:
            if event == "Submit":
                password = values['-password-']
                vaultaddress = values['vaultaddress']
                progress_bar()
                if vaultaddress == "" or vaultaddress == " ":
                    vaultaddress = os.getcwd()
                locn=f'{vaultaddress}/vault.db'
                fp = open(locn, 'w')
                fp.write("{}")
                fp.close()
                el=encrypt_file(locn,password)
                os.remove(locn)
                fp=open("config.json","w")
                json.dump({"location":el}, fp)
                fp.close()
                window.close()
                layout=[[sg.Text("Vault Created.", size =(15, 1), font=40)], [sg.Button("Login to the vault", size =(50), font=40, key="login")], [sg.Button("Cancel", size =(50))]]
                window = sg.Window("Password Manager", layout,size=(300, 200))
                while True:
                    event,values = window.read()
                    if event == 'Cancel' or event == sg.WIN_CLOSED:
                        break
                    else:
                        if event=="login":
                            login(window)

def main():
    global vaultaddress, password
    sg.theme('LightBlue2')
    layout = [[sg.Button("Create Vault", size =(50,8), font=40, key="create")],
    [sg.Button("Open a Existing Vault", size =(50,8), font=40, key="open")]]
    window = sg.Window("Password Manager", layout,size=(500, 450))
    while True:
        event,values = window.read()
        if event == 'Cancel' or event == sg.WIN_CLOSED:
            break
        else:
            if event == "create":
                create_account(window)
            elif event=="open":
                login(window)
main()