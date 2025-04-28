import os
import json
import base64
import win32crypt
import tempfile
import shutil
from Crypto.Cipher import AES
import sqlite3
def getBrowser():
    Envpath = os.environ.get('LOCALAPPDATA')
    browserdata=[{
        "name":"edge", 
        "masterkey":Envpath+r"\Microsoft\Edge\User Data\Local State",
        "browserPass":Envpath+r"\Microsoft\Edge\User Data\Default\Login Data"
        },
          {
        "name":"google",
        "masterkey":Envpath+r"\Google\Chrome\User Data\Local State",
        "browserPass":Envpath+r"\Google\Chrome\User Data\Default\Login Data"
        }       ]
    for browserData in browserdata:
        print(browserData["browserPass"])
        if not os.path.exists(browserData["browserPass"]):
            print(f"{browserData["name"]}浏览器文件夹不存在")
            return
        if not os.path.exists(browserData["masterkey"]):
            print("主密钥文件不存在")
        masterkey = readMasterkey(browserData["masterkey"])
        if not masterkey:
            print("主密钥获取失败")
        else:
            print("成功获取主密钥")
        temp = tempfile.NamedTemporaryFile(delete=False).name
        try:
            shutil.copy2(browserData["browserPass"],temp)
        except Exception as e:
            print(f"复制数据库失败{e}")
        try:
            conn=sqlite3.connect(temp)
            cursor=conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            rows=cursor.fetchall()
            lenth = len(rows)
            succ = 0
            for url,username,password in rows:
                plaintext=decryptFuc(password,masterkey)
                if plaintext:
                    succ+=1
                print(f"url:{url}")
                print(f"用户名:{username}")
                print(f"密码:{plaintext}")
                print("-------------------------------------")
                print("-------------------------------------")
            print(f"共找到{lenth}条记录，成功解密{succ}条")
            
            
        except Exception as e:
            print(f"sqlite3 错误:{e}")
            
            
        
        
def readMasterkey(masterkeyPath):
    with open(masterkeyPath,"r",encoding="utf-8") as f:
        local_stat=json.load(f)
    encryptD=base64.b64decode(local_stat["os_crypt"]["encrypted_key"])
    encryptD=encryptD[5:]
    #win32crypt.CryptUnprotectData返回一个数组，我需要第二个值
    decryptD=win32crypt.CryptUnprotectData(encryptD,None,None,None,0)[1]
    return decryptD
def decryptFuc(cipher,masterkey):
    if not cipher:
        return "[密码为空]"
    if cipher[:3] == b"v10":
        if not masterkey:
            return "[v-10缺乏密钥]"
        iv = cipher[3:15]  # 12字节IV
        data=cipher[15:-16]
        tag=cipher[-16:]
        #AES
        try:
            aes = AES.new(masterkey,AES.MODE_GCM,iv)
            plainText=aes.decrypt_and_verify(data,tag)
            return plainText.decode("utf-8")
        except Exception as e:
            return f"[AES解密失败:{e}]"
    else:
        try:
            plainText=win32crypt.CryptUnprotectData(cipher,None,None,None,0)[1]
            return plainText.decode("utf-8")
        except Exception as e:
            return f"[DPAPI解密失败:{e}]"
    
    
    
    
if __name__ == "__main__":
    getBrowser()
