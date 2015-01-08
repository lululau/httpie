import re
import os.path
import httpie.sessions
import sqlite3
import os, shutil, tempfile
from urlparse import urlparse
import keyring
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

class BrowserCookie(object):
    def __init__(self, browser_name, *args, **kwargs):
        super(BrowserCookie, self).__init__(*args, **kwargs)
        self.cookies = []
        if re.match("^c", browser_name):
            self.load_chrome_cookies(browser_name)
        elif re.match("^s", browser_name):
            load_safari_cookies()
        elif re.match("^f", browser_name):
            load_firefox_cookies()

    def load_chrome_cookies(self, browser_name):

        if re.match(".*:", browser_name):
            _, prof_num = browser_name.split(":")
            profile = "Profile " + prof_num
        else:
            profile = "Default"
        cookie_filename = os.path.expanduser("~/Library/Application Support/Google/Chrome/%s/Cookies" % profile)
        tmpf = tempfile.NamedTemporaryFile()
        shutil.copy2(cookie_filename, tmpf.name)
        cookie_filename = tmpf.name
        db = sqlite3.connect(cookie_filename)
        cur = db.cursor()
        cur.execute('select host_key, path, name, value, encrypted_value, expires_utc, secure from Cookies')
        while True:
            row = cur.fetchone()
            if not row:
                break
            self.cookies.append({"domain": row[0], "path": row[1], "name": row[2], "value": row[3], "encrypted_value": row[4], "expires": row[5], "secure": row[6] == 1})
        db.close()

    def get_session(self, url):
        cookies = {}

        passwd = keyring.get_password('Chrome Safe Storage', 'Chrome').encode('utf-8')

        def decrypt_value(ev):
            salt = b'saltysalt'
            iv = b' ' * 16
            length = 16
            iterations = 1003
            key = PBKDF2(passwd, salt, length, iterations)
            ev = ev[3:]
            decrypted = AES.new(key, AES.MODE_CBC, IV=iv).decrypt(ev)
            return decrypted[:-ord(decrypted[-1])].decode('utf-8')

        def get_value(v, ev):
            if v or (ev[:3] != b'v10'):
                return v
            else:
                return decrypt_value(ev)
       
        parse_res = urlparse(url)
        hostname = parse_res.netloc.split(":")[0]
        path = parse_res.path
        for c in self.cookies:
            if path.startswith(c['path']):
                if c['domain'].startswith("."):
                    if hostname.endswith(c['domain']):
                        cookies[c['name']] = {
                            "expires": c['expires']/1000000-11644473600,
                            "path": c['path'],
                            "secure": c['secure'],
                            "value": get_value(c['value'], c['encrypted_value'])
                        }
                else:
                    if c['domain'] == hostname:
                        cookies[c['name']] = {
                            "expires": c['expires']/1000000-11644473600,
                            "path": c['path'],
                            "secure": c['secure'],
                            "value": get_value(c['value'], c['encrypted_value'])
                        }

        session = httpie.sessions.Session(None)
        hsh = {
            "__meta__": {
                "about": "HTTPie session file",
                "help": "https://github.com/jkbr/httpie#sessions",
                "httpie": "0.8.0"
            },
            "auth": {
                "password": None,
                "type": None,
                "username": None
            },
            "cookies": cookies,
            "headers": {}
        }
        session.update(hsh)
        return session
