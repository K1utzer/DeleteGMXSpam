from email.utils import parseaddr
from email.header import decode_header
from email.parser import Parser
from tqdm import tqdm
import json
import poplib
import ssl
import concurrent.futures
import os
import pathlib

pfad = f"{os.path.dirname(pathlib.Path(__file__).parent.resolve())}"

poplib._MAXLINE = 20480

def readEmails():
    with open(f"{pfad}\\emails.json", "r") as f:
        emailAccs = f.read()
    emailAccs = json.loads(emailAccs)
    return emailAccs['emails'], emailAccs['passwords']

def readBlacklist() -> list:
    with open("blacklist.txt", "r") as f:
        blacklist = f.read().split("\n")
    return blacklist

def login(email, password):
    server = poplib.POP3_SSL('pop.gmx.net', port=995)
    server.user(email)
    server.pass_(password)
    return server

def checkForSpamMails(email, password):
    server = login(email, password)
    blacklist = readBlacklist()
    mails, _ = server.stat()
    for c in tqdm(range(mails+1, 1, -1), f"Checking: {email}"):
        try:
            _, lines, _ = server.retr(c)
            msg_content = b'\r\n'.join(lines).decode(errors="ignore")
            msg = Parser().parsestr(msg_content)
            email_from = msg.get('From')
            for email in blacklist:
                if (email in email_from):
                    server.dele(c)
        except poplib.error_proto:
            pass
        except ssl.SSLError:
            #TODO: fix this error
            pass
        except Exception as e:
            raise e
    server.quit()

def startCheck():
        emails, passwords = readEmails()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            for email, password in zip(emails, passwords):
                executor.submit(
                    checkForSpamMails, email, password)

startCheck()