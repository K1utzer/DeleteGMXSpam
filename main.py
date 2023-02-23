import json
from email.utils import parseaddr
from email.header import decode_header
from email.parser import Parser
import poplib
import ssl
import socket
from tqdm import tqdm

poplib._MAXLINE = 20480

def readEmails():
    with open("emails.json", "r") as f:
        emailAccs = f.read()
    emailAccs = json.loads(emailAccs)
    return emailAccs['emails'], emailAccs['passwords']

def readBlacklist() -> list:
    with open("blacklist.txt", "r") as f:
        blacklist = f.read().split("\n")
    return blacklist

def login(email, password):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    server = poplib.POP3_SSL('pop.gmx.net', port=995, context=context)
    server.user(email)
    server.pass_(password)
    return server

def checkForSpamMails(server, to_email):
    blacklist = readBlacklist()
    _, mails, _ = server.list()
    for c in tqdm(range(1, len(mails)+1), f"Checking: {to_email}"):
        try:
            _, lines, _ = server.retr(c)
            msg_content = b'\r\n'.join(lines).decode(errors="ignore")
            msg = Parser().parsestr(msg_content)
            email_from = msg.get('From')
            for email in blacklist:
                if (email in email_from):
                    server.dele(c)
                    print(f"Delete: {c}; Email: {email_from}")
        except poplib.error_proto:
            pass
        except Exception as e:
            raise e

def startCheck():
        emails, passwords = readEmails()
        for email, password in zip(emails, passwords):
            server = login(email, password)
            checkForSpamMails(server, email)
            server.quit()

startCheck()