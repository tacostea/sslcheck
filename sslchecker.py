import sys
import datetime, pytz
import re
import socket
import ssl
import OpenSSL
import requests
from mastodon import Mastodon
from logging import getLogger, basicConfig, DEBUG, WARN

import psycopg2
import psycopg2.extras
import postgresql


mastodon = Mastodon(
    client_id="certchecker_clientcred.secret",
    access_token="certchecker_usercred.secret",
    api_base_url="https://don.tacostea.net")
basicConfig(filename="debug.log", level=DEBUG)
basicConfig(filename="error.log", level=WARN)
logger = getLogger(__name__)

db = postgresql("pq://postgres@localhost/instances")


def ssl_expiry_datetime(hostname):
    x509_date_fmt = r"b'%Y%m%d%H%M%SZ'"
    cert = ssl.get_server_certificate((hostname, 443))
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    dt = datetime.datetime.strptime(str(x509.get_notAfter()), x509_date_fmt)
    return pytz.utc.localize(dt)
    

def ssl_valid_time_remaining(hostname):
    expires = ssl_expiry_datetime(hostname)
    logger.debug("%s : %s", hostname, expires.isoformat())
    return expires - datetime.datetime.utcnow()

def dm_to_admin(hostname, expires, remain):
    url = "https://" + hostname + "/api/v1/instance"
    try:
      json = requests.get(url).json()
      if "contact_account" in json:
        acct = json['contact_account']['acct']
        mastodon.status_post("@" + acct + "@" + hostname + " Hello, this is automatic message from SSLCheck bot. The SSL Certification for your instance " + hostname + " looks expiring in 1 day.\nDue(UTC): " + expires.strftime('%Y-%m-%d %H:%M:%S') + "\n* If you want stop just messages like this or stop checking(fetching), reply me whichever you want.", visibility='direct')
    except Exception as e:
      print(url,e)

def ssl_expires_in(hostname, buffer_days=7):
    expires = ssl_expiry_datetime(hostname)
    
    insert_cert = db.prepare('UPDATE cert SET expiration = $2 WHERE uri = $1')
    insert_cert(hostname, expires)
    
    logger.debug(hostname + " : " + expires.isoformat())
    remain = expires - datetime.datetime.utcnow()
    if remain.days >= -6 and remain.days <= buffer_days:
        if remain.days < 0 and remain.days >= -6 and remain.days % 2 == 0:
            message = "[OOPS] " + hostname + " : Cert has expired " + str(-1 * remain.days) + " day(s) ago!"
        elif remain.days == 0:
            message = "[WHY...]" + hostname + " : Admin are you kidding users? It's gone in 24 hour!"
            dm_to_admin(hostname, expires, remain)
        elif remain.days <= 3 and remain.days > 0:
            message = "[WARN] " + hostname + " : Cert will expire in " + str(remain.days) + " day(s)!"
        #    dm_to_admin(hostname, expires, remain)
        elif remain.days <= buffer_days and remain.days > 3 and remain.days % 2 == 0:
            message = "[INFO] " + hostname + " : Cert will expire in " + str(remain.days) + " day(s)"
        message += "\n Due: " + expires.strftime('%Y-%m-%d %H:%M:%SZ') + "\n#tacobot"
        mastodon.status_post(message)
        return True
    else:
        return False

def select_host_will_expire(days=7):
  # access DB and get target hosts

  # check response code

  # if Name error, post it

  # if status is OK, call ssl_expires_in
  print(none)

if __name__ == '__main__':
    filename = sys.argv[1]
    f = open(filename)
    hostnames = f.readlines()
    f.close()

    for hostname in hostnames:
        hostname = hostname.strip()
        try:
            ssl_expires_in(hostname)
        except Exception as e:
            e_str = re.sub(r'\[.+\]', "", str(e))
            logger.warn(hostname + " : " + e_str)
