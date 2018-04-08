import sys
import datetime
import re
import socket
import ssl
import OpenSSL
from mastodon import Mastodon 
from logging import getLogger, StreamHandler, DEBUG

mastodon = Mastodon(
  client_id="certchecker_clientcred.secret",
  access_token="certchecker_usercred.secret",
  api_base_url = "https://don.tacostea.net"
)
logger = getLogger(__name__)
handler = StreamHandler()
handler.setLevel(DEBUG)
logger.setLevel(DEBUG)
logger.addHandler(handler)
logger.propagate = False
 
def ssl_expiry_datetime(hostname):
  x509_date_fmt = r"b'%Y%m%d%H%M%SZ'"
  cert=ssl.get_server_certificate((hostname, 443))
  x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
  return datetime.datetime.strptime(str(x509.get_notAfter()), x509_date_fmt)

def ssl_valid_time_remaining(hostname):
  expires = ssl_expiry_datetime(hostname) 
  logger.debug( "%s : %s",
    hostname,
    expires.isoformat()
  )
  return expires - datetime.datetime.utcnow()

def ssl_expires_in(hostname, buffer_days=7):
  expires = ssl_expiry_datetime(hostname)
  print(hostname, expires)
  remaining = expires - datetime.datetime.utcnow()
  if remaining.days < 0 and remaining.days >= -7:
    mastodon.toot("[OOPS] " + hostname + " : Cert has expired " + str(remaining.days) + " days ago!\n Due: " + expires.strftime('%Y-%m-%d %H:%M:%SZ'))
  elif remaining.days <= 3 and remaining.days >= 0:
    mastodon.toot("[WARN] " + hostname + " : Cert will expire in " + str(remaining.days) + " day(s)!\n Due: " + expires.strftime('%Y-%m-%d %H:%M:%SZ'))
  elif remaining.days <= buffer_days and remaining.days > 3:
    mastodon.toot("[INFO] " + hostname + " : Cert will expire in " + str(remaining.days) + " days\n Due: " + expires.strftime('%Y-%m-%d %H:%M:%SZ'))
    return True
  else:
    return False

if __name__=='__main__':
  filename=sys.argv[1]
  f = open(filename)
  hostnames = f.readlines()
  f.close()
  
  f = open('error.log', 'w+')
  for hostname in hostnames:
    hostname =  hostname.strip()
    try:
      ssl_expires_in(hostname)
    except Exception as e:
      e_str = re.sub(r'\[.+\]', "", str(e))
      #print(hostname,e)
      f.write( hostname + " : " + e_str)
  f.close()
