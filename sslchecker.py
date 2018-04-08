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
#  context = ssl.create_default_context() 
#  conn = context.wrap_socket(
#    socket.socket(socket.AF_INET),
#    server_hostname=hostname
#  )
#  conn.settimeout(3.0) 
#  conn.connect((hostname, 443))
#  ssl_info = conn.getpeercert() 
#  return datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt)
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
  if remaining < datetime.timedelta(days=3):
    mastodon.toot("[WARNING] " + hostname + " : Cert will expire in " + remaining + " day(s)!\n Due: " + expires)
  elif remaining < datetime.timedelta(days=buffer_days):
    mastodon.toot("[INFO] " + hostname + " : Cert will expire in " + remaining + " days\n Due: " + expires)
    return True
  else:
    return False

if __name__=='__main__':
  filename=sys.argv[1]
  f = open(filename)
  hostnames = f.readlines()
  f.close()
  
  for hostname in hostnames:
    hostname =  hostname.strip()
    try:
      ssl_expires_in(hostname)
    except Exception as e:
      e_str = re.sub(r'\[.+\]', "", str(e))
      #print(hostname,e)
      print("[ERROR] " + hostname + " : " + e_str)
