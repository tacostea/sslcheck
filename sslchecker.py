import sys
import datetime
import re
import socket
import ssl
import OpenSSL
from mastodon import Mastodon
from logging import getLogger, basicConfig, DEBUG, WARN

mastodon = Mastodon(
    client_id="certchecker_clientcred.secret",
    access_token="certchecker_usercred.secret",
    api_base_url="https://don.tacostea.net")
basicConfig(filename="debug.log", level=DEBUG)
basicConfig(filename="error.log", level=WARN)
logger = getLogger(__name__)


def ssl_expiry_datetime(hostname):
    x509_date_fmt = r"b'%Y%m%d%H%M%SZ'"
    cert = ssl.get_server_certificate((hostname, 443))
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    return datetime.datetime.strptime(str(x509.get_notAfter()), x509_date_fmt)


def ssl_valid_time_remaining(hostname):
    expires = ssl_expiry_datetime(hostname)
    logger.debug("%s : %s", hostname, expires.isoformat())
    return expires - datetime.datetime.utcnow()


def ssl_expires_in(hostname, buffer_days=7):
    expires = ssl_expiry_datetime(hostname)
    logger.debug(hostname + " : " + expires.isoformat())
    remain = expires - datetime.datetime.utcnow()
    if remain.days >= -6 and remain.days <= buffer_days:
        if remain.days < 0 and remain.days >= -6 and remain.days % 2 == 0:
            message = "[OOPS] " + hostname + " : Cert has expired " + str(
                -1 * remain.days) + " day(s) ago!"
        elif remain.days == 0:
            message = "[WHY...]" + hostname + " : Admin are you kidding users? It's gone in 24 hour!"
        elif remain.days <= 3 and remain.days > 0:
            message = "[WARN] " + hostname + " : Cert will expire in " + str(
                remain.days) + " day(s)!"
        elif remain.days <= buffer_days and remain.days > 3 and remain.days % 2 == 0:
            message = "[INFO] " + hostname + " : Cert will expire in " + str(
                remain.days) + " day(s)"
        message += "\n Due: " + expires.strftime(
            '%Y-%m-%d %H:%M:%SZ') + "\n#tacobot"
        mastodon.toot(message)
        return True
    else:
        return False


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
