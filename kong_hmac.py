# kong_hmac.py

import base64
import hashlib
import hmac
import re
from wsgiref.handlers import format_date_time
from datetime import datetime
from time import mktime


def create_date_header():
    now = datetime.now()
    stamp = mktime(now.timetuple())
    return format_date_time(stamp)


def get_headers_string(signature_headers):
    headers = ""
    for key in signature_headers:
        if headers != "":
            headers += " "
        headers += key
    return headers


def get_signature_string(signature_headers):
    sig_string = ""
    for key, value in signature_headers.iteritems():
        if sig_string != "":
            sig_string += "\n"
        if key.lower() == "request-line":
            sig_string += value
        else:
            sig_string += key.lower() + ": " + value
    return sig_string


def md5_hash_base64(string_to_hash):
    m = hashlib.md5()
    m.update(string_to_hash)
    return base64.b64encode(m.digest())


def sha1_hash_base64(string_to_hash, secret):
    h = hmac.new(secret, (string_to_hash).encode("utf-8"), hashlib.sha1)
    return base64.b64encode(h.digest())


def generate_request_headers(key_id, secret, url, data=None, content_type=None):
    # Set the authorization header template
    auth_header_template = (
        'hmac username="{}",algorithm="{}",headers="{}",signature="{}"'
    )
    # Set the signature hash algorithm
    algorithm = "hmac-sha1"
    # Set the date header
    date_header = create_date_header()
    # Set headers for the signature hash
    signature_headers = {"date": date_header}

    # Determine request method
    if data is None or content_type is None:
        request_method = "GET"
    else:
        request_method = "POST"
        # MD5 digest of the content
        base64md5 = md5_hash_base64(data)
        # Set the content-length header
        content_length = str(len(data))
        # Add headers for the signature hash
        signature_headers["content-type"] = content_type
        signature_headers["content-md5"] = base64md5
        signature_headers["content-length"] = content_length

    # Strip the hostname from the URL
    target_url = re.sub(r"^https?://[^/]+/", "/", url)
    # Build the request-line header
    request_line = request_method + " " + target_url + " HTTP/1.1"
    # Add to headers for the signature hash
    signature_headers["request-line"] = request_line

    # Get the list of headers
    headers = get_headers_string(signature_headers)
    # Build the signature string
    signature_string = get_signature_string(signature_headers)
    # Hash the signature string using the specified algorithm
    signature_hash = sha1_hash_base64(signature_string, secret)
    # Format the authorization header
    auth_header = auth_header_template.format(
        key_id, algorithm, headers, signature_hash
    )

    if request_method == "GET":
        request_headers = {"Authorization": auth_header, "Date": date_header}
    else:
        request_headers = {
            "Authorization": auth_header,
            "Date": date_header,
            "Content-Type": content_type,
            "Content-MD5": base64md5,
            "Content-Length": content_length,
        }

    return request_headers
