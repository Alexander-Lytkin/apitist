import collections
import dataclasses
import io
from urllib import parse
import requests
import hashlib
import json
import os.path
from pendulum import DateTime
import hmac
from datetime import datetime
from dataclasses import dataclass
from urllib.parse import quote
import re
from cattr import Converter
import attr
from requests.models import PreparedRequest

"""Canonical headers"""
HOST_HEADER = "host"
AUTHORIZATION_HEADER = "x-hmac-authorization-content-sha256"
DATE_HEADER = "x-hmac-authorization-date"


class CanonicalRequest:

    def __init__(self, prep_request, hmac_key, hmac_path_replacer):
        self.signature = None
        self.string_to_sign = None
        self.canonical_request = None
        self.signed_headers = None
        self.hashed_payload = None
        self.timestamp = None
        self.hmac_path_replacer = hmac_path_replacer
        self.prep_request = prep_request
        self.hmac_key = hmac_key

    def make_canonical_request(self):
        self.timestamp = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        if isinstance(self.prep_request.body, bytes):
            self.body = self.prep_request.body
        if isinstance(self.prep_request.body, str):
            self.body = self.prep_request.body.encode()
        if isinstance(self.prep_request.body, io.BufferedReader):
            self.body = self.prep_request.body.read(-1)
            self.prep_request.body = io.BytesIO(self.body)
        if self.prep_request.body is not None and hasattr(self, 'body'):
            self.hashed_payload = hashlib.sha256(self.body).hexdigest()
        else:
            self.hashed_payload = hashlib.sha256(''.encode()).hexdigest()

        canonical_request = f"{self.prep_request.method}\n" \
                            f"{self.get_canonical_path(self.prep_request.path_url)}\n"

        query = parse.urlparse(self.prep_request.path_url).query
        if query:
            params_list = []
            query_list = parse.parse_qs(query, True)
            for key, values in query_list.items():
                for value in values:
                    params_list.append(f'{quote(key)}={quote(value, "")}'.replace('%20', '+'))

            params_list.sort()
            canonical_request += '&'.join(params_list)
        canonical_request += "\n"

        if "Host" in self.prep_request.headers:
            canonical_request += f"{HOST_HEADER}:{self.prep_request.headers['Host']}\n"
        else:
            canonical_request += f"{HOST_HEADER}:{parse.urlparse(self.prep_request.url).netloc}\n"
        canonical_request += f"{AUTHORIZATION_HEADER}:{self.hashed_payload}\n"
        canonical_request += f"{DATE_HEADER}:{self.timestamp}\n"
        canonical_request += "\n"

        self.signed_headers = sorted([HOST_HEADER, AUTHORIZATION_HEADER, DATE_HEADER])
        for signed_header in self.signed_headers:
            canonical_request += f"{signed_header};"
        canonical_request = canonical_request[0:-1]  # Срез нужен, чтобы удалить последний знак ";"
        canonical_request += "\n"

        canonical_request += self.hashed_payload

        self.canonical_request = canonical_request

    def set_hmac(self):
        self.string_to_sign = "AC-HMAC-SHA256\n" \
                              f"{self.timestamp}\n\n" \
                              f"{hashlib.sha256(self.canonical_request.encode()).hexdigest()}"
        self.signature = hmac.new(self.hmac_key.encode(),
                                  self.string_to_sign.encode(), hashlib.sha256).hexdigest()

    def get_headers_for_hmac(self):
        self.make_canonical_request()
        self.set_hmac()
        authorization = f'AC-HMAC-SHA256 ' \
                        f'SignedHeaders="{HOST_HEADER};{AUTHORIZATION_HEADER};{DATE_HEADER}", ' \
                        f'Signature="{self.signature}"'
        headers = {
            'X-Hmac-Authorization': authorization,
            'X-Hmac-Authorization-Content-Sha256': self.hashed_payload,
            'X-Hmac-Authorization-Date': self.timestamp
        }
        return headers

    def get_canonical_path(self, url):
        path = parse.urlparse(url).path
        if self.hmac_path_replacer:
            path = self.hmac_path_replacer(path)

        return path
