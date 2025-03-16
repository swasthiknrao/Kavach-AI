import ssl
import socket

class SSLValidator:
    def validate(self, url):
        return url.startswith('https://') 