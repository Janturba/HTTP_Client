import socket
import ssl
import getpass
import base64
import tkinter as tk
from tkinter import ttk
import time
import gssapi
from ntlm_auth.ntlm import NtlmContext

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Proxy UA Tester')
        self.geometry('800x800')
        # Define style for inputs
        input_width = 80
        input_height = 1
        # Define host input box
        self.host = tk.Text(self, height=input_height, width=input_width)
        self.host.pack()
        self.host.insert(tk.END, "www.example.com")
        # Define server port input box
        self.port = tk.Text(self, height=input_height, width=input_width)
        self.port.pack()
        self.port.insert(tk.END, "443")
        # Define proxy
        self.proxy = tk.Text(self, height=input_height, width=input_width)
        self.proxy.pack()
        self.proxy.insert(tk.END, "proxy")
        # Define proxy port
        self.proxy_port = tk.Text(self, height=input_height, width=input_width)
        self.proxy_port.pack()
        self.proxy_port.insert(tk.END, "8080")
        # Define CONNECT UA
        self.connect_ua = tk.Text(self, height=input_height, width=input_width)
        self.connect_ua.pack()
        self.connect_ua.insert(tk.END, "CONNECT UA")
        # Define HTTP UA
        self.http_ua = tk.Text(self, height=input_height, width=input_width)
        self.http_ua.pack()
        self.http_ua.insert(tk.END, "HTTP UA")
        # Define scheme
        self.scheme = tk.Text(self, height=input_height, width=input_width)
        self.scheme.pack()
        self.scheme.insert(tk.END, "https")
        # Define Method
        self.method = tk.Text(self, height=input_height, width=input_width)
        self.method.pack()
        self.method.insert(tk.END, "GET")
        # Define path
        self.path = tk.Text(self, height=input_height, width=input_width)
        self.path.pack()
        self.path.insert(tk.END, "/")
        # Exit button
        tk.Button(self, text="Exit", command=self.exit_button)
        runMe = tk.Button(self, text="Run", command=self.call)
        runMe.pack()
        # Output
        self.output = tk.Text(self, width=input_width, height=20, fg="green", font=('arial', 13))
        self.output.pack()
        self.python_image = tk.PhotoImage(file='./UA_tester.gif')
        tk.Label(self, image=self.python_image).pack()

    def update_text(self):
        self.output.insert(tk.END, str(self.a) + "\t\n")

    def exit_button(self):
        exit()

    def call(self):
        host_string = self.host.get(1.0, "end-1c")
        host_port = self.port.get(1.0, "end-1c")
        proxy_string = self.proxy.get(1.0, "end-1c")
        proxy_port = self.proxy_port.get(1.0, "end-1c")
        connect_ua = self.connect_ua.get(1.0, "end-1c")
        http_ua = self.http_ua.get(1.0, "end-1c")
        scheme = self.scheme.get(1.0, "end-1c")
        method = self.method.get(1.0, "end-1c")
        path = self.path.get(1.0, "end-1c")
        self.call = proxyCall(host_string, int(host_port), proxy_string, int(proxy_port), connect_ua, http_ua,
                              scheme, method, path, tunneled="FALSE")
        self.a = self.call.get_socket()
        self.update_text()


class proxyCall():

    def __init__(self, *args, tunneled="FALSE"):
        self.HOST = args[0]
        self.PORT = args[1]
        self.PROXY = args[2]
        self.PROXY_PORT = args[3]
        self.CONNECT_UA = args[4]
        self.HTTP_UA = args[5]
        self.proto = args[6]
        self.method = args[7]
        self.uri_path = args[8]
        self.auth_round = False
        self.tunneled = tunneled

    def get_kerberos_token(self):
        """Generates a Kerberos token for the specified service name."""
        target_name = gssapi.Name('HTTP/proxy.cloud.turbovci.co.uk')
        ctx = gssapi.SecurityContext(name=target_name)
        token = ctx.step()
        self.token = base64.b64encode(token).decode('utf-8')
        return self.token

    def get_ntlm_negotiate_token(self, username, password):
        """Generate the NTLM negotiate token."""
        # Save the NTLM context for the authentication process
        self.ntlm_context = NtlmContext(username, password)
        negotiate_message = self.ntlm_context.step()
        return base64.b64encode(negotiate_message).decode('utf-8')

    def get_ntlm_authenticate_token(self):
        """Generate the NTLM authenticate token."""
        # Ensure the challenge is available
        if not hasattr(self, 'challenge') or not self.challenge:
            raise Exception("NTLM challenge not available.")
        authenticate_message = self.ntlm_context.step(base64.b64decode(self.challenge))
        return base64.b64encode(authenticate_message).decode('utf-8')

    def extract_ntlm_challenge(self, response):
        """Extract NTLM challenge from the server's 407 response."""
        import re
        # Extract the NTLM challenge from the Proxy-Authenticate header
        match = re.search(r'Proxy-Authenticate: NTLM ([A-Za-z0-9+/=]+)', response.decode('utf-8'))
        if match:
            print(match.group(1))
            return match.group(1)
        return None

    def getCreds(self):
        user = input("Enter user: ")
        passwd = getpass.getpass("Enter password: ")
        creds = user + ":" + passwd
        encodedBytes = base64.b64encode(creds.encode('utf-8'))
        encodedString = encodedBytes.decode('utf-8')
        print(f"#####\n")
        self.encoded_creds = encodedString
        return self.encoded_creds

    def http_parser(self, headers, body):
        import re
        self.headers = headers
        self.headers_parsed = re.split(r'\r\n|\r|\n', headers)
        for line in self.headers_parsed:
            print(f"{line}\n")
        self.body_decoded = body.decode('UTF-8')
        self.body_parsed = re.split('\r\n|\r|\n', self.body_decoded)
        for line in self.body_parsed:
            print(f"{line}\n")
        print(f"#####\n")
        self.http_log = f"****HEADERS****\n\n{self.headers}\n\n****BODY****\n\n{self.body_decoded}"
        return self.http_log

    def connect_parser(self, response_bytes):
        import re
        self.connect_decoded = response_bytes.decode('UTF-8')
        parsed = re.split(r'\r\n|\r|\n', self.connect_decoded)
        for line in parsed:
            print(line)
        print(f"#####\n")
        self.connect_log = f"****CONNECT****\n\n{self.connect_decoded}"
        return self.connect_log

    def get_socket(self):
        if not self.auth_round:
            print(f"Starting first round")
            print(f"#####\n")
            if self.proto == "https":
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.sock:
                    self.sock.connect((self.PROXY, self.PROXY_PORT))
                    self.do_CONNECT()  # first round of authN, no Authorization header exists
                    combined_log = f"{self.connect_log}\n\n{self.http_log}"
                    return combined_log
            elif self.proto == "http":
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.sock:
                    self.sock.connect((self.PROXY, self.PROXY_PORT))
                    if self.method == "POST":
                        self.do_POST()
                        return self.http_log
                    elif self.method == "GET":
                        self.do_GET_with_auth()
                        return self.http_log

        elif self.auth_round:
            print(f"#####\n")
            print(f"Starting second round \n")
            if self.proto == "https":
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.sock:
                    self.sock.connect((self.PROXY, self.PROXY_PORT))
                    auth_done = False
                    try:  # Try Kerberos
                        self.service_name = "HTTP/proxy.cloud.turbovci.co.uk"
                        self.blob = self.get_kerberos_token()
                        self.do_CONNECT_with_auth_kerberos()
                        auth_done = True
                    except Exception as e:
                        print(f"Kerberos Failed\n{e}")
                    if not auth_done:
                        try:
                            self.do_CONNECT_with_auth_ntlm()
                            auth_done = True
                        except Exception as e:
                            print(f"NTLM Failed: {e}")
                    if not auth_done:
                        self.do_CONNECT_with_auth_basic()  # second round of authN, this time Authorization header exists
                        auth_done = True
                    return self.connect_log
            elif self.proto == "http":
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.sock:
                    self.sock.connect((self.PROXY, self.PROXY_PORT))
                    self.do_GET_with_auth()
                    return self.http_log

    def https_handler(self):
        response_bytes = b''
        while b'\r\n\r\n' not in response_bytes:
            response_bytes += self.ssl_socket.recv(1024)
        headers, body = response_bytes.split(b'\r\n\r\n', 1)
        headers = headers.decode()
        content_length = None
        for header in headers.split('\r\n'):
            if header.startswith('Content-Length'):
                content_length = int(header.split(': ')[1])
                break
        reminder = len(body)
        if content_length is not None:
            while reminder < content_length:
                chunk = self.ssl_socket.recv(1024)
                body += chunk
                reminder += len(chunk)
        self.http_parser(headers, body)

    def http_handler(self):
        response_bytes = b''
        while b'\r\n\r\n' not in response_bytes:
            response_bytes += self.sock.recv(1024)
        headers, body = response_bytes.split(b'\r\n\r\n', 1)
        headers = headers.decode()
        content_length = None
        for header in headers.split('\r\n'):
            if header.startswith('Content-Length'):
                content_length = int(header.split(': ')[1])
                break
        reminder = len(body)
        if content_length is not None:
            while reminder < content_length:
                chunk = self.sock.recv(1024)
                body += chunk
                reminder += len(chunk)
        self.http_parser(headers, body)

    def do_CONNECT(self):
        __CONNECT = f"CONNECT {self.HOST}:{self.PORT} HTTP/1.1\r\n" \
                    f"HOST: {self.HOST}:{self.PORT}\r\n" \
                    f"User-Agent: {self.CONNECT_UA}\r\n" \
                    f"\r\n"
        self.sock.send(__CONNECT.encode())
        self.connect_resp = self.sock.recv(1024)
        if b"200" in self.connect_resp:
            self.connect_parser(self.connect_resp)
            self.do_SSLhandshake()
        elif b"407" in self.connect_resp:
            self.connect_parser(self.connect_resp)
            self.auth_round = True
            self.get_socket()
        else:
            self.connect_parser(self.connect_resp)

    def do_CONNECT_with_auth_basic(self):
        self.creds = self.getCreds()
        __CONNECT_with_creds = f"CONNECT {self.HOST}:{self.PORT} HTTP/1.1\r\n" \
                               f"HOST: {self.HOST}:{self.PORT}\r\n" \
                               f"User-Agent: {self.CONNECT_UA}\r\n" \
                               f"Proxy-Authorization: BASIC {self.creds}\r\n" \
                               f"\r\n"
        self.sock.send(__CONNECT_with_creds.encode())
        self.connect_two_resp = self.sock.recv(1024)
        if b"200" in self.connect_two_resp:
            self.connect_parser(self.connect_two_resp)
            self.do_SSLhandshake()
        elif b"407" in self.connect_two_resp:
            self.connect_parser(self.connect_two_resp)
            self.auth_round = True
            raise Exception(f"Check your credentials. \n")
        else:
            self.http_parser(self.connect_two_resp)

    def do_CONNECT_with_auth_ntlm(self):
        """Handles CONNECT with NTLM authentication."""
        # Prompt for NTLM credentials
        username = input("Enter NTLM username (e.g., DOMAIN\\user): ")
        password = getpass.getpass("Enter NTLM password: ")

        # NTLM Round 1: Negotiate
        self.blob = self.get_ntlm_negotiate_token(username, password)
        ntlm_connect_request = (
            f"CONNECT {self.HOST}:{self.PORT} HTTP/1.1\r\n"
            f"HOST: {self.HOST}:{self.PORT}\r\n"
            f"User-Agent: {self.CONNECT_UA}\r\n"
            f"Proxy-Authorization: NTLM {self.blob}\r\n\r\n"
        )
        self.sock.send(ntlm_connect_request.encode())
        self.connect_resp = self.sock.recv(4096)

        # Parse the 407 Proxy Authentication Required
        if b"407" in self.connect_resp:
            print("Starting NTLM second round")
            self.challenge = self.extract_ntlm_challenge(self.connect_resp)
            if not self.challenge:
                raise Exception("NTLM challenge not found in server response.")

            # NTLM Round 2: Authenticate
            auth_token = self.get_ntlm_authenticate_token()
            ntlm_auth_request = (
                f"CONNECT {self.HOST}:{self.PORT} HTTP/1.1\r\n"
                f"HOST: {self.HOST}:{self.PORT}\r\n"
                f"User-Agent: {self.CONNECT_UA}\r\n"
                f"Proxy-Authorization: NTLM {auth_token}\r\n\r\n"
            )
            self.sock.send(ntlm_auth_request.encode())
            self.connect_resp = self.sock.recv(4096)

        # Check for successful connection
        if b"200 Connection established" in self.connect_resp:
            print("NTLM authentication successful!")
            self.connect_parser(self.connect_resp)
            self.do_SSLhandshake()
        else:
            raise Exception("NTLM authentication failed.")

    def do_CONNECT_with_auth_kerberos(self):
        __CONNECT_with_creds = f"CONNECT {self.HOST}:{self.PORT} HTTP/1.1\r\n" \
                               f"HOST: {self.HOST}:{self.PORT}\r\n" \
                               f"User-Agent: {self.CONNECT_UA}\r\n" \
                               f"Proxy-Authorization: NEGOTIATE {self.blob}\r\n" \
                               f"\r\n"
        self.sock.send(__CONNECT_with_creds.encode())
        self.connect_two_resp = self.sock.recv(1024)
        if b"200" in self.connect_two_resp:
            self.connect_parser(self.connect_two_resp)
            self.do_SSLhandshake()
        elif b"407" in self.connect_two_resp:
            self.connect_parser(self.connect_two_resp)
            self.auth_round = True
            raise Exception(f"Check your credentials. \n")
        else:
            self.http_parser(self.connect_two_resp)

    def do_SSLhandshake(self):
        if self.tunneled == "TRUE":
            print(f"Starting tunnel ....")
            while True:
                msg = f"foobar"
                self.sock.send(msg.encode())
        else:
            ssl_context = ssl.create_default_context()
            self.ssl_socket = ssl_context.wrap_socket(self.sock, server_hostname=self.HOST)
            server_certs = self.ssl_socket.getpeercert(binary_form=False)
            print(f"ISSUER: {server_certs['issuer']}")
            print(f"#####\n")
            if self.method == "GET":
                self.do_GET()
            elif self.method == "POST":
                self.do_POST()
            else:
                self.do_GET()

    def do_POST(self):
        __post = f"{self.method} {self.uri_path} HTTP/1.1\r\n" \
                 f"HOST: {self.HOST}:{self.PORT}\r\n" \
                 f"User-Agent: {self.HTTP_UA}\r\n" \
                 f"Proxy-Connection: Keep-Alive\r\n" \
                 f"Content-Length: 2049\r\n" \
                 f"Content-Type: multipart/form-data; boundary=EOF123\r\n" \
                 f"\r\n" \
                 f"EOF123\r\n" \
                 f"Content-Disposition: form-data; name=\"Python_Upload_File\";filename=\"foobar\"\r\n" \
                 f"Content-Type: application/octet-stream \r\n" \
                 f"\r\n" \
                 f"foobar\r\n" \
                 f"\r\n" \
                 f"EOF123\r\n" \
                 f"\r\n"
        if self.proto == "https":
            self.ssl_socket.send(__post.encode())
            self.https_handler()
        elif self.proto == "http":
            self.http_handler()

    def do_GET(self):
        __get = f"{self.method} {self.uri_path} HTTP/1.1\r\n" \
                f"HOST: {self.HOST}:{self.PORT}\r\n" \
                f"User-Agent: {self.HTTP_UA}\r\n" \
                f"\r\n"
        if self.proto == "https":
            self.ssl_socket.send(__get.encode())
            self.https_handler()
        elif self.proto == "http":
            self.sock.send(__get.encode())
            self.http_handler()

    def do_GET_with_auth(self):
        __get = f"{self.method} {self.uri_path} HTTP/1.1\r\n" \
                f"HOST: {self.HOST}:{self.PORT}\r\n" \
                f"User-Agent: {self.HTTP_UA}\r\n" \
                f"Proxy-Authorization: BASIC {self.creds}\r\n" \
                f"\r\n"
        if self.proto == "https":
            self.ssl_socket.send(__get.encode())
            self.https_handler()
        elif self.proto == "http":
            self.sock.send(__get.encode())
            self.http_handler()
            self.b = "blah"
            return self.b


# init objects
if __name__ == "__main__":
    app = App()
    app.mainloop()
