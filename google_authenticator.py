#!/usr/bin/python
from http.server import BaseHTTPRequestHandler,HTTPServer
from urllib.parse import urlparse
import hmac, base64, struct, hashlib, time

PORT_NUMBER = 8080

# Takes a secret and a time interval, returning a token.  Success if it matches what the user provided
# pseudocode provided here: https://en.wikipedia.org/wiki/Google_Authenticator

def get_hotp_token(secret, intervals_no):
    key = base64.b32decode(secret, True)
    msg = struct.pack(">Q", intervals_no)
    hash = hmac.new(key, msg, hashlib.sha1).digest()
    offset = hash[19] & 15
    code = (struct.unpack(">I", hash[offset:offset+4])[0] & 0x7fffffff) % 1000000
    return code

def get_totp_token(secret):
    return get_hotp_token(secret, intervals_no=int(time.time()/30))

def get_QR_code(secret, query_components):
    html = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<script type="text/javascript">
function load() {
var secret = '""" + secret + """';
var name = '""" + query_components.get("name", "Alice") + """';
document.getElementById('qr_image').src = 
	"https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=" +
	"otpauth://totp/" + name + "?secret=" + secret;
}
</script>
<body onload="load()"><h1>Validate Google Authenticator Device</h1>
<img src="nothing.jpg" id="qr_image" name="qr_image"/>
<form action="/registerTOTP">
  Enter 1st code:
  <input type="text" name="code1"><br/><br/>
  After roll over enter 2nd code:
  <input type="text" name="code2"><br/><br/>
  <input type="submit" value="Validate">
</form></body></html>"""
    return html

def register_TOTP(secret, query_components):
    html = 'Failure'
    interval_no=int(time.time()/30)
    code1 = int(query_components.get("code1", "0"))
    # In production you should consider the user might be a second or two late
    if ( code1 == get_hotp_token(secret, interval_no-1) ):
        code2 = int(query_components.get("code2", "0"))
        if ( code2 == get_hotp_token(secret, interval_no) ):
            html = "Success"
    return html

def validate_TOTP(secret, query_components):
    html = 'Failure'
    code = int(query_components.get("code", "0"))
    if ( code == get_hotp_token(secret, int(time.time()/30)) ):
        html = "Success"
    return html

def get_HOTP(secret, query_components):
    interval = int(time.time()/30)
    code = get_hotp_token(secret, interval)
    link = "http://localhost:8080/validateHOTP?secret=" + secret + "&code=" + str(code) + "&interval=" + str(interval)    
    return "Secret= " +secret +"<br/>Code= " +str(code) +"<br/>Interval= " +str(interval) + "<br/><a href='" + link + "'>" + link + "<a/>"

def validate_HOTP(secret, query_components):
    html = 'Failure'
    code = int(query_components.get("code", "0"))
    interval = int(query_components.get("interval", "0"))
    if ( code == get_hotp_token(secret, interval) ):
        html = "Success"
    return html

def show_help(secret, query_components):
    html = """<h1>How to use this service</h1><br/>
    Replace [yoursecret] with a 16 hexidecimal value: MZXW633PN5XW6MZX is the default<br/><br/>
    Add new Google authenticator account: <a href="http://localhost:8080/getQRcode?name=yourname?secret=MZXW633PN5XW6MZX">http://localhost:8080/getQRcode?name=[yourname]?secret=[yoursecret]<a/> This will respond with a QR code and two code boxes to setup a new Authenticator account on your device.  Pressing the validate button will confirm the server and your device agree.<br/>
    <br/>
    Validate Google Authenticator account: <a href="http://localhost:8080/registerTOTPtoken?code1=379972&code2=165691?secret=MZXW633PN5XW6MZX">http://localhost:8080/registerTOTPtoken?code1=379972&code2=165691?secret=[yoursecret]<a/><br/>
    <br/>
    Validate Google Authenticator code: <a href="http://localhost:8080/validateTOTP?code=379972?secret=MZXW633PN5XW6MZX">http://localhost:8080/validateTOTPtoken?code=379972?secret=[yoursecret]<a/><br/>
    <br/>
    Generate HOTP values: <a href="http://localhost:8080/getHOTP">http://localhost:8080/getHOTP<a/><br/>
    <br/>
    Validate a HOTP: <a href="http://localhost:8080/validateHOTP?secret=MZXW633PN5XW6MZX&code=469817&interval=48829623">http://localhost:8080/validateHOTP?secret=[yoursecret]&code=[yourauthcode]&interval=[yourinterval]<a/><br/>
    """
    return html

action_statements = {
    "/getQRcode": get_QR_code,
    "/registerTOTP": register_TOTP,
    "/validateTOTP": validate_TOTP,
    "/getHOTP": get_HOTP,
    "/validateHOTP": validate_HOTP,
    "help": show_help
}

#This class will handles any incoming request from
#the browser 
class myHandler(BaseHTTPRequestHandler):

    #Handler for the GET requests
    def do_GET(self):
        # Everything returns 200 OK
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()

        action = urlparse(self.path).path
        action = action_statements.get(action,show_help)
        
        try:
            query = urlparse(self.path).query
            query_components = dict(qc.split("=") for qc in query.split("&"))
        except ValueError:
            # Missing or malformed query string so use an empty dictionary
            query_components = {"":""}
            
        secret = query_components.get("secret", "MZXW633PN5XW6MZX")
        # ------WARNING-------
        # In production the 'secret' will not be passed on every call.
        # The right way would be to randomly generate on the server and pass
        # to the client when the QR code is generated.  The clinet and server
        # would each know the secret and current time.  There is not need to
        # expose them to eavesdroppers at validation time
        # ---- END WARNING ----

        self.wfile.write (action(secret, query_components).encode())
        return
    
try:
    #Create a web server and define the handler to manage the
    #incoming request
    server = HTTPServer(('', PORT_NUMBER), myHandler)
    print ('Started httpserver on port {0:4d}'.format(PORT_NUMBER) )

    #Wait forever for incoming htto requests
    server.serve_forever()

except KeyboardInterrupt:
    print ('^C received, shutting down the web server' )
    server.socket.close()