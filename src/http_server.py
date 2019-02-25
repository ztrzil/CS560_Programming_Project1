import os
import sys
import socket
import signal
import time
import const
import uuid # create random file name
# sanitize upload file names
from werkzeug.utils import secure_filename

class HttpServer:
  def __init__(self, ip_addr='', port=0):
    self.ip = ip_addr
    self.port = port
    self.www_dir = 'www'
    self.upload_dir = 'upload'


  def start_server(self):
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
      self.sock.bind((self.ip, self.port))
      if self.port == 0:
        self.port = self.sock.getsockname()[1]
      print('Starting HTTP server at {} on port {}'.format(self.ip, self.port))
    except Exception as e:
      print('Failed to start HTTP server.')
      print(e)
      if 'Address already in use' in str(e):
        print('Trying to start HTTP server on a free port. . .')
        self.port = 0
        self.start_server()

    self._wait_for_connections()


  def _generate_headers(self, status_code):
    """Generate appropriate header based on status code. Return the header
    encoded as a bytes object so that it can be sent to the browser. """
    if status_code == const.HTTP_STATUS_OK:
      header = 'HTTP/1.1 {} OK\r\n'.format(const.HTTP_STATUS_OK)
    elif status_code == const.HTTP_STATUS_BAD_REQ:
      pass
    elif status_code == const.HTTP_STATUS_FILE_NOT_FOUND:
      header = 'HTTP/1.1 {} OK\r\n'.format(const.HTTP_STATUS_FILE_NOT_FOUND)
    elif status_code == const.HTTP_STATUS_FORBIDDEN:
      header = 'HTTP/1.1 {} Forbidden\r\n'.format(const.HTTP_STATUS_FORBIDDEN)
    elif status_code == const.HTTP_STATUS_INTERNAL_ERROR:
      header = 'HTTP/1.1 {} Internal Error\r\n'.format(const.HTTP_STATUS_INTERNAL_ERROR)
    elif status_code == const.HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE:
      header = 'HTTP/1.1 {} Unsupported Media Type\r\n'.format(const.HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE)
    else: #unrecognized status
      header = 'HTTP/1.1 {} Bad Request\r\n'.format(const.HTTP_STATUS_BAD_REQ)

    # add more fields to the header, regardless of status code
    cur_date = time.strftime('%a %d %b %Y %H %M %S', time.localtime())
    header += 'Date: ' + cur_date + '\r\n'
    header += 'Server: ' + const.SERVER_SIGNATURE + '\r\n'
    header += 'Connection: close\r\n'
    header += 'Content-Type: text/html\r\n\r\n'

    return header.encode()


  def _get_content(self, filename):
    """ Open up the webpage and return it. Note: opening file in binary mode,
    so the content does not need to be encoded like the header """
    with open(filename, 'rb') as fp:
      content = fp.read()
    return content


  def _serve_content(self, req_file, req_method, conn, status=const.HTTP_STATUS_OK):
    if status == const.HTTP_STATUS_BAD_REQ:
      headers = self._generate_headers(const.HTTP_STATUS_BAD_REQ)
      content = self._get_content(self.www_dir + '/' + 'error_400.html')
    elif status == const.HTTP_STATUS_FORBIDDEN:
      headers = self._generate_headers(status)
      content = self._get_content(self.www_dir + '/' + 'error_403.html')
    elif status == const.HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE:
      headers = self._generate_headers(status)
      content = self._get_content(self.www_dir + '/' + 'error_415.html')
    else:
      try: 
        content = self._get_content(req_file)
        headers = self._generate_headers(status)
      except FileNotFoundError as e:
        headers = self._generate_headers(const.HTTP_STATUS_FILE_NOT_FOUND)
        content = self._get_content(self.www_dir + '/' + 'error_404.html')
        print(e)
      except Exception as e:
        headers = self._generate_headers(const.HTTP_STATUS_INTERNAL_ERROR)
        content = self._get_content(self.www_dir + '/' + 'error_500.html')
        print(e)

    response = headers + content
    conn.send(response)
    print('Terminating connection with client')
    conn.close()


  def _upload_file(self, fields, data, conn):
    parts = data.split('\r\n\r\n'.encode())
    while len(parts) < 3:
      chunk = conn.recv(const.CHUNK_SIZE)
      if not chunk: break
      data += chunk
      parts = data.split('\r\n\r\n'.encode())

    if len(parts) < 3: # error
      self._serve_content('', '', conn, const.HTTP_STATUS_INTERNAL_ERROR)
      return

    file_name = bytes.decode(parts[1]).split('filename=\"')[1].split('"')[0]
    file_name = secure_filename(file_name) # sanitize filename
    if file_name == '': # handle if sanitize returns empty filename or file exists
      file_name = uuid.uuid4().hex + '.txt'
    if not file_name.endswith('.txt'):
      print('Unsupported Media Type')
      self._serve_content('', '', conn, const.HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE)
      return
    exists = os.path.isfile(self.upload_dir + '/' + file_name)
    if exists:
      name, ext = file_name.split('.')
      file_name = name + '_' + uuid.uuid4().hex + '.' + ext

    print('File to upload: ', file_name)
    content = b'' 
    for part in parts[2:]:
      content += part
    conn.settimeout(2.0)
    while chunk:
      try:
        chunk = conn.recv(const.CHUNK_SIZE)
      except socket.timeout:
        break
      print(chunk)
      if not chunk: break
      content += chunk

    file_data = content.decode().split('\r\n------')[0]
    #print(file_data)
    with open(self.upload_dir + '/' + file_name, 'wb') as fp:
      fp.write(file_data.encode())

    self._serve_content(self.www_dir + '/upload_success.html', 'GET', conn)


  def __is_safe_path(self, path):
    """ Check for attempt at path traversal! """
    basedir = os.getcwd() + '/' + self.www_dir
    follow_symlinks = False
    if follow_symlinks:
      return os.path.realpath(path).startswith(basedir)
    return os.path.abspath(path).startswith(basedir)


  def _handle_request(self, data, conn):
    data_str = bytes.decode(data)
    fields = data_str.split('\n')
    fields = [field.split(' ') for field in fields] 
    request_method = fields[0][0]
    print(request_method)
    print(fields)
    if request_method == 'GET' or request_method == 'HEAD':
      req_file = fields[0][1]
      if req_file == '/': req_file += 'index.html'
      req_file = self.www_dir + req_file
      print('Request for file: ', req_file)
      if self.__is_safe_path(req_file): # Safe to try to open file
        print('This is a safe file!')
        status = const.HTTP_STATUS_OK
      else: # return 403 Forbidden error
        status = const.HTTP_STATUS_FORBIDDEN
      self._serve_content(req_file, request_method, conn, status)
    elif request_method == 'POST':
      self._upload_file(fields, data, conn)
    else:
      print('Unknown HTTP request method: ', request_method)
      status = const.HTTP_STATUS_BAD_REQ
    

  def _wait_for_connections(self):
    """ Sit in loop and wait for connections. Handle the request once
    a connection is received. """
    while True:
      print('Listening for new connection')
      self.sock.listen(const.MAX_CONNECTIONS)

      conn, addr = self.sock.accept()
      print('New connection from ', addr)
      data = conn.recv(const.CHUNK_SIZE)

      #TODO: try-catch here w/ 500 internal error if exception
      self._handle_request(data, conn)



  def shutdown(self):
    """ Shutdown any active connections and close the socket """
    try: 
      print('\nShutting down HTTP Server. . .')
      self.sock.shutdown(socket.SHUT_RDWR) # shut down both halves of active connection
    except Exception as e:
      # Errno 57 Socket Not Connected means there were no active connections at
      # the time of shutting down. Ignore that error silently and close the conn.
      if not 'Errno 57' in str(e): 
        print('Error while shutting down HTTP Server:')
        print(e)
    finally:
      self.sock.close()



def stop_server(sig, frame):
  """ If ctrl-c is caught, shut down the server gracefully and exit."""
  s.shutdown()
  sys.exit(0)


# Gracefully shutdown HTTP server upon ctrl-c
signal.signal(signal.SIGINT, stop_server)


s = HttpServer('', 8000)
s.start_server()



'''
    #TODO: size isn't working (size of headers and other info is included. 
    # Splitting on '\r\n\r\n' should work, but also isn't...
    parts = data.split('\r\n\r\n'.encode())
    while len(parts) < 3:
      new_d = conn.recv(const.CHUNK_SIZE)
      if not new_d: break
      data += new_d
      parts = data.split('\r\n\r\n'.encode())

    if len(parts) < 3:
      # malformed request. Raise error
      pass
    #    print(bytes.decode(parts[1]))
    fields = bytes.decode(parts[0]).split('\n')
    fields = [field.split(' ') for field in fields] 
    sz = int(fields[3][1])
    #TODO: grab actual file name and sanitize it. Add random string if name collision
    filename = uuid.uuid4().hex
    content = parts[2]
    print(sz)
    print('uploading file!')
    with open(self.upload_dir + '/' + filename, 'wb') as fp:
      if len(content) < sz:
        fp.write(content)
        sz -= len(content)
      else:
        fp.write(content[0:sz])
        return
      print(content)
      while content:
        print('SIZE: ', sz)
        content = conn.recv(const.CHUNK_SIZE)
        check = content.split('\r\n\r\n'.encode()) 
        if len(check) > 1:
          print('FOUND IT!')
          fp.write(check[0])
          print(check[0])
          print('This shit is after:')
          print(check[1])
          break
        if len(content) < sz:
          print(content)
          fp.write(content)
          sz -= len(content)
        else:
          print(content[0:sz])
          fp.write(content[0:sz])
          break
    sys.exit(0)
'''
'''
    content = data

    chunk = conn.recv(512)
    content += chunk
    conn.settimeout(2.0)
    while chunk:
      try:
          chunk = conn.recv(512) 
      except socket.timeout as e:
          break
      print(chunk)
      content += chunk
      print(len(chunk))
      if len(chunk) < 1:
          break
    
    conn.settimeout(None)
    form = content.decode()

    stuff = form.split('------')[1]
    parsed = stuff.split('\n')
    info = parsed[1]
    file_data = '\n'.join(parsed[3:])
    file_name = info.split('filename=\"')[1][:-2]
    print(file_name)
    print(file_data)

    print('uploading file!')
    with open(self.upload_dir + '/' + file_name, 'wb') as fp:
        fp.write(file_data.encode())
'''
