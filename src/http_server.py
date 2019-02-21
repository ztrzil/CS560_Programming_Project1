import os
import sys
import socket
import signal
import time
import const


class HttpServer:
  def __init__(self, ip_addr='', port=0):
    self.ip = ip_addr
    self.port = port
    self.www_dir = 'www/'
    self.upload_dir = 'upload/'


  def start_server(self):
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
      #print('Starting HTTP server at {} on port {}'.format(self.ip, self.port))
      self.sock.bind((self.ip, self.port))
      if self.port == 0:
        self.port = self.sock.getsockname()[1]
      print('Starting HTTP server at {} on port {}'.format(self.ip, self.port))
#    except PermissionError as e:
#      print('Failed to start HTTP server.')
#      print(e)
      #TODO: Attempt to connect to unpriveleged port
    except Exception as e:
      print('Failed to start HTTP server.')
      print(e)
      if 'Address already in use' in str(e):
        print('Trying to start HTTP server on a free port. . .')
        self.port = 0
        self.start_server()

    self._wait_for_connections()


  def _generate_headers(self, status_code):
    if status_code == const.HTTP_STATUS_OK:
      header = 'HTTP/1.1 {} OK\n'.format(const.HTTP_STATUS_OK)
    elif status_code == const.HTTP_STATUS_BAD_REQ:
      pass
    elif status_code == const.HTTP_STATUS_FILE_NOT_FOUND:
      header = 'HTTP/1.1 {} OK\n'.format(const.HTTP_STATUS_FILE_NOT_FOUND)
    elif status_code == const.HTTP_STATUS_FORBIDDEN:
      pass
    #elif status_code == const.HTTP_STATUS
    else: #unrecognized status
      pass

    # add more fields to the header, regardless of status code
    cur_date = time.strftime('%a %d %b %Y %H %M %S', time.localtime())
    header += 'Date: ' + cur_date + '\n'
    header += 'Server: ' + const.SERVER_SIGNATURE + '\n'
    header += 'Connection: close\n\n'

    return header


  def _serve_content(self, req_file, req_method, conn):
    if req_method != 'GET':
      pass # Error check that the request method was a GET
      # headers = self._generate_headers(const.HTTP_STATUS_BAD_REQ)
    try: 
      with open(req_file, 'rb') as fp:
        content = fp.read()

      headers = self._generate_headers(const.HTTP_STATUS_OK)

    except Exception as e:
      print('FUCK MY SHIT UP')
      print(e)

    response = headers.encode() + content
    conn.send(response)
    print('Terminating connection with client')
    conn.close()


  def __is_safe_path(self, path):
    basedir = os.getcwd() + '/' + self.www_dir
    follow_symlinks = False
    if follow_symlinks:
      return os.path.realpath(path).startswith(basedir)
    return os.path.abspath(path).startswith(basedir)


  def _handle_request(self, data, conn):
    status = const.HTTP_STATUS_OK
    fields = data.split(' ')
    request_method = fields[0]
    if request_method == 'GET' or request_method == 'HEAD':
      req_file = fields[1]
      if req_file == '/': req_file = 'index.html'
      req_file = self.www_dir + req_file
      print('Request for file: ', req_file)
      if self.__is_safe_path(req_file):
        print('This is a safe file!')
        self._serve_content(req_file, request_method, conn)
      else:
        # return 403 Forbidden error
        pass
    else:
      print('Unknown HTTP request method: ', request_method)
    


  def _wait_for_connections(self):
    while True:
      print('Listening for new connection')
      self.sock.listen(const.MAX_CONNECTIONS)

      conn, addr = self.sock.accept()
      print('New connection from ', addr)

      data = conn.recv(1024)
      data_str = bytes.decode(data)

      self._handle_request(data_str, conn)



  def shutdown(self):
    try: 
      print('Shutting down HTTP Server')
      self.sock.shutdown(socket.SHUT_RDWR) # shut down both halves of the connection
    except Exception as e:
      print('Failed to shutdown HTTP Server:')
      print(e)



def stop_server(sig, frame):
  s.shutdown()
  sys.exit(0)


# Gracefully shutdown HTTP server upon ctrl-c
signal.signal(signal.SIGINT, stop_server)


s = HttpServer('', 8000)
s.start_server()
time.sleep(1)
s.shutdown()
