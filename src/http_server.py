import os
import sys
import socket
import signal
import time
import const
import uuid # create random file name
import argparse
# sanitize upload file names
from werkzeug.utils import secure_filename

#Parses Arguments
def check_args(args=None):
  parser = argparse.ArgumentParser(description='Process flags for the program.')
#  parser.add_argument('input', type=str, help="File name for file to search")
#  parser.add_argument('kth_smallest', type=int, help="kth smallest element to find")
#  parser.add_argument('num_elems', type=int, help="Number of elements to use from input file")
  parser.add_argument('-v', '--verbose', action='store_true', help="more verbose printing")
  results = parser.parse_args(args)
  return results


class HttpServer:
  def __init__(self, ip_addr='', port=0, verbose=False):
    """ Constructor
    Parameters
    ----------
    ip_addr : str, optional
        Ip address to bind the socket to. Default is empty str which binds to
        0.0.0.0
    port : int, optional
        Port that the socket binds to. Default is a random, available port
    verbose : bool, optional
        The server prints some info to the command line. Should this printing
        be verbose.
    Attributes
    ----------
    www_dir : str
        The directory, relative to the base directory where the HTML files are
        stored.
    upload_dir : str
        The directory, relative to the base directory where the files uploaded
        by the user are stored.
    """
    self.ip = ip_addr
    self.port = port
    self.www_dir = 'www'
    self.upload_dir = 'upload'
    self.verbose = verbose


  def start_server(self):
    """ Open the socket, and bind it to the address and port set in the
    constructor. If unable to connect on the specified port because address is
    already in use, try again. This is useful for testing or immediate restart.
    Once we bind the socket, call the loop that waits for connections.
    """
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
    encoded as a bytes object so that it can be sent to the browser. 

    Parameters
    ----------
    status_code : int
        The status code that will be set in the header

    Returns 
    -------
    bytes object
        The header with the necessary fields set appropriately and encoded to
        be sent over the socket. 
    """
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
    so the content does not need to be encoded like the header.

    Parameters
    ----------
    filename : str
        The path of the file that the user is requesting. 
    Returns 
    -------
    bytes object
        The contents of the file (should be HTML) to be sent to the socket
    """
    with open(filename, 'rb') as fp:
      content = fp.read()
    return content


  def _traverse_uploads(self, path):
    """ Traverses the directory and lists the files contained therein.

    Parameters
    ----------
    path : str
        Path of directory being requested by user that has files to list

    Returns 
    -------
    bytes object
        The HTML displaying the files in the directory encoded to be sent via
        the socket
    """
    content = ''
    for f in os.listdir(path):
      if os.path.isdir(path + '/' + f):
        f += '/'
      #content += '<a href=' + path + '/' + f + '>' + f + '</a><br>'
      content += '<a href=#>' + f + '</a><br>'
      print(f)
  
    return content.encode()



  def _serve_content(self, req_file, req_method, conn, status=const.HTTP_STATUS_OK):
    """ Fetch the header, open the necessary file, and return the headers and
    file to the socket.

    Parameters
    ----------
    req_file : str
        The name of the file that is being requested
    req_method : str
        The request method, should be GET or POST
    conn : socket.socket object
        The handle to the socket over which the content will be served
    status : int
        The status code that will be put in the header. This may be changed in
        this function.
    """
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
        headers = self._generate_headers(status)
        if req_file.startswith(self.www_dir + '/' + self.upload_dir) and os.path.isdir(req_file):
          content = self._traverse_uploads(req_file)
        else:
          content = self._get_content(req_file)
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
    """ Handle file uploads by a user via HTML form. This function will save
    the file uploaded by the user to the upload directory.

    Parameters
    ----------
    fields : list of lists of str
        The lists in fields are the different HTML headers. Each str element in
        each list is a space delimited value of that header.            
    data : bytes object
        The initial data received from the socket. Contains HTML headers
    conn : socket.socket object
        The handle to the socket that we're listening on. Will be used to
        receive the rest of the data from the client.
    """
    parts = data.split('\r\n\r\n'.encode())
    while len(parts) < 3:
      chunk = conn.recv(const.CHUNK_SIZE)
      if not chunk: break
      data += chunk
      parts = data.split('\r\n\r\n'.encode())

    if len(parts) < 3: # error
      self._serve_content('', '', conn, const.HTTP_STATUS_INTERNAL_ERROR)
      return

    file_name = bytes.decode(parts[1].split(b'filename=\"')[1].split(b'"')[0])
    file_name = secure_filename(file_name) # sanitize filename
    if file_name == '': # handle if sanitize returns empty filename or file exists
      file_name = uuid.uuid4().hex
    exists = os.path.isfile(self.upload_dir + '/' + file_name)
    if exists:
      name, ext = file_name.split('.')
      file_name = name + '_' + uuid.uuid4().hex + '.' + ext

    if self.verbose:
      print('File to upload: ', file_name)
    content = b'' 
    # In listening for the form data (filename, etc. we may have already
    # received some of the file data
    for part in parts[2:]:
      content += part
    conn.settimeout(2.0)
    while chunk:
      try:
        chunk = conn.recv(const.CHUNK_SIZE)
      except socket.timeout:
        break
      if self.verbose:
        print(chunk)
      if not chunk: break
      content += chunk
    # Don't write what is after the boundary as it is not part of the file
    file_data = content.split(b'\r\n------')[0]
    print(file_data)
    with open(self.upload_dir + '/' + file_name, 'wb') as fp:
      fp.write(file_data)

    self._serve_content(self.www_dir + '/upload_success.html', 'GET', conn)


  def __is_safe_path(self, path):
    """ Check for an attempt at path traversal.

    Parameters
    ----------
    path : str
        The path being requested by the client that needs to be validated.
    
    Returns 
    -------
    bool
        Boolean of the check if the user is requesting file at the proper path
    """
    basedir = os.getcwd() + '/' + self.www_dir + '/'
    basedir = self.www_dir + '/'
    return os.path.commonprefix([path, basedir]) == basedir


  def _handle_request(self, data, conn):
    """ Called each time a request is received on the socket. This function
    checks the type of request -- GET or POST -- and does some some safety
    checking for path traversal before handing the request and data off to
    the function that will serve it.

    Parameters
    ----------
    data : bytes object
        The initial data received from the socket. Contains HTML headers
    conn : socket.socket object
        The handle to the socket that we're listening on. Will be used to
        receive the rest of the data from the client.
    """
    data_str = bytes.decode(data)
    fields = data_str.split('\n')
    fields = [field.split(' ') for field in fields] 
    request_method = fields[0][0]
    print('Request method: ', request_method)
    if self.verbose:
      print('Header fields:')
      print(fields)
    if request_method == 'GET' or request_method == 'HEAD':
      req_file = fields[0][1]
      if req_file == '/': req_file += 'index.html'
      if req_file.startswith('/' + self.www_dir + '/' + self.upload_dir):
        req_file = req_file[1:]
      if not req_file.startswith(self.www_dir) and not req_file.startswith('/'+ self.www_dir): #TODO: new if statement. Keep or always do?
        req_file = self.www_dir + req_file
      print('Request for file: ', req_file)
      print('Checking for path traversal attempt. . .')
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
    a connection is received. 
    """
    while True:
      print('Listening for new connection')
      self.sock.listen(const.MAX_CONNECTIONS)

      conn, addr = self.sock.accept()
      print('New connection from ', addr)
      data = conn.recv(const.CHUNK_SIZE)

      #TODO: try-catch here w/ 500 internal error if exception??
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

args = check_args(sys.argv[1:])
s = HttpServer('', 8000, args.verbose)
s.start_server()
