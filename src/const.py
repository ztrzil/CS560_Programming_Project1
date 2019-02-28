#: Size of data chunks taken off the socket
CHUNK_SIZE = 1024
#: Maximum number of simultaneous connections allowed
MAX_CONNECTIONS = 10
#: HTTP status code indicating everything is OK
HTTP_STATUS_OK = 200
#: HTTP status code for unrecognized request
HTTP_STATUS_BAD_REQ = 400
#: HTTP status code for attempts to access files outside of the www directory
HTTP_STATUS_FORBIDDEN = 403
#: HTTP status code for file not found error
HTTP_STATUS_FILE_NOT_FOUND = 404
#: HTTP status code for an internal server error
HTTP_STATUS_INTERNAL_ERROR = 500
#: HTTP status code for unsupported media type error
HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE = 415
#: The server signature that is included in the HTTP header
SERVER_SIGNATURE = 'Trzil_and_McDaniel_HTTP_Server'
