import socket

def is_connected(host="8.8.8.8", port=53, timeout=3):
    """
    Check if the system has internet connectivity by attempting to connect to a DNS server.
    """
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except socket.error:
        return False
