#!/usr/bin/env python3
"""Simple test to verify IoT endpoint connectivity."""

import socket
import ssl
import sys

def test_endpoint_connectivity(endpoint):
    """Test if we can connect to the IoT endpoint."""
    print(f"Testing connectivity to {endpoint}:8883...")
    
    try:
        # Test basic TCP connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        result = sock.connect_ex((endpoint, 8883))
        sock.close()
        
        if result == 0:
            print("✓ TCP connection successful")
        else:
            print(f"✗ TCP connection failed (error: {result})")
            return False
            
        # Test TLS connection
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        with socket.create_connection((endpoint, 8883), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=endpoint) as ssock:
                print("✓ TLS connection successful")
                print(f"  TLS version: {ssock.version()}")
                print(f"  Cipher: {ssock.cipher()}")
                
        return True
        
    except Exception as e:
        print(f"✗ Connection test failed: {e}")
        return False

if __name__ == "__main__":
    # Test with a common AWS IoT endpoint pattern
    test_endpoints = [
        "a3qxzmo82qzqo3-ats.iot.us-east-1.amazonaws.com",
        "a3qxzmo82qzqo3-ats.iot.eu-west-1.amazonaws.com",
        "a3qxzmo82qzqo3-ats.iot.ap-southeast-1.amazonaws.com"
    ]
    
    for endpoint in test_endpoints:
        test_endpoint_connectivity(endpoint)
        print()
