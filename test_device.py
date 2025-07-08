#!/usr/bin/env python3
"""Test script to verify device creation and IoT connection setup."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'custom_components', 'dyson_local', 'vendor', 'libdyson'))

from dyson_device import DysonDevice
from dyson_360_vis_nav import Dyson360VisNav
from const import DEVICE_TYPE_360_VIS_NAV

# Test device creation
print("Testing device creation...")
device = Dyson360VisNav("TEST-SERIAL-123", "test-credential")
print(f"Device type: {device.device_type}")
print(f"Device serial: {device.serial}")
print(f"Status topic: {device._status_topic}")
print(f"Command topic: {device._command_topic}")

# Test IoT connection parameters
print("\nTesting IoT connection parameters...")
test_iot_details = {
    "endpoint": "test-endpoint.iot.us-east-1.amazonaws.com",
    "client_id": "test-client-id",
    "token_value": "test-token-value",
    "token_signature": "test-token-signature"
}

print(f"Endpoint: {test_iot_details['endpoint']}")
print(f"Client ID: {test_iot_details['client_id']}")
print(f"Token Value: {test_iot_details['token_value']}")
print(f"Token Signature: {test_iot_details['token_signature']}")

print("\nDevice creation test complete!")
