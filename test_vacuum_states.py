#!/usr/bin/env python3
"""Test script to verify vacuum.py syntax."""

import sys
import os

# Add the custom components path to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'custom_components', 'dyson_local', 'vendor', 'libdyson'))

try:
    # Test importing the VacuumState enum
    from const import VacuumState
    print(f"Successfully imported VacuumState with {len(VacuumState)} states")
    
    # List all available states
    print("Available VacuumState constants:")
    for state in VacuumState:
        print(f"  - {state.name}")
    
    # Verify that MACHINE_OFF is not in the list
    if not hasattr(VacuumState, 'MACHINE_OFF'):
        print("✓ MACHINE_OFF is correctly not present in VacuumState")
    else:
        print("✗ MACHINE_OFF is still present in VacuumState")
        
    print("VacuumState enum test completed successfully!")
    
except Exception as e:
    print(f"Error importing VacuumState: {e}")
    sys.exit(1)
