#!/bin/bash

# Start the background processes
/opt/rapido_bank/security_tools/test_malicious_payload &
python /opt/rapido_bank/security_tools/mtd_system.py &

# Keep the script running
tail -f /dev/null
