#!/bin/bash
# AegisGuard SSL VPN auth - via-file mode
# OpenVPN passes a temp file with: line1=username, line2=password
/usr/bin/python3 /etc/aegisguard/vpn_auth_check.py "$1"
