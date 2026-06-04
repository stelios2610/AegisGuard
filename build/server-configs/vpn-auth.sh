#!/bin/bash
# AegisGuard SSL VPN auth script
# Called by OpenVPN via-file: $1 = temp file with username/password

/usr/bin/python3 /etc/aegisguard/vpn_auth_check.py "$1"
