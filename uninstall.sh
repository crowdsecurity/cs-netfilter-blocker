#!/bin/bash

BIN_PATH_INSTALLED="/usr/local/bin/custom-blocker"
CONFIG_DIR="/etc/crowdsec/custom-blocker/"
PID_DIR="/var/run/crowdsec/"
SYSTEMD_PATH_FILE="/etc/systemd/system/custom-blocker.service"

uninstall() {
	systemctl stop custom-blocker
	rm -rf "${CONFIG_DIR}"
	rm -f "${SYSTEMD_PATH_FILE}"
	rm -f "${PID_DIR}custom-blocker.pid"
	rm -f "${BIN_PATH_INSTALLED}"
}

uninstall
