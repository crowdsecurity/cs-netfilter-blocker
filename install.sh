#!/usr/bin/env bash
BIN_PATH_INSTALLED="/usr/local/bin/custom-blocker"
BIN_PATH="./custom-blocker"
CONFIG_DIR="/etc/crowdsec/custom-blocker/"
PID_DIR="/var/run/crowdsec/"
SYSTEMD_PATH_FILE="/etc/systemd/system/custom-blocker.service"

install_custom_blocker() {
	install -v -m 755 -D "${BIN_PATH}" "${BIN_PATH_INSTALLED}"
	mkdir -p "${CONFIG_DIR}"
	cp "./config/custom-blocker.yaml" "${CONFIG_DIR}custom-blocker.yaml"
	CFG=${CONFIG_DIR} PID=${PID_DIR} BIN=${BIN_PATH_INSTALLED} envsubst < ./config/custom-blocker.service > "${SYSTEMD_PATH_FILE}"
	systemctl daemon-reload
	systemctl start custom-blocker
}


echo "Installing custom-blocker"
install_custom_blocker