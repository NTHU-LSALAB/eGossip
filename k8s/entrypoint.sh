#!/bin/sh
/usr/local/bin/xdp-gossip server --name "${POD_NAME}" --link eth0 --proto "${PROTO}" --debug
