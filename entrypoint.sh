#!/bin/bash

# OVS veritabanını başlat
mkdir -p /var/run/openvswitch
ovsdb-tool create /etc/openvswitch/conf.db /usr/share/openvswitch/vswitch.ovsschema 2>/dev/null || true
ovsdb-server --remote=punix:/var/run/openvswitch/db.sock \
    --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
    --pidfile --detach

# OVS'yi başlat (kernel modülü yoksa userspace modunda)
ovs-vsctl --no-wait init
ovs-vswitchd --pidfile --detach --log-file 2>/dev/null || \
    ovs-vswitchd --pidfile --detach --log-file --dpdk-init=false 2>/dev/null || \
    echo "Warning: OVS started in limited mode"

echo "==========================================="
echo "  LEO SDN Attack Detection Environment"
echo "==========================================="
echo "OVS Status: $(ovs-vsctl --version 2>/dev/null | head -1 || echo 'Not available')"
echo "Mininet: $(mn --version 2>/dev/null || echo 'Available')"
echo "Ryu: $(ryu-manager --version 2>/dev/null || echo 'Available')"
echo "==========================================="

exec "$@"

