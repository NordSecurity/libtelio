#!/usr/bin/env bash
set -euxo pipefail

echo "PermitRootLogin yes" >> /private/etc/ssh/sshd_config
