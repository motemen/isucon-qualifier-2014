#!/bin/sh
set -e
set -x
ssh isucon@54.168.155.12 'cd ~/deploy && git pull && supervisorctl restart isucon_perl'
