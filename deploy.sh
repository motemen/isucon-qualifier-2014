#!/bin/sh
set -e
set -x
me=$(whoami)
ssh isucon@54.168.155.12 "/home/isucon/notify.sh $me deploying...; cd ~/deploy && git pull && supervisorctl restart isucon_perl && /home/isucon/notify.sh deployed: \$(git log -1 --pretty=oneline)"
