#!/bin/sh
set -x
set -e
cd $(dirname $0)

sudo /etc/init.d/memcached restart

myuser=root
mydb=isu4_qualifier
myhost=127.0.0.1
myport=3306
mysql -h ${myhost} -P ${myport} -u ${myuser} -e "DROP DATABASE IF EXISTS ${mydb}; CREATE DATABASE ${mydb}"
mysql -h ${myhost} -P ${myport} -u ${myuser} ${mydb} < sql/schema.sql
mysql -h ${myhost} -P ${myport} -u ${myuser} ${mydb} < sql/dummy_users_3.sql
mysql -h ${myhost} -P ${myport} -u ${myuser} ${mydb} < sql/alter_user.sql
