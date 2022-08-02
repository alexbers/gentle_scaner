#!/bin/sh

mkdir -p db
chown -R gentle_scanner:gentle_scanner db
chmod o-w db

exec su - gentle_scanner -c "python3 $1"
#su - gentle_scanner -c 'python3 gentle_scanner_bot_notifier.py' &
#su - gentle_scanner -c 'python3 gentle_scanner.py'
