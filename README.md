The gentle scanner. Like an nmap, but gentle and continious.

- No more than 1 packet per second per host
- Fair TCP connections, not only SYN
- Alerts and scan control with Telegram as bot
- Popular ports are scanned more often, every 10 minutes
- Less popular ports are rescanned every hour
- The rest ports are rescanned every 24 hours

# Running

Put your bot token in secrets.py. See the secrets.py.example

```docker-compose up -d```
