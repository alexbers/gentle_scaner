import sys
import time
import os
import re
import socket

import telegram

from secrets import BOT_TOKEN, TG_ADMIN_ID


DELAY = 10

PAUSE_BETWEEN_MSGS = 2

def print_err(*params):
    print(*params, file=sys.stderr, flush=True)


def print_log(*params):
    print(*params, file=sys.stdout, flush=True)


def validate_ip(ip):
    if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip):
        return False
    try:
        socket.inet_aton(ip)
    except OSError:
        return False
    return True



def find_and_send_alerts(bot):
    accounts = [int(d) for d in os.listdir("db/bot")
                       if re.fullmatch("[0-9]+", d) and os.path.isdir(f"db/bot/{d}")]

    for account in accounts:
        notifications = []
        files = os.listdir(f"db/bot/{account}")
        ips = [f.removesuffix(".txt") for f in files if validate_ip(f.removesuffix(".txt"))]

        for ip in sorted(ips):
            desc = ""
            try:
                desc = open(f"db/bot/{account}/{ip}.txt").read()
            except OSError:
                pass

            ports = {}
            for port_file in os.listdir(f"db/{ip}"):
                try:
                    port = int(port_file.removesuffix(".txt"))
                except ValueError:
                    continue

                timestamp = 0
                try:
                    timestamp = open(f"db/{ip}/{port_file}").read()
                    timestamp = int(timestamp)
                except OSError:
                    pass

                ports[port] = timestamp

            try:
                for line in open(f"db/bot/{account}/ignore_ports.txt"):
                    ign_ip, port, timestamp = line.strip().split(" ", 2)
                    port = int(port)
                    timestamp = int(timestamp)
                    if not validate_ip(ign_ip):
                        continue

                    # remove ignored ports
                    if ip == ign_ip and port in ports and ports[port] < timestamp:
                        del ports[port]
            except OSError:
                pass

            for port in list(ports):
                if os.path.exists(f"db/bot/{account}/{ip}_{port}.txt"):
                    if port in ports:
                        del ports[port]

            if ports:
                notifications.append([ip, desc, list(ports)])

        ## send notifications
        if notifications:
            msg = "**New ports are opened**\n```\n"

            for ip, desc, ports in notifications:
                msg += f"{ip} {desc}: {', '.join(map(str, list(ports)))}\n"
            msg += "```\n"

            bot.send_message(text=msg, chat_id=account, parse_mode=telegram.ParseMode.MARKDOWN_V2)
            time.sleep(PAUSE_BETWEEN_MSGS)

            for ip, desc, ports in notifications:
                for port in ports:
                    try:
                        open(f"db/bot/{account}/{ip}_{port}.txt", "w").write(str(int(time.time())))
                    except OSError as E:
                        print_err(f"failed to store notification status {E}")


def main():
    bot = telegram.Bot(token=BOT_TOKEN)
    # bot.send_message(text="Hello", chat_id=53684567)

    while True:
        try:
            print_log("New iter")
            find_and_send_alerts(bot)
        except Exception as E:
            print_err(f"exception {E}")
            import traceback
            traceback.print_exc()
        finally:
            time.sleep(DELAY)



if __name__ == "__main__":
    main()