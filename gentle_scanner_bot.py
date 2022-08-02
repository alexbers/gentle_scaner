import re
import socket
import os
import time
import json

from telegram import Update, ParseMode
from telegram.ext import Updater, CommandHandler, MessageHandler, CallbackContext, Filters, Defaults

from secrets import BOT_TOKEN


HELP_TEXT = r"""
*Tell me the IP and its description and I will continiously scan it for open ports*

Commands:
```
/add 127\.0\.0\.1 localhost
/show
/reset 127\.0\.0\.1 80
/del 127\.0\.0\.1
```
"""

def start(update, context):
    update.message.reply_text(HELP_TEXT)

def message(update, context):
    update.message.reply_text(HELP_TEXT)


def validate_ip(ip):
    if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip):
        return False
    try:
        socket.inet_aton(ip)
    except OSError:
        return False
    return True


def update_scanner_ips():
    ips = set()
    for d in os.listdir("db/bot"):
        if d.isnumeric() and os.path.isdir(f"db/bot/{d}"):
            for f in os.listdir(f"db/bot/{d}"):
                f = f.removesuffix(".txt")
                if validate_ip(f):
                    ips.add(f)

    # atomicaly write to db/ips.txt
    with open("db/ips.txt.new", "w") as f:
        f.write("\n".join(ips))

    os.rename("db/ips.txt.new", "db/ips.txt")

def fmt(text):
    return "```\n" + text + "\n```"

def add(update, context):
    fields = re.split(r"\s+", update.message.text, 2)
    if len(fields) == 3:
        command, ip, description = fields
    elif len(fields) == 2:
        command, ip, description = fields[0], fields[1], ""
    else:
        update.message.reply_text("bad args")
        return

    if not validate_ip(ip):
        update.message.reply_text("bad ip")
        return

    # normalize ip
    ip = socket.inet_ntoa(socket.inet_aton(ip))

    if not re.fullmatch(r"[\w. _()-]+", description):
        update.message.reply_text("bad description")
        return

    from_id = int(update.message.chat.id)

    try:
        os.makedirs(f"db/bot/{from_id}", exist_ok=True)
        open(f"db/bot/{from_id}/{ip}.txt", "w").write(description)
    except OSError:
        update.message.reply_text("saving error")
        return

    update.message.reply_text("ok")
    update_scanner_ips()


def del_ip(update, context):
    fields = re.split(r"\s+", update.message.text, 1)
    if len(fields) == 2:
        command, ip = fields
    else:
        update.message.reply_text("bad args")
        return

    if not validate_ip(ip):
        update.message.reply_text("bad ip")
        return

    from_id = int(update.message.chat.id)

    try:
        os.unlink(f"db/bot/{from_id}/{ip}.txt")
    except FileNotFoundError:
        update.message.reply_text("ip not found")
        return

    except OSError:
        update.message.reply_text("saving error")
        return

    update.message.reply_text("ok")
    update_scanner_ips()


def show(update, context):
    from_id = int(update.message.chat.id)

    try:
        files = os.listdir(f"db/bot/{from_id}")
    except OSError:
        update.message.reply_text("no address added yet")
        return

    ips = [f.removesuffix(".txt") for f in files if validate_ip(f.removesuffix(".txt"))]

    ans = ""

    for ip in sorted(ips):
        desc = ""
        try:
            desc = open(f"db/bot/{from_id}/{ip}.txt").read()
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
            for line in open(f"db/bot/{from_id}/ignore_ports.txt"):
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

        stats = {}

        try:
            stats = json.load(open(f"db/stats.txt"))
        except Exception as E:
            pass

        ans += f"{ip} {desc} ({stats.get(ip, 0)} port probes):\n"
        if not ports:
            ans += f"  no open ports yet"
        else:
            for port in sorted(ports):
                sec_ago = int(time.time()) - ports[port]
                if sec_ago > 86400:
                    ago_text = f"{sec_ago//86400} days ago"
                elif sec_ago > 3600:
                    ago_text = f"{sec_ago//3600} hours ago"
                elif sec_ago > 60:
                    ago_text = f"{sec_ago//60} minutes ago"
                else:
                    ago_text = f"{sec_ago} seconds ago"

                ans += f"  {port:5d} {ago_text}\n"

    update.message.reply_text(fmt(ans))


def reset(update, context):
    fields = re.split(r"\s+", update.message.text, 2)
    if len(fields) == 3:
        command, ip, port = fields
    else:
        update.message.reply_text("bad args")
        return

    if not validate_ip(ip):
        update.message.reply_text("bad ip")
        return

    try:
        port = int(port)
    except ValueError:
        update.message.reply_text("bad port")
        return

    from_id = int(update.message.chat.id)

    try:
        os.makedirs(f"db/bot/{from_id}", exist_ok=True)
        open(f"db/bot/{from_id}/ignore_ports.txt", "a").write(f"{ip} {port} {int(time.time())}\n")

        try:
            os.unlink(f"db/bot/{from_id}/{ip}_{port}.txt")
        except FileNotFoundError:
            pass

    except OSError:
        update.message.reply_text("saving error")
        return

    update.message.reply_text("ok")
    update_scanner_ips()



def main():
    updater = Updater(BOT_TOKEN, defaults=Defaults(parse_mode=ParseMode.MARKDOWN_V2))

    dispatcher = updater.dispatcher
    dispatcher.add_handler(CommandHandler("start", start))
    dispatcher.add_handler(CommandHandler("help", start))
    dispatcher.add_handler(CommandHandler("add", add))
    dispatcher.add_handler(CommandHandler("del", del_ip))
    dispatcher.add_handler(CommandHandler("show", show))
    dispatcher.add_handler(CommandHandler("reset", reset))
    dispatcher.add_handler(MessageHandler(Filters.all, message))

    updater.start_polling()


if __name__ == "__main__":
    main()
