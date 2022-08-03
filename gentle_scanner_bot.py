import re
import socket
import os
import time
import json

import hostlist
from telegram import Update, ParseMode
from telegram.ext import Updater, CommandHandler, MessageHandler, CallbackContext, Filters, Defaults

from secrets import BOT_TOKEN


HELP_TEXT = r"""
*Tell me the IP and its description and I will continiously scan it for open ports*

Commands:
```
/add   - add a new host
/hosts - print hosts list
/port  - print ports list
/reset - reenable alert on host and port
/del   - delete a host
```
"""

ADD_TEXT = r"""
*Send me ip and description to add host to scanlist*

Examples:
127\.0\.0\.1 localhost
127\.0\.0\.\[1\-2,4\] several hosts
"""

DEL_TEXT = r"""
*Send me ip to del host to scanlist*

Examples:
127\.0\.0\.1
127\.0\.0\.\[1\-2,4\]
"""

RESET_TEXT = r"""
*Send me ip and port to reset port detection and alert the next time it opens*

Examples:
127\.0\.0\.1 80
"""

# STATES: IDLE, AWAIT_ADD, AWAIT_DEL, AWAIT_RESET

def get_user_state(from_id):
    try:
        return open(f"db/bot/{from_id}/state.txt").read().strip()
    except OSError:
        return "IDLE"


def set_user_state(from_id, state):
    os.makedirs(f"db/bot/{from_id}", exist_ok=True)
    open(f"db/bot/{from_id}/state.txt", "w").write(state)


def start_cmd(update, context):
    from_id = int(update.message.chat.id)
    set_user_state(from_id, "IDLE")

    update.message.reply_text(HELP_TEXT)

def message(update, context):
    from_id = int(update.message.chat.id)

    state = get_user_state(from_id)

    if state == "IDLE":
        update.message.reply_text(HELP_TEXT)
    elif state == "AWAIT_ADD":
        add(update, context)
    elif state == "AWAIT_DEL":
        del_ip(update, context)
    elif state == "AWAIT_RESET":
        reset(update, context)


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

def add_cmd(update, context):
    from_id = int(update.message.chat.id)

    set_user_state(from_id, "AWAIT_ADD")
    update.message.reply_text(ADD_TEXT)

def add(update, context):
    fields = re.split(r"\s+", update.message.text, 1)
    if len(fields) == 2:
        ip_hostlist, description = fields
    else:
        update.message.reply_text("bad args")
        return

    try:
        ips = hostlist.expand_hostlist(ip_hostlist)
    except hostlist.BadHostlist:
        update.message.reply_text("bad ip")
        return

    MAX_IPS_PER_REQ = 256
    if len(ips) > MAX_IPS_PER_REQ:
        update.message.reply_text("too many ips")
        return

    if not re.fullmatch(r"[\w. _()-]+", description):
        update.message.reply_text("bad description")
        return

    from_id = int(update.message.chat.id)

    try:
        os.makedirs(f"db/bot/{from_id}", exist_ok=True)
    except OSError:
        update.message.reply_text("db error")
        return

    count = 0
    for ip in ips:
        if not validate_ip(ip):
            continue

        # normalize ip
        ip = socket.inet_ntoa(socket.inet_aton(ip))

        try:
            open(f"db/bot/{from_id}/{ip}.txt", "w").write(description)
            count += 1
        except OSError:
            continue

    update.message.reply_text(f"ok, {count} good ips added")
    update_scanner_ips()


def del_cmd(update, context):
    from_id = int(update.message.chat.id)

    set_user_state(from_id, "AWAIT_DEL")
    update.message.reply_text(DEL_TEXT)


def del_ip(update, context):
    fields = re.split(r"\s+", update.message.text, 1)
    if len(fields) == 1:
        ip_hostlist = fields[0]
    else:
        update.message.reply_text("bad args")
        return

    try:
        ips = hostlist.expand_hostlist(ip_hostlist)
    except hostlist.BadHostlist:
        update.message.reply_text("bad ip")
        return

    MAX_IPS_PER_REQ = 256
    if len(ips) > MAX_IPS_PER_REQ:
        update.message.reply_text("too many ips")
        return

    from_id = int(update.message.chat.id)

    count = 0
    for ip in ips:
        if not validate_ip(ip):
            continue

        try:
            os.unlink(f"db/bot/{from_id}/{ip}.txt")
            count += 1
        except FileNotFoundError:
            continue
        except OSError:
            continue

    update.message.reply_text(f"ok, {count} good ips deleted")
    update_scanner_ips()


def hosts_cmd(update, context):
    from_id = int(update.message.chat.id)

    set_user_state(from_id, "IDLE")

    try:
        files = os.listdir(f"db/bot/{from_id}")
    except OSError:
        update.message.reply_text("no address added yet")
        return


    ips = [f.removesuffix(".txt") for f in files if validate_ip(f.removesuffix(".txt"))]

    desc_to_ips = {}

    for ip in sorted(ips):
        desc = ""
        try:
            desc = open(f"db/bot/{from_id}/{ip}.txt").read()
        except OSError:
            pass

        desc_to_ips[desc] = desc_to_ips.get(desc, []) + [ip]

    ans = []

    for desc in desc_to_ips:
        ans.append(f"{desc}:")
        ans.append("  " + hostlist.collect_hostlist(desc_to_ips[desc]))

    LINES_PER_MSG = 30

    for start_line in range(0, len(ans), LINES_PER_MSG):
        msg = "\n".join(ans[start_line:start_line + LINES_PER_MSG])
        update.message.reply_text(fmt(msg))


def ports_cmd(update, context):
    from_id = int(update.message.chat.id)

    set_user_state(from_id, "IDLE")

    try:
        files = os.listdir(f"db/bot/{from_id}")
    except OSError:
        update.message.reply_text("no address added yet")
        return

    ips = [f.removesuffix(".txt") for f in files if validate_ip(f.removesuffix(".txt"))]

    ans = []

    no_port_ips = []

    for ip in sorted(ips):
        desc = ""
        try:
            desc = open(f"db/bot/{from_id}/{ip}.txt").read()
        except OSError:
            pass

        try:
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
        except FileNotFoundError:
            pass


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

        if not ports:
            no_port_ips.append(ip)
        else:
            ans.append(f"{ip} {desc} ({stats.get(ip, 0)} probes):")
            for port in sorted(ports):
                sec_ago = int(time.time()) - ports[port]
                if sec_ago > 86400:
                    ago_text = f"{sec_ago//86400} days ago"
                elif sec_ago > 3600:
                    ago_text = f"{sec_ago//3600} hours ago"
                elif sec_ago > 60:
                    ago_text = f"{sec_ago//60} mins ago"
                else:
                    ago_text = f"{sec_ago} secs ago"

                ans.append(f"  {port:5d} {ago_text}")

    LINES_PER_MSG = 30

    for start_line in range(0, len(ans), LINES_PER_MSG):
        msg = "\n".join(ans[start_line:start_line + LINES_PER_MSG])
        update.message.reply_text(fmt(msg))


def reset_cmd(update, context):
    from_id = int(update.message.chat.id)

    set_user_state(from_id, "AWAIT_RESET")
    update.message.reply_text(RESET_TEXT)


def reset(update, context):
    fields = re.split(r"\s+", update.message.text, 2)
    if len(fields) == 2:
        ip, port = fields
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
    dispatcher.add_handler(CommandHandler("start", start_cmd))
    dispatcher.add_handler(CommandHandler("help", start_cmd))
    dispatcher.add_handler(CommandHandler("add", add_cmd))
    dispatcher.add_handler(CommandHandler("del", del_cmd))
    dispatcher.add_handler(CommandHandler("hosts", hosts_cmd))
    dispatcher.add_handler(CommandHandler("ports", ports_cmd))
    dispatcher.add_handler(CommandHandler("reset", reset_cmd))
    dispatcher.add_handler(MessageHandler(Filters.all, message))

    updater.start_polling()


if __name__ == "__main__":
    main()
