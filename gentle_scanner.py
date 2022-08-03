import asyncio
import re
import sys
import time
import os
import json

from ports import gen_ports

TIMEOUT = 10
UPDATE_HOSTLIST_INTERVAL = 5


ip_to_task = {}
ip_to_count = {}


def print_err(*params):
    print(*params, file=sys.stderr, flush=True)


def print_log(*params):
    print(*params, file=sys.stdout, flush=True)


def setup_files_limit():
    try:
        import resource
        soft_fd_limit, hard_fd_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard_fd_limit, hard_fd_limit))
    except (ValueError, OSError):
        print_err("failed to increase the limit of opened files")
    except ImportError:
        pass


def register_port_up(ip, port):
    port = int(port)
    if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip, re.ASCII):
        print_err(f"failed to register port up bad ip {ip} {port}")
        return

    try:
        os.makedirs(f"db/{ip}", exist_ok=True)
        open(f"db/{ip}/{port}.txt", "w").write(str(int(time.time())))
    except OSError as E:
        print_err(f"failed to register port up {ip} {port} {E}")


async def port_is_up(ip, port):
    global ip_to_count
    ip_to_count[ip] = ip_to_count.get(ip, 0) + 1

    try:
        task = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(task, timeout=TIMEOUT)
        writer.close()

        register_port_up(ip, port)

        return True
    except ConnectionRefusedError:
        return False
    except Exception as E:
        return False


async def scan(ip):
    global ip_to_task
    for port, timestamp in gen_ports():
        if ip not in ip_to_task:
            break
        await asyncio.sleep(max(0, timestamp - time.time()))
        # await asyncio.sleep(0)
        asyncio.create_task(port_is_up(ip, port), name=f"scan_{ip}_{port}")


def load_ips():
    ret = [line for line in map(str.strip, open("db/ips.txt", "r"))
                if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", line, re.ASCII)]
    return ret



async def main():
    ips = []

    while True:
        try:
            ips = load_ips()
        except Exception as E:
            print_err(f"failed to load ip list: {E}")

        for ip in ips:
            if ip not in ip_to_task:
                print_log(f"start scan {ip}")
                ip_to_task[ip] = asyncio.create_task(scan(ip), name=f"scan_{ip}")

        for ip in set(ip_to_task) - set(ips):
            print_log(f"stop scan {ip}")
            del ip_to_task[ip]

        print_log(f"checked ports: {sum(ip_to_count.values())}")

        try:
            open("db/stats.txt", "w").write(json.dumps(ip_to_count))
        except OSError as E:
            print_err(f"failed to write stats {E}")
        await asyncio.sleep(UPDATE_HOSTLIST_INTERVAL)


if __name__ == "__main__":
    setup_files_limit()
    asyncio.run(main())
