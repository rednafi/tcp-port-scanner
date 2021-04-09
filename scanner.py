"""
A strangely familiar TCP Scanner that leverages Python's Asyncio
The only external depenency is Rich. Install rich via running:

`pip install rich`
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import itertools
import re

from rich import traceback
from rich.console import Console
from rich.table import Table

MAX_CONSUMERS = 1000

traceback.install()
console = Console()


class InvalidFormatError(BaseException):
    """Raised when the ip address and port are not of the following formats:

    ip: ipv4 format
        '172.217.163.78'

    port: individual or port range
        '80, 443' or '80, 5000, 5000-6000'

    """


class InvalidValueError(BaseException):
    """Raised when port value is not between -1 and 65535."""


def split_addr(ip_port: tuple[str, int]) -> tuple[int, ...]:
    """Split ip address and port for sorting later.

    Example
    --------
    >>> split_addr(('172.217.163.78', 80))
    >>> (172, 217, 163, 78, 80)
    """

    split = [int(i) for i in ip_port[0].split(".")]
    split.append(ip_port[1])

    return tuple(split)


def print_addrs(open_addrs: list[tuple[str, int]]) -> None:
    """Make a table using Rich to display the IP address and the open ports."""

    table = Table(
        show_header=True,
        header_style="bold magenta",
        width=50,
        title="Open Ports",
        title_style="bold Cyan",
        title_justify="left",
    )
    table.add_column("IP")
    table.add_column("Ports")

    for idx, open_port in enumerate(open_addrs):
        if idx == 0:
            table.add_row(open_port[0], str(open_port[1]))
        else:
            table.add_row("", str(open_port[1]))
    console.print()
    console.print(table)


def parse_ports(port_str: str) -> tuple[int, ...]:
    """
    syntax: port,port-range,...
    use regex to verify input validity, then create a tuple of
    ports used in port scan. there definitely some room for optimization
    here, but it won't matter much. go optimize the coroutines instead.
    """
    if not re.match(r"[\d\-,\s]+", port_str):
        raise InvalidFormatError("invalid port string format")

    ports = []
    port_list = [x for x in port_str.split(",") if x]

    for port in port_list:
        if "-" in port:
            try:
                port = [int(p) for p in port.split("-")]
            except ValueError:
                raise InvalidFormatError("port string formatting is not correct")

            # This handles the case where start range is greater than end range.
            start = min(port[0], port[-1])
            end = max(port[0], port[-1])

            for p in range(start, end):
                if not (-1 < p < 65536):
                    raise InvalidValueError("ports must be between 0 and 65535")
                ports.append(p)

        else:
            port = int(port)
            if not (-1 < port < 65536):
                raise InvalidValueError("ports must be between 0 and 65535")

            ports.append(port)

    return tuple(set(ports))


async def producer(
    host: str,
    ports: tuple[str, ...],
    timeout: float,
    task_queue: asyncio.Queue,
) -> None:

    """Add jobs to a queue, up to `MAX_CONSUMERS` at a time"""
    host = host.replace("/32", "")

    try:
        hosts = [str(host) for host in ipaddress.ip_network(host).hosts()]
    except ValueError:
        raise InvalidFormatError("ip address format is incorrect")

    for ip, port in itertools.product(hosts, ports):
        task_queue.put_nowait((ip, port, timeout))


async def consumer(task_queue: asyncio.Queue, result_queue: asyncio.Queue) -> None:
    """Pull connection information from queue and attempt connection."""

    while not task_queue.empty():
        ip, port, timeout = await task_queue.get()
        conn = asyncio.open_connection(ip, port)
        try:
            await asyncio.wait_for(conn, timeout)
        except asyncio.TimeoutError:
            pass
        else:
            result_queue.put_nowait((ip, port))
        finally:
            task_queue.task_done()


async def orchestrator(host: str, port_str=None, timeout=2) -> None:
    """Coordinates the producer and the consumer tasks."""

    task_queue = asyncio.Queue()
    result_queue = asyncio.Queue()

    if port_str is None:
        # NOTE: This is a string not a tuple.
        # A few common ports.
        port_str = (
            "9,20-23,25,37,41,42,53,67-70,79-82,88,101,102,107,109-111,"
            "113,115,117-119,123,135,137-139,143,152,153,156,158,161,162,170,179,"
            "194,201,209,213,218,220,259,264,311,318,323,383,366,369,371,384,387,"
            "389,401,411,427,443-445,464,465,500,512,512,513,513-515,517,518,520,"
            "513,524,525,530,531,532,533,540,542,543,544,546,547,548,550,554,556,"
            "560,561,563,587,591,593,604,631,636,639,646,647,648,652,654,665,666,"
            "674,691,692,695,698,699,700,701,702,706,711,712,720,749,750,782,829,"
            "860,873,901,902,911,981,989,990,991,992,993,995,8080,2222,4444,1234,"
            "12345,54321,2020,2121,2525,65535,666,1337,31337,8181,6969"
        )

    ports = parse_ports(port_str)

    # Execute the producer.
    tasks = []
    await producer(host, ports, timeout, task_queue)

    # Execute the consumer.
    for _ in range(MAX_CONSUMERS):
        tasks.append(asyncio.create_task(consumer(task_queue, result_queue)))

    with console.status("[bold green]Scanning..."):
        task_queue_complete = asyncio.create_task(task_queue.join())

        await asyncio.wait(
            [task_queue_complete, *tasks],
            return_when=asyncio.FIRST_EXCEPTION,
        )

        if not task_queue_complete.done():
            for task in tasks:
                if task.done():
                    task.result()
                    task.cancel()

    open_ports = []

    while result_queue.qsize():
        open_ports.append(await result_queue.get())

    open_ports.sort(key=split_addr)
    print_addrs(open_ports)


class CLI:
    def build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            description="The strangely familiar TCP port scanner ⚙️\n"
        )

        # Add arguments.
        parser.add_argument(
            "--ip",
            help="target ip address [example: --ip '127.0.0.1']",
            required=True,
        )
        parser.add_argument(
            "--ports",
            help="port string [example: --ports '100, 200, 8080-9000']",
            required=False,
        )
        parser.add_argument(
            "--timeout",
            help="add timeout [example --timeout '5.9']",
            required=False,
        )
        return parser

    def trigger_handler(self, args: argparse.Namespace) -> None:
        if args.timeout is not None:
            asyncio.run(orchestrator(args.ip, args.ports, float(args.timeout)))
        else:
            asyncio.run(orchestrator(args.ip, args.ports))

    def entrypoint(self, argv=None) -> None:
        parser = self.build_parser()
        args = parser.parse_args(argv)
        # Raise arg errors.
        self.trigger_handler(args)


if __name__ == "__main__":
    cli = CLI()
    cli.entrypoint()
