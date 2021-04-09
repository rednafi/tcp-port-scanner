<div align="center">

<h1>TCP Port Scanner</h1>
<strong>Simple IPV4 Port Scanner Leveraging Python's Asyncio</strong>
<br> <br>
</div>

## Description

The title says it all. I just wanted to take a dabble in Python's Asyncio before putting Asyncio driven code in production. TCP scanner is the perfect little program to learn—asynchronous queueing, exception handling, and running blocking code in executor. So here it goes.

## Installation

You don't need another pip package in your life. So, if you want to test this out:

* Clone the repo.

* `cd` to root directory.

* Fire up a Python virtual environment and run:
    ```
    pip install -r requirements.txt
    ```

* Check the options:
    ```
    python -m scanner -h
    ```

    This should print out the following:

    ```
    usage: scanner.py [-h] --ip IP [--ports PORTS] [--timeout TIMEOUT]

    The strangely familiar TCP port scanner ⚙️

    optional arguments:
    -h, --help         show this help message and exit
    --ip IP            target ip address [example: --ip '127.0.0.1']
    --ports PORTS      port string [example: --ports '100, 200, 8080-9000']
    --timeout TIMEOUT  add timeout [example --timeout '5.9']

    ```

* Take it for a test drive:
    ```
    python -m scanner --ip=$(dig +short github.com) --ports="1-500"
    ```

    The output should look like the following:

    ```
    Open Ports
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
    ┃ IP                              ┃ Ports        ┃
    ┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
    │ 192.30.255.113                  │ 22           │
    │                                 │ 80           │
    │                                 │ 443          │
    └─────────────────────────────────┴──────────────┘
    ```
