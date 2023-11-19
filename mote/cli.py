import argparse

def define_parser():
    message_lst = ['join', 'app', 'pull', 'fuzz']
    parser = argparse.ArgumentParser(
        description=f'{message_lst}'
    )
    parser.add_argument(
        '-c',
        '--config',
        type=str,
        default="./config",
    )
    parser.add_argument(
        '--model',
        type=str,
        default="./models",
    )
    sub_parsers = parser.add_subparsers(title="sub", dest="command")
    join_parser = sub_parsers.add_parser("join", help="Send join request.", description="Send a join reques.")
    join_parser.add_argument(
        '-n', '--new', help=('.'), dest='new', action='store_true'
    )
    app_parser = sub_parsers.add_parser("app", help="Send application data.", description="Send a normal application data.")
    app_parser.add_argument(
        '-f', help='FOpts field.', dest='fopts'
    )
    app_parser.add_argument(
        '-u', '--unconfirmed', help='unconfirmed data.', dest='unconfirmed', action='store_true'
    )
    app_parser.add_argument(
        '-a', '--ack', help=('ack of downlink message.'), dest='ack', action='store_true'
    )

    def check_fport(value):
        ivalue = int(value)
        if 0 < ivalue <= 223:
            return ivalue
        else:
            raise argparse.ArgumentTypeError(f"FPort {ivalue} exceeds range [1, 223].")

    app_parser.add_argument(
        '-p', '--fport', help=('Specify the FPort of uplink message.'), dest='fport', type=check_fport
    )
    app_parser.add_argument(
        "msg", help="Message to be sent, 'str' required, default empty string.", default=""
    )
    pull_parser = sub_parsers.add_parser("pull", help="Send PULL_DATA.")

    fuzz_parser = sub_parsers.add_parser("fuzz", help="Send Fuzzed_PULL_DATA")
    fuzz_parser.add_argument(
        "msg", help="Message to be fuzzed, 'str' required, default empty string.", default=""
    )
    fuzz_parser.add_argument(
        '-p', '--fport', help=('Specify the FPort of uplink message.'), dest='fport', type=check_fport
    )
    fuzz_parser.add_argument(
        '-f', help='FOpts field.', dest='fopts'
    )
    fuzz_parser.add_argument(
        '-u', '--unconfirmed', help='unconfirmed data.', dest='unconfirmed', action='store_true'
    )
    fuzz_parser.add_argument(
        '-a', '--ack', help=('ack of downlink message.'), dest='ack', action='store_true'
    )


    return parser

__all__ = ['define_parser']
