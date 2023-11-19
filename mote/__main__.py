import csv

import json
import logging
import socket
import random
import shutil
import pathlib
import time

from .log import logger
from . import mac, network
from .cli import define_parser
from .config import Config, load_config, parse_config
from .exceptions import *
from .fuzzer import *

def init_gateway(args):
    base_config_dir = pathlib.Path(args.config)
    config = load_config(base_config_dir / 'config.json')
    target = (config.dest.hostname, config.dest.port)
    local = (config.src.hostname, config.src.port)
    gateway_file = base_config_dir / 'gateway.json'
    with open(gateway_file) as f:
        gateway_conf = json.load(f)
    gweui = gateway_conf.get('GatewayEUI')
    gateway = mac.Gateway(gweui)
    udp_client = network.UDPClient(target, address=local, timeout=config.timeout)
    return gateway, udp_client


def init_mote(args):
    base_config_dir = pathlib.Path(args.config)
    base_model_dir = pathlib.Path(args.model)
    original_file = base_config_dir / 'device.json'
    device_file = base_model_dir / 'device.pkl'

    with open(original_file) as f:
        device_conf = parse_config(json.load(f), Config())


    if args.command == 'join' and args.new:
        appkey = device_conf.RootKeys.AppKey
        nwkkey = device_conf.RootKeys.NwkKey
        device_info = device_conf.Device
        joineui = device_info.JoinEUI
        deveui = device_info.DevEUI
        mote = mac.Mote(joineui, deveui, appkey, nwkkey)
    else:
        try:
            mote = mac.Mote.load(device_file)
            
        except FileNotFoundError:
            raise NewDeviceError('-n') from None
    return mote


def main():
    logger = logging.getLogger('main')
    try:
        args = define_parser().parse_args()
        print(args)
        gateway, udp_client = init_gateway(args)
        if args.command == 'pull':
            gateway.pull(udp_client)
        else:
            mote = init_mote(args)
            if args.command == 'join':
                phypld = mote.form_join()
            elif args.command == 'app':
                fopts = bytes.fromhex(args.fopts) if args.fopts else b''
                fport = getattr(args, "fport", None)
                fport = fport if fport is not None else random.randint(1, 223)
                msg = args.msg.encode()
                print(msg)
                phypld = mote.form_phypld(fport, msg, fopts, unconfirmed=args.unconfirmed, ack=args.ack)

            elif args.command == 'fuzz':
                test_results = []
                msg_list = get_string_list(args.msg)
                i = 1

                for msg in msg_list:
                    result = {
                        "Data": msg,
                        "ACK": False, 
                        "RESP": False,
                        "MACPayload": "", 
                        "DevAddr": "" 
                    }

                    fopts = bytes.fromhex(args.fopts) if args.fopts else b''
                    fport = getattr(args, "fport", None)
                    fport = fport if fport is not None else random.randint(1, 223)
                    msg = msg.encode()

                    print(f"# ------round : {i} ------#")
                    print(f"# ------test_DATA : {msg} ------#")
                    i = i+1
                    
                    gateway.pull(udp_client)
                    time.sleep(1)

                    phypld = mote.form_phypld(fport, msg, fopts, unconfirmed=args.unconfirmed, ack=args.ack)

                    gateway.push(udp_client, phypld, mote, result)
                    time.sleep(1)
                    print(result)
                    test_results.append(result)

                filename = "Fuzzed_results.csv"

                with open(filename, 'w', newline='') as file:
                    writer = csv.DictWriter(file, fieldnames=["Data", "ACK", "RESP", "MACPayload", "DevAddr"])
                    writer.writeheader()
                    for result in test_results:
                        writer.writerow(result)
                
                exit(0)
            gateway.push(udp_client, phypld, mote)
    except socket.timeout as e:
        logger.error('Socket Timeout')
    except AttributeError as e:
        logger.error(' finish Join procedure.')
        logger.exception(e)
    except FileNotFoundError as e:
        print(e)
        logger.error("Config files not found,.")
    except (MICError, StructParseError, FOptsError, NewDeviceError, ActivationError) as e:
        logger.error(e)
    except NotImplementedError as e:
        logger.error(e)
    except json.decoder.JSONDecodeError as e:
        logger.error('Bad config file format.')
        print(e)
    except Exception as e:
        logger.exception(e)

