import csv

import pdb
import base64
import json
import logging
import math
import pickle
import random
import secrets
import struct
import socket
import time
import pathlib

from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from collections import ChainMap, namedtuple

from .exceptions import *

GMTformat = "%Y-%m-%d %H:%M:%S GMT"

logger = logging.getLogger('main')

MHDR_LEN = 1
MTYPE_OFFSET = 5
JOINACPT_CFLIST_OFFSET = 12
AES_BLOCK = 16
MIC_LEN = 4
DEVNONCE_LEN = 2
DEVADDR_LEN = 4
FCTRL_LEN = 1
FCNT_LEN = 2
FPORT_LEN = 1

def parse_bytes(typ, fmt, data):
    try:
        return struct.unpack(fmt, data)
    except struct.error:
        raise StructParseError(typ, fmt, data) from None


class Gateway:
    pushack_f = '<s2ss'
    pullresp_f = '<s2ss'
    txdr2datr = {
        0: 'SF12BW125',
        1: 'SF11BW125',
        2: 'SF10BW125',
        3: 'SF9BW125',
        4: 'SF8BW125',
        5: 'SF7BW125',
        6: 'SF7BW250',
        7: 50000,
    }

    def __init__(self, gweui):
        self.gweui = bytes.fromhex(gweui)
        self.version = b'\x02'
        self.token_length = 2

    def add_data(self, rxpk, data):

        rxpk['rxpk'][0].update({
            'size': len(data),
            'data': data,
        })
        return rxpk

    @property
    def stat(self):

        return {
            "stat": {
                "time": time.strftime(GMTformat, time.localtime()),
                "lati": 39.9075,
                "long": 116.38806,
                "rxnb": 1,
                "rxok": 0,
                "rxfw": 0,
                "ackr": 0,
                "dwnb": 0,
                "txnb": 0,
            }
        }

    def form_rxpk(self, mote):

        return {
            'rxpk': [{
                "tmst": int(time.time()),
                "chan": mote.txch,
                "rfch": mote.txch,
                "freq": 868.3,
                "stat": 1,
                "modu": 'LORA',
                "datr": self.txdr2datr[mote.txdr],
                "codr": '4/5',
                "lsnr": 2,
                "rssi": -119,
                "size": 17,
                "data": '',
            }]
        }

    def form_push_pld(self, data, mote):

        data = self.b64data(data)
        payload = self.add_data(self.form_rxpk(mote), data)
        stat = self.stat
        payload.update(stat)
        return json.dumps(
            payload
        ).encode('ascii')

    def b64data(self, data):
        return base64.b64encode(data).decode()

    @property
    def pull_data(self):
        plldat_f = 's2ss8s'
        token = secrets.token_bytes(self.token_length)
        pull_id = b'\x02'
        logger.info(
            ('PULL DATA -\nVersion: {}, '
                'Token: {}, '
                'Identifier: {}, '
                'GatewayEUI: {}').format(
                    self.version.hex(),
                    token.hex(),
                    pull_id.hex(),
                    self.gweui.hex()
                ))

        return struct.pack(
            plldat_f,
            self.version,
            token,
            pull_id,
            self.gweui,
        )

    def pull(self, transmitter):
        """
        PULL_DATA:
        --------------------------------------------------
        |   Version    | Token | Identifier | GatewayEUI |
        --------------------------------------------------
        | 0x01 or 0x02 |2 bytes|    0x02    |   8 bytes  |
        --------------------------------------------------
        """
        transmitter.send(self.pull_data)
        res = transmitter.recv()
        self.parse_pullack(res[0])

    def parse_pullack(self, pullack):
        """
        PULL_ACK:
        --------------------------------------------------
        |   Version    | Token | Identifier | GatewayEUI |
        --------------------------------------------------
        | 0x01 or 0x02 |2 bytes|    0x04    |   8 bytes  |
        --------------------------------------------------
        """
        pullack = memoryview(pullack)
        pullack_f = '<s2ss'
        version, token, identifier = parse_bytes(
            'PULL_ACK',
            pullack_f,
            pullack
        )
        logger.info(
            ('PULL ACK -\nVersion: {}, '
                'Token: {}, '
                'Identifier: {}, '
                ).format(
                    version.hex(),
                    token.hex(),
                    identifier.hex(),
                    #gatewayeui.hex(),
                ))

    def form_pshdat(self, data, mote):
        """
        PUSH_DATA
        ------------------------------------------------------------
        |   Version    | Token | Identifier | GatewayEUI | Payload |
        ------------------------------------------------------------
        | 0x00 or 0x01 |2 bytes|    0x00    |   8 bytes  |    -    |
        ------------------------------------------------------------
        """
        payload = self.form_push_pld(data=data, mote=mote)
        token = secrets.token_bytes(self.token_length)
        push_id = b'\x00'
        logger.info(
            ('Sending a PUSH DATA -\nVerson: {}, '
                'Token: {}, '
                'Identifier: {}, '
                'GatewayEUI: {}').format(
                    self.version.hex(),
                    token.hex(),
                    push_id.hex(),
                    self.gweui.hex(),
                ))

        return b''.join([
            self.version,
            token,
            push_id,
            self.gweui,
            payload,
        ])

    def push(self, transmitter, data, mote, result):
        transmitter.send(self.form_pshdat(data, mote))
        pushack = transmitter.recv()
        
        self.parse_pushack(pushack[0])
        try:
            pullresp = transmitter.recv()
            result['ACK'] = True
        except socket.timeout as e:
            logger.info(
                ('No response is received from remote servers')
            )
        else:
            self.parse_pullresp(pullresp[0], mote, result)
            result['RESP'] = True

    def parse_pushack(self, pushack):
        """
        PUSH_ACK:
        -----------------------------------
        |  Version   | Token | Identifier |
        -----------------------------------
        |0x00 or 0x01|2 bytes|    0x01    |
        -----------------------------------
        """
        pushack = memoryview(pushack)
        version, token, identifier = parse_bytes(
            'PUSH_ACK',
            self.pushack_f,
            pushack
        )
        logger.info(
            ('Receiving a PUSH ACK -\n'
                'Version: {}, '
                'Token: {}, '
                'Identifier: {}').format(
                    version.hex(),
                    token.hex(),
                    identifier.hex(),
                ))

    def parse_pullresp(self, pullresp, mote, result):
        """
        ---------------------------------------------------------------
        | Protocol Version | PULL RESP Token | Identifier |  Payload  |
        ---------------------------------------------------------------
        |   0x01 or 0x02   |     2 bytes     |    0x03    |< 996 bytes|
        ---------------------------------------------------------------
        """
        pullresplen = len(pullresp)
        pullresp_f = self.pullresp_f + '{}s'.format(pullresplen - 4)
        version, token, identifier, txpk = parse_bytes(
            'PULL_RESP',
            pullresp_f,
            pullresp,
        )
        txpk = json.loads(txpk.decode('ascii'))['txpk']
        logger.info(
            ('Receiving a PULL RESP - \n'
                'Version: {}, '
                'Token: {}, '
                'Identifier: {} --').format(
                    version.hex(),
                    token.hex(),
                    identifier.hex(),
                ))
        self.parse_txpk(txpk, mote, result)

    def parse_txpk(self, txpk, mote, result):
        """
        ------------------------------
        |       Required Fields      |
        ------------------------------
        | time |       UTC time      |
        ------------------------------
        | rfch |    Antenna index    |
        ------------------------------
        | codr |    ECC code rate    |
        ------------------------------
        | ipol |         True        |
        ------------------------------
        |       Optional Fields      |
        ------------------------------
        | imme |      Immediately    |
        ------------------------------
        | tmst |     When to send    |
        ------------------------------
        | freq |         MHz         |
        ------------------------------
        | powe |     Output power    |
        ------------------------------
        | modu |    "FSK" or "LORA"  |
        ------------------------------
        | datr |    SFnBWm or k Hz   |
        ------------------------------
        | size |     Size of data    |
        ------------------------------
        | data |  base64 phypayload  |
        ------------------------------
        | ncrc |  Physical layer CRC |
        ------------------------------
        """
        phypld = memoryview(base64.b64decode(txpk.get('data')))
        mote.parse_phypld(phypld, result)
        

class Mote:
    joinmic_fields = namedtuple('joinmic', ('struct_f', 'field_name'))

    def __init__(self, joineui, deveui, appkey, nwkkey, dbpath='models', **kwargs):
        self.joineui = bytes.fromhex(joineui)
        self.deveui = bytes.fromhex(deveui)
        self.appkey, self.nwkkey = bytes.fromhex(appkey), bytes.fromhex(nwkkey)
        self.dbpath = pathlib.Path(dbpath)
        self.model_file = self.dbpath / "device.pkl"
        self.nonce_file = self.dbpath / "nonce.json"
        self._init_nonce_dic()
        self.txdr = 5 
        self.txch = 1 
        self.rjcount1 = 0 

        self.gen_jskeys()
        self.activation = False
        self.activation_mode = 'OTAA'
        self.version = "1.1"
        self.msg_file = "message.json"
        self.last_msg_acked = True
        self.acked_downlink = 0
        self.acked_uplink = 0
        self.save()

    def _init_nonce_dic(self):
        try:  
            self.nonce_dic = self.load_nonce()
        except (FileNotFoundError, json.decoder.JSONDecodeError):
            self.nonce_dic = {}
        finally:
            self.devnonce
            self.save_nonce()

    @property
    def devnonce(self):
        try:
            val = self.nonce_dic[self.deveui.hex()]
        except KeyError:
            self.devnonce = val = 0
        return val

    @devnonce.setter
    def devnonce(self, val):
        self.nonce_dic[self.deveui.hex()] = val

    def _initialize_session(self, optneg, devnonce):

        if optneg:
            if self.joinreqtyp == b'\xFF':
                nwkskey_prefix = b''.join([
                    self.joinnonce[::-1],
                    self.joineui[::-1],
                    struct.pack('<H', devnonce),
                ])
            else:
                nwkskey_prefix = b''.join([
                    self.joinnonce,
                    self.joineui,
                    bytes(2),
                ])
            fnwksint_msg, snwksint_msg, nwksenc_msg = [
                (prefix + nwkskey_prefix).ljust(AES_BLOCK, b'\x00')
                for prefix in (b'\x01', b'\x03', b'\x04')
            ]
            self.fnwksintkey, self.snwksintkey, self.nwksenckey = self.gen_keys(
                self.nwkkey, (fnwksint_msg, snwksint_msg, nwksenc_msg)
            )
            appsmsg = b''.join([
                b'\x02',
                self.joinnonce[::-1],
                self.joineui[::-1],
                struct.pack('<H', devnonce),
            ]).ljust(AES_BLOCK, b'\x00')
            self.appskey, = self.gen_keys(self.appkey, (appsmsg,))
        else:
            sesskey_prefix = b''.join([
                self.joinnonce[::-1],
                self.homenetid[::-1],
                struct.pack('<H', devnonce),
            ])
            apps_msg, fnwksint_msg = [
                (prefix + sesskey_prefix).ljust(AES_BLOCK, b'\x00')
                for prefix in (b'\x02', b'\x01')
            ]
            self.appskey, self.fnwksintkey = self.gen_keys(self.nwkkey, (apps_msg, fnwksint_msg))
            self.snwksintkey = self.nwksenckey = self.fnwksintkey
        self.fcntup = self.rjcount0 = 0
        self.activation = True
        self.save()

    @staticmethod
    def parse_byte(data: bytes, name: list, offset: list, bitlength: list):
        assert len(name) == len(offset) == len(bitlength)
        data = int.from_bytes(data, byteorder='little')
        res = [0 for _ in range(len(name))]
        for ind, value in enumerate(name):
            off, leng = offset[ind], bitlength[ind]
            binmask = '1'*leng + '0'*off
            mask = int(binmask, base=2)
            res[ind] = (data & mask) >> off
        return res

    @classmethod
    def load(cls, filename):
        with open(filename, 'rb') as f:
            obj = pickle.load(f)
        obj._init_nonce_dic()
        return obj

    def save(self):
        try:
            self.dbpath.mkdir()
        except FileExistsError:
            pass
        finally:
            with open(self.model_file, 'wb') as f:
                pickle.dump(self, f)

    def save_nonce(self):
        try:
            self.dbpath.mkdir()
        except FileExistsError:
            pass
        finally:
            with open(self.nonce_file, 'w') as f:
                json.dump(self.nonce_dic, f)

    def load_nonce(self):
        with open(self.nonce_file, "r") as f:
            nonce_dic = json.load(f)
        return nonce_dic

    def __str__(self):
        basic = (f'LoRa Motes Information:\n'
            f'DevEUI: {self.deveui.hex()}\n'
            f'JoinEUI: {self.joineui.hex()}\n'
            f'NwkKey: {self.nwkkey.hex()}\n'
            f'AppKey: {self.appkey.hex()}\n'
            f'Activation mode: {self.activation_mode}\n'
            f'Activation status: {self.activation}\n')
        extra = actv_extra = last_msg = ''
        if self.activation:
            extra = (f'\nDevAddr: {self.devaddr.hex()}\n'
                f'FCntUp: {self.fcntup}\n'
                f'ACKed Downlink Count: {self.acked_downlink}\n'
                f'ACKed Uplink Count: {self.acked_uplink}\n'
                f'JSIntKey: {self.jsintkey.hex()}\n'
                f'JSEncKey: {self.jsenckey.hex()}\n'
                f'FNwkSIntKey: {self.fnwksintkey.hex()}\n'
                f'SNwkSIntKey: {self.snwksintkey.hex()}\n'
                f'NwkSEncKey: {self.nwksenckey.hex()}\n'
                f'AppSKey: {self.appskey.hex()}\n'
            )
            if self.activation_mode == 'OTAA':
                actv_extra = (
                    f'JoinNonce: {self.joinnonce.hex()}\n'
                    f'DevNonce: {self.devnonce}\n'
                    f'Rjcount0: {self.rjcount0}\n'
                    f'Rjcount1: {self.rjcount1}\n'
                )
            if self.last_msg_acked:
                last_msg = (
                    f'Last message is acknowledged\n'
                )
            else:
                last_msg = (
                    f'Last message has not been acknowledged yet\n'
                )
        return basic + extra + actv_extra + last_msg

    def gen_jskeys(self):
        """
        ------------------------------
        | 0x06 \ 0x05 | DevEUI | pad |
        ------------------------------
        |    1 byte   | 8 bytes|  -  |
        ------------------------------
        """
        jsintkeymsg, jsenckeymsg = [
            (prefix + self.deveui[::-1]).ljust(AES_BLOCK, b'\x00') 
            for prefix in (b'\x06', b'\x05')
        ]
        self.jsintkey, self.jsenckey = self.gen_keys(self.nwkkey, (jsintkeymsg, jsenckeymsg))

    @staticmethod
    def bytes_xor(b1, b2):
        result = bytearray()
        for b1, b2 in zip(b1, b2):
            result.append(b1 ^ b2)
        return bytes(result)


    def form_fctrl(self, foptslen: int, ack: bool) -> bytes:
        """
        ---------------------------------------
        | ADR | RFU | ACK | ClassB | FOptsLen |
        ---------------------------------------
        |  0  |  0  |  0  |    0   |   0000   |
        ---------------------------------------
        """
        mask = 0x2F if ack else 0x0F
        return (mask & (foptslen | 0xF0)).to_bytes(1, 'big')

    def parse_fctrl(self, fctrl):
        """
        ---------------------------------------
        | ADR | RFU | ACK |FPending| FOptsLen |
        ---------------------------------------
        |  0  |  0  |  0  |    0   |   0000   |
        ---------------------------------------
        """
        name = ['adr', 'rfu', 'ack', 'fpending', 'foptslen']
        offset = (7, 6, 5, 4, 0)
        bitlength = [1, 1, 1, 1, 4]
        return self.parse_byte(fctrl, name=name, bitlength=bitlength, offset=offset)

    def form_fhdr(self, fopts, version='1.1', ack=False):
        """
        ----------------------------------
        | DevAddr | FCtrl | FCnt | FOpts |
        ----------------------------------
        |  0000   |   0   |  00  | 0 ~ 15|
        ----------------------------------
        """
        foptslen = len(fopts)
        fhdr_f = '<4ssH'
        if foptslen:
            if version == '1.1':
            # fOpts encryption is only required in LoRaWAN 1.1.
                fopts = self.encrypt(
                    self.nwksenckey,
                    fopts,
                    direction=0,
                    start=0,
                )
        fhdr_f = fhdr_f + '{}s'.format(foptslen)
        fctrl = self.form_fctrl(foptslen, ack)
        return struct.calcsize(fhdr_f), struct.pack(fhdr_f, self.devaddr[::-1], fctrl, self.fcntup, fopts)

    def parse_fhdr(self, macpld):
        const_len = DEVADDR_LEN + FCTRL_LEN + FCNT_LEN
        beforefopts_f = '<4ssH'
        devaddr, fctrl, fcnt = parse_bytes(
            'FHDR',
            beforefopts_f,
            macpld[:const_len]
        )
        adr, _, ack, fpending, foptslen = self.parse_fctrl(fctrl)
        fhdrlen = const_len + foptslen
        fopts = self.encrypt(
            self.nwksenckey,
            macpld[const_len:fhdrlen].tobytes(),
            direction=1,
            fcnt=fcnt,
            start=0
        )
        fhdr_d = dict(
            devaddr=devaddr,
            adr=adr,
            ack=ack,
            fpending=fpending,
            foptslen=foptslen,
            fcnt=fcnt,
            fopts=fopts
        )
        return fhdrlen, macpld[:fhdrlen], fhdr_d

    def calcmic_app(self, mhdr, fhdr, ack=False, fport=None, frmpld=None, direction=0, fcnt=0):
        """
        Downlink MIC B0:
        ------------------------------------------------------------------------------
        | 0x49 | ConfFCnt | 0x0000 | dir | DevAddr | AF(NF)CntDown | 0x00 | len(msg) |
        ------------------------------------------------------------------------------
        Downlink key: SNwkSIntKey

        Uplink MIC B0:
        ----------------------------------------------------------------
        | 0x49 | 0x00000000 | dir | DevAddr | FCntUp | 0x00 | len(msg) |
        ----------------------------------------------------------------
        B0 key: FNwkSIntKey

        B1:
        ----------------------------------------------------------------------------
        | 0x49 | ConfFCnt | TxDr | TxCh | dir | DevAddr | FCntUp | 0x00 | len(msg) |
        ----------------------------------------------------------------------------
        B1 key: SNwkSIntKey
        """
        msg_lst = [mhdr, fhdr]
        if fport is not None:
            msg_lst.append(fport.to_bytes(1, 'big'))
            msg_lst.append(frmpld)
        msg = b''.join(msg_lst)
        msglen = len(msg)

        B_f = '<cHBBB4sIBB'
        if direction == 0:
            fcnt = self.fcntup
            key = self.fnwksintkey
            conffcnt = 0 # ConfFCnt is zero in B0.
        else:
            key = self.snwksintkey
            conffcnt = self.fcntup - 1 if (ack) else 0 # divmod(self.acked_uplink, 2**16)[1] if (ack) else 0
        B0_elements = [
            b'\x49',
            conffcnt,
            0,
            0,
            direction,
            self.devaddr[::-1],
            fcnt,
            0,
            msglen
        ]
        B0 = struct.pack(
            B_f,
            *B0_elements,
        )
        fmsg = B0 + msg
        fcmacobj = CMAC.new(key, ciphermod=AES)
        fcmac = fcmacobj.update(fmsg)
        if direction == 0: # Only uplink message has B1
            B1_elements = B0_elements[:]
            conffcnt = 0 if ack else 0  # FIXME: ChirpStack uplink ConfFCnt always zero
            B1_elements[1:4] = [conffcnt, self.txdr, self.txch]
            B1 = struct.pack(
                B_f,
                *B1_elements,
            )
            smsg = B1 + msg
            scmacobj = CMAC.new(self.snwksintkey, ciphermod=AES)
            scmac = scmacobj.update(smsg)
            return scmac.digest()[:MIC_LEN//2] + fcmac.digest()[:MIC_LEN//2]
        else:
            return fcmac.digest()[:MIC_LEN]

    def calcmic_join(self, key, macpld, optneg=0):
        """
        Join request MIC fields:
        --------------------------------------
        | MHDR | JoinEUI | DevEUI | DevNonce |
        --------------------------------------
        |1 byte| 8 bytes |8 bytes |  2 bytes |
        --------------------------------------
        Key: NwkKey

        Rejoin 0 & 2 MIC fields:
        --------------------------------------------------
        | MHDR | Rejoin Type | NetID | DevEUI | RJcount0 |
        --------------------------------------------------
        |1 byte|    1 byte   |3 bytes|8 bytes |  2 bytes |
        --------------------------------------------------
        Key: SNwkSIntKey

        Rejoin 1 MIC fields:
        ----------------------------------------------------
        | MHDR | Rejoin Type | JoinEUI | DevEUI | RJcount1 |
        ----------------------------------------------------
        |1 byte|    1 byte   | 8 bytes |8 bytes | 2 bytes  |
        ----------------------------------------------------
        Key: JSIntKey

        Join accept MIC fields (OptNeg = 0, LoRaWAN 1.0):
        ----------------------------------------------------------------------
        | MHDR | JoinNonce | NetID | DevAddr | DLSettings | RxDelay | CFList |
        ----------------------------------------------------------------------
        |1 byte|  3 bytes  |3 bytes| 4 bytes |   1 byte   |  1 byte | 0 ~ 15 |
        ----------------------------------------------------------------------
        Key: NwkKey

        Join accept MIC fields (OptNeg = 1, LoRaWAN 1.1):
        -------------------------------------------------------------
        | JoinReqType | JoinEUI | DevNonce | MHDR | JoinNonce | NetID ...
        -------------------------------------------------------------
        |   1 byte    | 8 bytes | 2 bytes  |1 byte|  2 bytes  | Same above
        -------------------------------------------------------------
        Key: JSIntKey
        """
        if optneg:
            acptopt_f = '<s8sH'
            macpld = struct.pack(
                    acptopt_f,
                    self.joinreqtyp,
                    self.joineui[::-1],
                    self.devnonce,
                    ) + macpld

        cobj = CMAC.new(key, ciphermod=AES)
        cobj.update(macpld)
        return cobj.digest()[:MIC_LEN]

    def joinacpt_decrypt(self, macpld):
        """
        Decryption keys:
        ----------------------
        | ReqType |   Key    |
        ----------------------
        |  Join   |  NwkKey  |
        ----------------------
        | Rejoin  | JSEncKey |
        ----------------------
        """
        macpldlen = len(macpld)
        padding_size = (AES_BLOCK - macpldlen) % AES_BLOCK
        macpld = macpld + padding_size * b'\x00'
        cryptor = AES.new(self.joinenckey, AES.MODE_ECB)
        return cryptor.encrypt(macpld)

    def encrypt(self, key, payload, direction=0, fcnt=0, start=1):
        """
        Ai:
        -----------------------------------------------------------
        | 0x01 | 4 X 0x00 | Direction | DevAddr | FCnt | 0x00 | i |
        -----------------------------------------------------------
        """
        pldlen = len(payload)
        k = math.ceil(pldlen / AES_BLOCK)
        cryptor = AES.new(key, AES.MODE_ECB)
        S = b''
        ai_f = '<cIB4sIBB'
        fcnt = self.fcntup if direction == 0 else fcnt
        for i in range(start, k + start):
            Ai = struct.pack(
                ai_f,
                b'\x01',
                0,
                direction,
                self.devaddr[::-1],
                fcnt,
                0,
                i
            )
            Si = cryptor.encrypt(Ai)
            S += Si
        return Mote.bytes_xor(S, payload)[:pldlen]

    def gen_keys(self, root, keymsgs: tuple, mode=AES.MODE_ECB):
        cryptor = AES.new(root, mode)
        return [cryptor.encrypt(msg) for msg in keymsgs]

    @property
    def joinenckey(self):
        return self.nwkkey if self.joinreqtyp == b'\xFF' else self.jsenckey

    def form_join(self):
        """
        ---------------------
        |0xFF| Join Request |
        ---------------------
        |0x00| Rejoin type 0|
        ---------------------
        |0x01| Rejoin type 1|
        ---------------------
        |0x02| Rejoin type 2|
        ---------------------
        """
        joinreq_f = '<s8s8sH'
        self.joinreqtyp = b'\xFF'
        self.devnonce += 1
        self.save_nonce()
        mhdr = b'\x00'
        joinreq = struct.pack(
            joinreq_f,
            mhdr,
            self.joineui[::-1],
            self.deveui[::-1],
            self.devnonce,
        )
        mic = self.calcmic_join(
            key=self.nwkkey,
            macpld=joinreq,
        )
        joinreq_f = '<{}s4s'.format(struct.calcsize(joinreq_f))
        joinreq = struct.pack(
            joinreq_f,
            joinreq,
            mic,
        )
        logger.info(
            ('Forming a join request message - \n'
                'NwkKey: {}, '
                'AppKey: {}, '
                'AppEUI: {}, '
                'DevEUI: {}, '
                'DevNonce: {}, '
                'MIC: {},'
                'Final Join Req: {} -- '
            ).format(
                    self.nwkkey.hex(),
                    self.appkey.hex(),
                    self.joineui.hex(),
                    self.deveui.hex(),
                    self.devnonce,
                    mic.hex(),
                    joinreq.hex(),
                ))

        return joinreq

    def parse_mhdr(self, mhdr):
        """
        MHDR:
        -----------------------
        | MType | RFU | Major |
        -----------------------
        |  000  | 000 |  00   |
        -----------------------
        """
        name = ('mtype', 'rfu', 'major')
        bitlength = (3, 3, 2)
        offset = (5, 2, 0)
        return self.parse_byte(mhdr, name=name, bitlength=bitlength, offset=offset)

    def parse_joinacpt(self, mhdr, joinacptmic):
        """
        Join Accept:
        --------------------------------------------------------------------
        | JoinNonce | Home_NetID | DevAddr | DLSettings | RxDelay | CFList |
        --------------------------------------------------------------------
        |  3 bytes  |   3 bytes  | 4 bytes |   1 byte   | 1 byte  |  (16)  |
        --------------------------------------------------------------------
        """
        msglen = len(joinacptmic)
        pldlen = msglen - MIC_LEN  # MHDR 1 byte, MIC 4 bytes
        pullresp_f = '<{}s{}s'.format(pldlen, MIC_LEN)
        joinacpt, mic = parse_bytes('Join Accept PHYPayload', pullresp_f, joinacptmic)
        joinacpt_f = '<3s3s4sss'
        self.cflist = joinacpt[JOINACPT_CFLIST_OFFSET:] or b''
        self.joinnonce, self.homenetid, self.devaddr, self.dlsettings, self.rxdelay = parse_bytes(
            'Join Accept MACPayload',
            joinacpt_f,
            joinacpt[:JOINACPT_CFLIST_OFFSET]
        )
        self.devaddr = self.devaddr[::-1]
        self.joinnonce = self.joinnonce[::-1]
        self.homenetid = self.homenetid[::-1]
        # Check OptNeg flag in DLSettings
        optneg, self.rx1droffset, self.rx2dr = self.parse_dlsettings(self.dlsettings)
        if optneg:
            joinacpt_mic_key = self.jsintkey
        else:
            joinacpt_mic_key = self.nwkkey
        cmic = self.calcmic_join(
            key=joinacpt_mic_key,
            macpld=struct.pack(f"<c{pldlen}s", mhdr.tobytes(), joinacpt),
            optneg=optneg,
        )

        logger.info(
            ('-----Parsing a join acpt message - \n'
                'devaddr: {}, '
                'joinnonce: {}, '
                'homenetid: {}, '
                'optneg: {}, '
                'rx1droffset: {}, '
                'rx2dr: {}, '
                'Calculated MIC: {} -- '
            ).format(self.devaddr.hex(),
                     self.joinnonce.hex(),
                     self.homenetid.hex(),
                     optneg,
                     self.rx1droffset,
                     self.rx2dr,
                     cmic.hex()
                     )),

        if (cmic == mic):
            logger.info(
                ('-----Join Accept (MIC verified) -\n'
                    'Original data: {}\n'
                    'MHDR: {}, '
                    'Join type: {}, '
                    'DevAddr: {}, '
                    'OptNeg: {}, '
                    'CFList: {}.'
                ).format(
                    joinacpt.hex(),
                    mhdr.hex(),
                    self.joinreqtyp.hex(),
                    self.devaddr.hex(),
                    optneg,
                    self.cflist.hex(),
                ))
            if self.joinreqtyp == b'\xFF':
                devnonce = self.devnonce
            elif self.joinreqtyp in (b'\x00', b'\x02'):
                devnonce = self.rjcount0
            else:
                devnonce = self.rjcount1
            self._initialize_session(optneg, devnonce)
        else:
            raise MICError('Join accept message', mic, cmic)

    def parse_dlsettings(self, dlsettings):
        """
        DLSettings:
        ----------------------------------------
        | OptNeg | RX1DRoffset | RX2 Data Rate |
        ----------------------------------------
        |   0    |    000      |     0000      |
        ----------------------------------------
        """
        name = ('optneg', 'rx1droffset', 'rx2dr')
        bitlength = (1, 3, 4)
        offset = (7, 4, 0)
        return self.parse_byte(dlsettings, name=name, bitlength=bitlength, offset=offset)

    def parse_phypld(self, phypld, result):
        """
        Message Type:
        -------------------------------
        | 000 |      Join request     |
        -------------------------------
        | 001 |      Join accept      |
        -------------------------------
        | 010 |  Unconfirmed data up  |
        -------------------------------
        | 011 | Unconfirmed data down |
        -------------------------------
        | 100 |   Confirmed data up   |
        -------------------------------
        | 101 |  Confirmed data down  |
        -------------------------------
        | 110 |     Rejoin request    |
        -------------------------------
        | 111 |       Proprietary     |
        -------------------------------
        """
        phypld = memoryview(phypld)
        mhdr = phypld[:MHDR_LEN]
        mtype, _, major = self.parse_mhdr(mhdr)
        if mtype == 1:
            encrypted_phypld = phypld[MHDR_LEN:]
            macpldmic = self.joinacpt_decrypt(encrypted_phypld.tobytes())
            self.parse_joinacpt(mhdr, macpldmic)
        else: 
            macpld = phypld[MHDR_LEN:-MIC_LEN]
            mic = phypld[-MIC_LEN:]
            self.parse_macpld(mtype, mhdr, macpld, mic, result)

    def parse_macpld(self, mtype, mhdr, macpld, mic, result):
        """
        -----------------------------------------
        | MHDR |    FHDR   | FPort | FRMPayload |
        -----------------------------------------
        |1 byte| > 6 bytes |1 byte |     -      |
        -----------------------------------------
        """
        macpld = memoryview(macpld)
        confirmed = True if mtype == 5 else False
        fhdrlen, fhdr, fhdr_d = self.parse_fhdr(macpld)
        ack = fhdr_d.get('ack')
        fcntdown = fhdr_d.get('fcnt')
        # There could be no FPort and FRMPayload fields, check before assign
        try:
            fport = macpld[fhdrlen]
        except IndexError:
            fport = frmpld = None
        else:
            frmpld = macpld[fhdrlen + FPORT_LEN:].tobytes()
        if fport == 0:
            key = self.nwksenckey
        else:
            key = self.appskey
        #TODO: The LoRaWAN version
        cmic = self.calcmic_app(
            mhdr,
            ack=ack,
            direction=1,
            fcnt=fcntdown,
            fhdr=fhdr,
            fport=fport,
            frmpld=frmpld,
        )
        if (cmic == mic):
            if ack:
                self.last_msg_acked = True
                self.acked_uplink += 1
                self.save()
            if frmpld is not None:
                frmpld = self.encrypt(
                    key,
                    frmpld,
                    direction=1,
                    fcnt=fcntdown # This arg must be provided
                )
            if confirmed:
                prefix = 'un'
            else:
                prefix = ''
            message_type = prefix + "confirmed downlink"
            logger.info(
                ('Downlink MACPayload (MIC verified), Important Info:\n'
                    '\tMessage Type: {}\n'
                    '\tDevAddr: {}, \n'
                    '\tFPort: {}, \n'
                    '\tPayload: {}.').format(
                        message_type,
                        fhdr_d.get("devaddr").hex()[::-1],
                        fport,
                        frmpld,
                    ))
            result['MACPayload'] = message_type
            result['DevAddr'] = fhdr_d.get("devaddr").hex()[::-1]
        else:
            raise MICError('MACPayload', mic, cmic)
        
    def form_phypld(self, fport, frmpld, fopts=b'', unconfirmed=False, ack=False):
        if unconfirmed:
            mhdr = b'\x40'
            self.last_msg_acked = True
        else:
            mhdr = b'\x80'
            self.last_msg_acked = False
        fhdrlen, fhdr = self.form_fhdr(fopts, self.version, ack)
        frmpldlen = len(frmpld)
        phypld_f = '<s{fhdrlen}sB{frmpldlen}s4s'.format(
            fhdrlen=fhdrlen,
            frmpldlen=frmpldlen,
        )
        if fport == 0:
            enckey = self.nwksenckey
        else:
            enckey = self.appskey
        frmpld = self.encrypt(
            enckey,
            frmpld,
            direction=0
        )
        mic = self.calcmic_app(
            mhdr,
            ack=ack,
            direction=0,
            fcnt=self.fcntup,
            fhdr=fhdr,
            fport=fport,
            frmpld=frmpld,
        )
        self.fcntup += 1
        if ack:
            self.acked_downlink += 1
            
        self.save()
        logger.info(
            ('Uplink application data -\n'
                'MHDR: {}, '
                'FHDR: {}, '
                'FOpts: {}, '
                'FPort: {}, '
                'FRMPayload (after encryption): {}, '
                'MIC: {} --').format(
                    mhdr.hex(),
                    fhdr.hex(),
                    fopts.hex(),
                    fport,
                    frmpld.hex(),
                    mic.hex()
                ))

        return struct.pack(
            phypld_f,
            mhdr,
            fhdr,
            fport,
            frmpld,
            mic,
        )

