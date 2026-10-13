"""Checks how a downlink data frame is labelled and which DevAddr is reported.

Run from the repository root:  python -m unittest discover tests
"""
import struct
import tempfile
import unittest

from mote import mac

DEVADDR = "01caa795"  # as ChirpStack shows it (most significant byte first)


def make_mote(dbpath):
    mote = mac.Mote(
        "0000000000000001",
        "bfd2718a2904e6a8",
        "5871FE1C02D1A74B6684D2D9FF54CEDA",
        "14714AAFF51F7792D8C4CCB614D08396",
        dbpath=dbpath,
    )
    # Session state that a successful join would set.
    mote.devaddr = bytes.fromhex(DEVADDR)
    mote.fcntup = 5
    mote.fnwksintkey = bytes(range(16))
    mote.snwksintkey = bytes(range(16, 32))
    mote.nwksenckey = bytes(range(32, 48))
    mote.appskey = bytes(range(48, 64))
    return mote


def downlink(mote, mtype, fcnt=7, fport=10, payload=b"hello"):
    """Build a downlink frame with a valid MIC, the way a network server would."""
    mhdr = bytes([mtype << mac.MTYPE_OFFSET])
    fhdr = struct.pack("<4ssH", mote.devaddr[::-1], b"\x00", fcnt)
    frmpld = mote.encrypt(mote.appskey, payload, direction=1, fcnt=fcnt)
    mic = mote.calcmic_app(mhdr, fhdr, fport=fport, frmpld=frmpld, direction=1, fcnt=fcnt)
    return mhdr + fhdr + bytes([fport]) + frmpld + mic


class DownlinkParsingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.mote = make_mote(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def parse(self, mtype):
        result = {}
        self.mote.parse_phypld(downlink(self.mote, mtype), result)
        return result

    def test_confirmed_downlink_is_labelled_confirmed(self):
        self.assertEqual(self.parse(5)["MACPayload"], "confirmed downlink")

    def test_unconfirmed_downlink_is_labelled_unconfirmed(self):
        self.assertEqual(self.parse(3)["MACPayload"], "unconfirmed downlink")

    def test_devaddr_is_reported_most_significant_byte_first(self):
        self.assertEqual(self.parse(3)["DevAddr"], DEVADDR)


if __name__ == "__main__":
    unittest.main()
