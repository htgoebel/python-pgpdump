import base64
from datetime import datetime
from itertools import repeat
import os.path
from unittest import main, TestCase

from pgpdump import AsciiData, BinaryData
from pgpdump.packet import (TAG_TYPES, SignaturePacket, PublicKeyPacket,
        PublicSubkeyPacket, UserIDPacket, old_tag_length, new_tag_length,
        SecretKeyPacket, SecretSubkeyPacket)
from pgpdump.utils import (PgpdumpException, crc24, get_int8, get_mpi,
        get_key_id, get_int_bytes, same_key)


class UtilsTestCase(TestCase):
    def test_crc24(self):
        self.assertEqual(0xb704ce, crc24(bytearray(b"")))
        self.assertEqual(0x21cf02, crc24(bytearray(b"123456789")))
        self.assertEqual(0xe84567, crc24(repeat(0, 1024 * 1024)))
        #self.assertEqual(0x03ebb7, crc24(repeat(0, 10 * 1024 * 1024)))
        #self.assertEqual(0x5c0542, crc24(repeat(0, 30 * 1024 * 1024)))

    # get_int2, get_int4 are tested plenty by actual code

    def test_int8(self):
        data = [
            (0, [0x00] * 8),
            (0x0a0b0c0d, (0x00, 0x00, 0x00, 0x00, 0x0a, 0x0b, 0x0c, 0x0d)),
            (0x0a0b0c0d << 32, bytearray(b'\x0a\x0b\x0c\x0d\x00\x00\x00\x00')),
        ]
        for expected, invals in data:
            self.assertEqual(expected, get_int8(invals, 0))

    def test_mpi(self):
        data = [
            (1,   3, (0x00, 0x01, 0x01)),
            (511, 4, (0x00, 0x09, 0x01, 0xff)),
            (65537, 5, bytearray(b'\x00\x11\x01\x00\x01')),
        ]
        for expected, offset, invals in data:
            self.assertEqual((expected, offset), get_mpi(invals, 0))

    def test_key_id(self):
        self.assertEqual(b"5C2E46A0F53A76ED",
                get_key_id(b"\\.F\xa0\xf5:v\xed", 0))

    def test_int_bytes(self):
        self.assertEqual(b"\x11", get_int_bytes(17))
        self.assertEqual(b"\x01\x00\x01", get_int_bytes(65537))

    def test_same_key(self):
        fprint = b"A5CA9D5515DC2CA73DF748CA5C2E46A0F53A76ED"
        key_id = b"5C2E46A0F53A76ED"
        short = b"F53A76ED"
        different = b"A5CA9D55"

        self.assertTrue(same_key(fprint, fprint))
        self.assertTrue(same_key(fprint, key_id))
        self.assertTrue(same_key(fprint, short))

        self.assertTrue(same_key(key_id, fprint))
        self.assertTrue(same_key(key_id, key_id))
        self.assertTrue(same_key(key_id, short))

        self.assertTrue(same_key(short, fprint))
        self.assertTrue(same_key(short, key_id))
        self.assertTrue(same_key(short, short))

        self.assertFalse(same_key(fprint, different))
        self.assertFalse(same_key(key_id, different))
        self.assertFalse(same_key(short, different))
        self.assertFalse(same_key(different, fprint))
        self.assertFalse(same_key(different, key_id))
        self.assertFalse(same_key(different, short))


class Helper(object):
    def check_sig_packet(self, packet, length, version, typ,
            creation_time, key_id, pub_alg, hash_alg):
        '''Helper method for quickly verifying several fields on a signature
        packet.'''
        self.assertEqual(2, packet.raw)
        self.assertEqual(length, packet.length)
        self.assertEqual(version, packet.sig_version)
        self.assertEqual(typ, packet.raw_sig_type)
        self.assertEqual(creation_time, packet.raw_creation_time)
        self.assertEqual(key_id, packet.key_id)
        self.assertEqual(pub_alg, packet.raw_pub_algorithm)
        self.assertEqual(hash_alg, packet.raw_hash_algorithm)

        # test some of the lazy lookup methods
        if typ == 0x18:
            self.assertEqual("Subkey Binding Signature", packet.sig_type)
        if pub_alg == 17:
            self.assertEqual("DSA Digital Signature Algorithm",
                    packet.pub_algorithm)
        if hash_alg == 2:
            self.assertEqual("SHA1", packet.hash_algorithm)

    def load_data(self, filename):
        full_path = os.path.join('testdata', filename)
        self.assertTrue(os.path.exists(full_path))
        with open(full_path, 'rb') as fileobj:
            data = fileobj.read()
        return data

    # Here for 2.6 compatibility; these won't be used by 2.7 and up
    def assertIsNone(self, obj, msg=None):
        return self.assertTrue(obj is None, msg)

    def assertIsNotNone(self, obj, msg=None):
        return self.assertFalse(obj is None, msg)


class ParseTestCase(TestCase, Helper):
    def test_parse_empty(self):
        self.assertRaises(PgpdumpException, BinaryData, None)

    def test_parse_short(self):
        self.assertRaises(PgpdumpException, BinaryData, [0x00])

    def test_parse_invalid(self):
        self.assertRaises(PgpdumpException, BinaryData, [0x00, 0x00])

    def test_parse_single_sig_packet(self):
        base64_sig = b"iEYEABECAAYFAk6A4a4ACgkQXC5GoPU6du1ATACgodGyQne3Rb7"\
                b"/eHBMRdau1KNSgZYAoLXRWt2G2wfp7haTBjJDFXMGsIMi"
        sig = base64.b64decode(base64_sig)
        data = BinaryData(sig)
        packets = list(data.packets())
        self.assertEqual(1, len(packets))
        sig_packet = packets[0]
        self.assertFalse(sig_packet.new)
        self.check_sig_packet(sig_packet, 70, 4, 0, 1317069230,
                b"5C2E46A0F53A76ED", 17, 2)
        self.assertEqual(2, len(sig_packet.subpackets))
        self.assertEqual(["Signature Creation Time", "Issuer"],
                [sp.name for sp in sig_packet.subpackets])

    def test_parse_ascii_sig_packet(self):
        asc_data = b'''
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.11 (GNU/Linux)

iEYEABECAAYFAk6neOwACgkQXC5GoPU6du23AQCgghWjIFgBazXWIZNj4PGnkuYv
gMsAoLGOjudliDT9u0UqxN9KeJ22Jdne
=KYol
-----END PGP SIGNATURE-----'''
        data = AsciiData(asc_data)
        packets = list(data.packets())
        self.assertEqual(1, len(packets))
        sig_packet = packets[0]
        self.assertFalse(sig_packet.new)
        self.check_sig_packet(sig_packet, 70, 4, 0, 1319598316,
                b"5C2E46A0F53A76ED", 17, 2)
        self.assertEqual(2, len(sig_packet.subpackets))

    def test_parse_bad_crc(self):
        asc_data = b'''
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.11 (GNU/Linux)

iEYEABECAAYFAk6neOwACgkQXC5GoPU6du23AQCgghWjIFgBazXWIZNj4PGnkuYv
gMsAoLGOjudliDT9u0UqxN9KeJ22JdnX
=KYol
-----END PGP SIGNATURE-----'''
        self.assertRaises(PgpdumpException, AsciiData, asc_data)


class ParseDataTestCase(TestCase, Helper):
    def test_parse_v3_sig(self):
        asc_data = b'''
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v2.0.18 (GNU/Linux)

iD8DBQBPWDfGXC5GoPU6du0RAq6XAKC3TejpiBsu3pGF37Q9Id/vPzoFlwCgtwXE
E/GGdt/Cn5Rr1G933H9nwxo=
=aJ6u
-----END PGP SIGNATURE-----'''
        data = AsciiData(asc_data)
        packets = list(data.packets())
        self.assertEqual(1, len(packets))
        sig_packet = packets[0]
        self.assertFalse(sig_packet.new)
        self.check_sig_packet(sig_packet, 63, 3, 0, 1331181510,
                b"5C2E46A0F53A76ED", 17, 2)
        self.assertEqual(b'\xae\x97', sig_packet.hash2)
        self.assertEqual(0, len(sig_packet.subpackets))

    def test_parse_ascii_clearsign(self):
        '''This is a clearsigned document with an expiring signature, so tests
        both the ignore pattern in AsciiData as well as additional signature
        subpackets.'''
        asc_data = self.load_data('README.asc')
        data = AsciiData(asc_data)
        packets = list(data.packets())
        self.assertEqual(1, len(packets))
        sig_packet = packets[0]
        self.assertFalse(sig_packet.new)
        self.assertEqual(3, len(sig_packet.subpackets))
        self.check_sig_packet(sig_packet, 76, 4, 1, 1332874080,
                b"5C2E46A0F53A76ED", 17, 2)
        # raw expires time is in seconds from creation date
        self.assertEqual(345600, sig_packet.raw_expiration_time)
        expires = datetime(2012, 3, 31, 18, 48, 00)
        self.assertEqual(expires, sig_packet.expiration_time)

    def test_parse_linus_binary(self):
        rawdata = self.load_data('linus.gpg')
        data = BinaryData(rawdata)
        packets = list(data.packets())
        self.assertEqual(44, len(packets))
        seen = 0
        for packet in packets:
            # all 44 packets are of the known 'old' variety
            self.assertFalse(packet.new)

            if isinstance(packet, SignaturePacket):
                # a random signature plucked off the key
                if packet.key_id == b"E7BFC8EC95861109":
                    seen += 1
                    self.check_sig_packet(packet, 540, 4, 0x10, 1319560576,
                            b"E7BFC8EC95861109", 1, 8)
                    self.assertEqual(2, len(packet.subpackets))
                # a particularly dastardly sig- a ton of hashed sub parts,
                # this is the "positive certification packet"
                elif packet.key_id == b"79BE3E4300411886" and \
                        packet.raw_sig_type == 0x13:
                    seen += 1
                    self.check_sig_packet(packet, 312, 4, 0x13, 1316554898,
                            b"79BE3E4300411886", 1, 2)
                    self.assertEqual(8, len(packet.subpackets))
                # another sig from key above, the "subkey binding sig"
                elif packet.key_id == b"79BE3E4300411886" and \
                        packet.raw_sig_type == 0x18:
                    seen += 1
                    self.check_sig_packet(packet, 287, 4, 0x18, 1316554898,
                            b"79BE3E4300411886", 1, 2)
                    self.assertEqual(3, len(packet.subpackets))

            elif isinstance(packet, PublicSubkeyPacket):
                seen += 1
                self.assertEqual(4, packet.pubkey_version)
                self.assertEqual(1316554898, packet.raw_creation_time)
                self.assertEqual(1, packet.raw_pub_algorithm)
                self.assertIsNotNone(packet.modulus)
                self.assertEqual(2048, packet.modulus_bitlen)
                self.assertEqual(65537, packet.exponent)
                self.assertEqual(b"012F54CA", packet.fingerprint[32:])

            elif isinstance(packet, PublicKeyPacket):
                seen += 1
                self.assertEqual(4, packet.pubkey_version)
                self.assertEqual(1316554898, packet.raw_creation_time)
                self.assertEqual(1, packet.raw_pub_algorithm)
                self.assertEqual("RSA Encrypt or Sign", packet.pub_algorithm)
                self.assertIsNotNone(packet.modulus)
                self.assertEqual(2048, packet.modulus_bitlen)
                self.assertEqual(65537, packet.exponent)
                self.assertEqual(b"ABAF11C65A2970B130ABE3C479BE3E4300411886",
                        packet.fingerprint)
                self.assertEqual(b"79BE3E4300411886", packet.key_id)

            elif isinstance(packet, UserIDPacket):
                seen += 1
                self.assertEqual("Linus Torvalds", packet.user_name)
                self.assertEqual("torvalds@linux-foundation.org",
                        packet.user_email)

        self.assertEqual(6, seen)

    def test_parse_linus_ascii(self):
        rawdata = self.load_data('linus.asc')
        data = AsciiData(rawdata)
        packets = list(data.packets())
        self.assertEqual(44, len(packets))
        # Note: we could do all the checks we did above in the binary version,
        # but this is really only trying to test the AsciiData extras, not the
        # full stack.

    def test_parse_dan(self):
        '''This key has DSA and ElGamal keys, which Linus' does not have.'''
        rawdata = self.load_data('dan.gpg')
        data = BinaryData(rawdata)
        packets = list(data.packets())
        self.assertEqual(9, len(packets))
        # 3 user ID packets
        self.assertEqual(3, sum(1 for p in packets if p.raw == 13))
        # 4 signature packets
        self.assertEqual(4, sum(1 for p in packets if p.raw == 2))

        seen = 0
        for packet in packets:
            self.assertFalse(packet.new)

            if isinstance(packet, PublicSubkeyPacket):
                seen += 1
                self.assertEqual(16, packet.raw_pub_algorithm)
                self.assertEqual("elg", packet.pub_algorithm_type)
                self.assertIsNotNone(packet.prime)
                self.assertIsNone(packet.group_order)
                self.assertIsNotNone(packet.group_gen)
                self.assertIsNotNone(packet.key_value)
                self.assertEqual(b"C3751D38", packet.fingerprint[32:])

            elif isinstance(packet, PublicKeyPacket):
                seen += 1
                self.assertEqual(17, packet.raw_pub_algorithm)
                self.assertEqual("dsa", packet.pub_algorithm_type)
                self.assertIsNotNone(packet.prime)
                self.assertIsNotNone(packet.group_order)
                self.assertIsNotNone(packet.group_gen)
                self.assertIsNotNone(packet.key_value)
                self.assertEqual(b"A5CA9D5515DC2CA73DF748CA5C2E46A0F53A76ED",
                        packet.fingerprint)

        self.assertEqual(2, seen)

    def test_parse_junio(self):
        '''This key has a single user attribute packet, which also uses the new
        size format on the outer packet, which is rare.'''
        rawdata = self.load_data('junio.gpg')
        data = BinaryData(rawdata)
        packets = list(data.packets())
        self.assertEqual(13, len(packets))
        # 3 user ID packets
        self.assertEqual(4, sum(1 for p in packets if p.raw == 13))
        # 4 signature packets
        self.assertEqual(6, sum(1 for p in packets if p.raw == 2))
        # 1 public subkey packet
        self.assertEqual(1, sum(1 for p in packets if p.raw == 14))
        # 1 user attribute packet
        self.assertEqual(1, sum(1 for p in packets if p.raw == 17))

        # check the user attribute packet
        ua_packet = [p for p in packets if p.raw == 17][0]
        self.assertEqual("jpeg", ua_packet.image_format)
        self.assertEqual(1513, len(ua_packet.image_data))

    def test_parse_v3_pubkeys(self):
        '''Two older version 3 public keys.'''
        rawdata = self.load_data('v3pubkeys.gpg')
        data = BinaryData(rawdata)
        packets = list(data.packets())
        self.assertEqual(2, len(packets))

        packet = packets[0]
        self.assertTrue(isinstance(packet, PublicKeyPacket))
        self.assertEqual(1, packet.raw_pub_algorithm)
        self.assertEqual("rsa", packet.pub_algorithm_type)
        self.assertEqual(944849149, packet.raw_creation_time)
        self.assertIsNone(packet.expiration_time)
        self.assertIsNotNone(packet.modulus)
        self.assertEqual(2048, packet.modulus_bitlen)
        self.assertIsNotNone(packet.exponent)
        self.assertEqual(b"3FC0BF6B", packet.key_id)
        self.assertEqual(b"7D263C88A1AB7737E31150CB4F3A211A",
                packet.fingerprint)

        packet = packets[1]
        self.assertTrue(isinstance(packet, PublicKeyPacket))
        self.assertEqual(1, packet.raw_pub_algorithm)
        self.assertEqual("rsa", packet.pub_algorithm_type)
        self.assertEqual(904151571, packet.raw_creation_time)
        self.assertIsNone(packet.expiration_time)
        self.assertIsNotNone(packet.modulus)
        self.assertEqual(1024, packet.modulus_bitlen)
        self.assertIsNotNone(packet.exponent)
        self.assertEqual(b"3DDE776D", packet.key_id)
        self.assertEqual(b"48A4F9F891F093019BC7FC532A3C5692",
                packet.fingerprint)

    def test_parse_v3_elgamal_pk(self):
        '''Two older version 3 public keys.'''
        rawdata = self.load_data('v3elgpk.asc')
        data = AsciiData(rawdata)
        packets = list(data.packets())
        self.assertEqual(3, len(packets))

        packet = packets[0]
        self.assertTrue(isinstance(packet, PublicKeyPacket))
        self.assertEqual(16, packet.raw_pub_algorithm)
        self.assertEqual("elg", packet.pub_algorithm_type)
        self.assertEqual(888716291, packet.raw_creation_time)
        self.assertIsNone(packet.expiration_time)
        self.assertIsNone(packet.modulus)
        self.assertIsNone(packet.modulus_bitlen)
        self.assertIsNone(packet.exponent)
        self.assertIsNotNone(packet.prime)
        self.assertIsNotNone(packet.group_gen)
        self.assertEqual(b"FF570A03", packet.key_id)
        self.assertEqual(b"7C4529FB11669ACA567BD53972000594",
                packet.fingerprint)

        self.assertTrue(isinstance(packets[1], UserIDPacket))

        packet = packets[2]
        self.assertTrue(isinstance(packet, SignaturePacket))
        self.assertEqual(16, packet.raw_pub_algorithm)
        self.assertEqual(888716292, packet.raw_creation_time)

    def test_parse_compressed_zlib(self):
        msg = """-----BEGIN PGP MESSAGE-----
Version: GnuPG v2

owFtUm1MFEcY5lAqnqJFWhpSautCLJiL7OzOfh0FQkREEpq0igk0hO7szh4b8A5u
Dw6KJxVo09ZrKicSCfEDpY39OisfLUHx40RA6I8SiBJBw5Wm1ZqmVtQE0dI5Yn80
6fyZzDvP87zP884ciFoWFmnqSq0uGfAfHDGN3kFh+dOfZNdSyKHWUNZaqhQvbZpu
t2FnuVO3uygrJSIRsRwCAmA4qCBOExTIiQJELIsEkRcVKGOJVWTKQpU4jBCDyCDZ
wJt1B6mRQ7Gukur/4EuXLmhAA5UDKo8ZVeB5GUmMLAIWI8hptKoAXsYy0qAoIZZX
BEaBDFQlUeGJMRmyEpKJJB2Sq1ySU0UNA5HVOCRigWWgxIsSQIQgYZljgRQCGthp
l3djgsY12KA8FsqJqxylOJTe0G3EsEFZ36E0GWq0BgCrMowmYVrUGEmRNValaRIB
KSwgM8Eaq/CIE1SORoBhaZ4BCGgc4ACmNaqIaJNuVbqyJP6sq013lVSi/zrZUWnP
cstOLeTGVVMeKrkxKn5GLka6XSXvQjhV2GnoDjtlBQSpuPQQG0BIc4DnedFC4epy
3YmL9RCCE3iRJstClZOERJJRMcnEsyrkJGkHpoGmkbliBQqiKkPA8owkYh7IZO4s
hwHLMrKEVU5RJcjQSMIiFcpTYXcQcZ4YlW1ElIzMLrsqnZjymD8Oj18eZooMey4i
PPS5wswrn//3x9n+Wvs0LuVE58tNvQH3QHSPmrpxT3Fc3dbmrd4X824UDqQZD2yZ
/uZXN0UYK5CFH0WzZzz3evCDfeKjvJgLP0/J6zK+f9LWbkmKXr5YdDjq7aj1bwze
HdGyPTFfwc9d4depF8qy/f11/fPxPza2FYy4rNsZJ13ts+3sLqxKNL6JSF7XXHra
tOFR+5aEnC+LzJe3rCnsSh27P6tuHM2AhV/jyT2DjcOb83OCC2m5Aw87UJWBRKbf
slpYOHJjavxsVr69bY5POnHz+M2zq7tNuV3Tvp41H8xN1KavF7tX/nSfS8w8Op7R
EhtpvxLu+9S9atuZg7u8rRvoU+dj9z6p9Fa044TJnDv+3EbvqXs9vcHb1oHjecN1
EzU1wYbUBcfv+eefPh57vW94U+rutILeIT144AvX+MmoCPO191v6Cs/d/kNYFWzy
vXYp/d2p2bjrnuls3GX0ZczOBYINJ+Ojf6gv+0xKTI/wnTvUnvDRpWNN11plxuQU
vA3s4K/bFnuZkk6rqe+XwOSQ/5Zrxu+r8L55eu8R2H+V+a7irYkCU3jcsg8TLPv3
/xk7XpqyMzZqJjC06DF12t6Lhe6W+bWBqytcHY230i/+lpKdMhSTOGMeeSmt9e5F
68N54XJHpuKG6VmPDx0ucfHJo/Vw7NvEC0fNenlu574rrzQl/e0pC9Tvoqe3e5PF
fwA=
=3Snw
-----END PGP MESSAGE-----""".encode()
        data = AsciiData(msg)
        packets = list(data.packets())
        self.assertEqual(packets[0].raw_compression_algo, 1)
        newpackets = list(BinaryData(packets[0].decompressed_data).packets())
        self.assertEqual(len(newpackets), 3)





class EncryptedPacketsTestCase(TestCase, Helper):
    def test_parse_sessionkey_elg(self):
        '''This file contains a public key and message encrypted with an
        ElGamal Encrypt-Only key.'''
        asc_data = self.load_data('sessionkey_elg.asc')
        data = AsciiData(asc_data)
        packets = list(data.packets())
        self.assertEqual(2, len(packets))
        session_key = packets[0]
        self.assertEqual(3, session_key.session_key_version)
        self.assertEqual(b"B705D3A4C3751D38", session_key.key_id)
        self.assertEqual(16, session_key.raw_pub_algorithm)
        self.assertEqual("ElGamal Encrypt-Only", session_key.pub_algorithm)

    def test_parse_sessionkey_rsa(self):
        '''This file contains a public key and message encrypted with a RSA
        Encrypt or Sign key.'''
        asc_data = self.load_data('sessionkey_rsa.asc')
        data = AsciiData(asc_data)
        packets = list(data.packets())
        self.assertEqual(2, len(packets))
        session_key = packets[0]
        self.assertEqual(3, session_key.session_key_version)
        self.assertEqual(b"1C39A7BD114BFFA5", session_key.key_id)
        self.assertEqual(1, session_key.raw_pub_algorithm)
        self.assertEqual("RSA Encrypt or Sign", session_key.pub_algorithm)

    def test_parse_partial_length(self):
        '''This file contains an encrypted message with a Partial Body Length header
           Reference: http://tools.ietf.org/html/rfc4880#section-4.2.2.4
        '''

        rawdata = self.load_data('partial_length.gpg')
        data = BinaryData(rawdata)
        packets = list(data.packets())
        self.assertEqual(2, len(packets))


class PacketTestCase(TestCase):
    def test_lookup_type(self):
        self.assertEqual("Signature Packet", TAG_TYPES[2][0])

    def test_old_tag_length(self):
        data = [
            ((1, 2),    [0xb0, 0x02]),
            ((1, 70),   [0x88, 0x46]),
            ((2, 284),  [0x89, 0x01, 0x1c]),
            ((2, 525),  [0xb9, 0x02, 0x0d]),
            ((2, 1037), [0xb9, 0x04, 0x0d]),
            ((2, 1037), bytearray(b'\xb9\x04\x0d')),
            ((2, 5119), [0xb9, 0x13, 0xff]),
            ((4, 100000), [0xba, 0x00, 0x01, 0x86, 0xa0]),
        ]
        for expected, invals in data:
            self.assertEqual(expected, old_tag_length(invals, 0))

    def test_new_tag_length(self):
        data = [
            ((1, 2, False), [0x02]),
            ((1, 16, False), [0x10]),
            ((1, 100, False), [0x64]),
            ((1, 166, False), [0xa6]),
            ((1, 168, False), [0xa8]),
            ((2, 1723, False), [0xc5, 0xfb]),
            ((2, 3923, False), [0xce, 0x93]),
            ((2, 5119, False), [0xd3, 0x3f]),
            ((2, 6476, False), [0xd8, 0x8c]),
            ((1, 8192, True), [0xed]),
            ((5, 26306, False), [0xff, 0x00, 0x00, 0x66, 0xc2]),
            ((5, 26306, False), bytearray(b'\xff\x00\x00\x66\xc2')),
            ((5, 100000, False), [0xff, 0x00, 0x01, 0x86, 0xa0]),
        ]
        for expected, invals in data:
            self.assertEqual(expected, new_tag_length(invals, 0))


class SecretKeyPacketTestCase(TestCase, Helper):
    def test_parse_encrypted(self):
        rawdata = self.load_data('v4_secret_encrypted.gpg')
        data = BinaryData(rawdata)
        packets = list(data.packets())
        self.assertEqual(7, len(packets))
        subs_seen = 0
        for packet in packets:
            self.assertFalse(packet.new)

            if isinstance(packet, SecretSubkeyPacket):
                subs_seen += 1
                if subs_seen == 1:
                    # elg packet
                    self.assertEqual("elg", packet.pub_algorithm_type)
                    self.assertEqual(254, packet.s2k_id)
                    self.assertEqual("Iterated and Salted S2K", packet.s2k_type)
                    self.assertEqual(
                            bytearray(b"\x8d\x89\xbd\xdf\x01\x0e\x22\xcd"),
                            packet.s2k_iv)
                elif subs_seen == 2:
                    # rsa packet
                    self.assertEqual("rsa", packet.pub_algorithm_type)
                    self.assertEqual(254, packet.s2k_id)
                    self.assertEqual("Iterated and Salted S2K", packet.s2k_type)
                    self.assertEqual(
                            bytearray(b"\x09\x97\x6b\xf5\xd4\x28\x41\x1d"),
                            packet.s2k_iv)
            elif isinstance(packet, SecretKeyPacket):
                self.assertEqual("dsa", packet.pub_algorithm_type)
                self.assertEqual(254, packet.s2k_id)
                self.assertEqual("Iterated and Salted S2K", packet.s2k_type)
                self.assertEqual("CAST5", packet.s2k_cipher)
                self.assertEqual("SHA1", packet.s2k_hash)
                self.assertEqual(
                        bytearray(b"\xc3\x87\xeb\xca\x9b\xce\xbc\x78"),
                        packet.s2k_iv)

    def test_parse_with_decryption(self):
        rawdata = self.load_data('v4_secret_decryption.gpg')
        data = BinaryData(rawdata, secret_keys=True, passphrase="password")
        packets = list(data.packets())
        self.assertEqual(5, len(packets))
        subs_seen = 0
        for packet in packets:
            self.assertFalse(packet.new)
            if isinstance(packet, SecretSubkeyPacket):
                self.assertEqual("rsa", packet.pub_algorithm_type)
                self.assertEqual(254, packet.s2k_id)
                self.assertEqual("Iterated and Salted S2K", packet.s2k_type)
                self.assertEqual("AES with 128-bit key", packet.s2k_cipher)
                self.assertEqual("SHA1", packet.s2k_hash)
                self.assertEqual(bytearray(b"\x25\x31\x2c\x15\x0d\x1a\xa4\x32"), packet.s2k_salt)
                self.assertEqual(28311552, packet.s2k_count)
                self.assertEqual(
                    bytearray(b"\xdb\xfb\xca\x71\x59\x5a\x59\xf4\xa4\xc8\x34\x4c\x70\xc7\x6e\xf8"),
                    packet.s2k_iv)
            elif isinstance(packet, SecretKeyPacket):
                self.assertEqual("rsa", packet.pub_algorithm_type)
                self.assertEqual(254, packet.s2k_id)
                self.assertEqual("Iterated and Salted S2K", packet.s2k_type)
                self.assertEqual("AES with 128-bit key", packet.s2k_cipher)
                self.assertEqual("SHA1", packet.s2k_hash)
                self.assertEqual(bytearray(b"\x7a\xd8\x0d\x35\xa4\x44\x4a\x4b"), packet.s2k_salt)
                self.assertEqual(28311552, packet.s2k_count)
                self.assertEqual(
                    bytearray(b"\xc0\x01\x34\xdb\xd7\xda\xbe\x15\xaf\xae\x33\x5c\x86\x42\x56\x40"),
                    packet.s2k_iv)
                self.assertEqual(57139543266192165128281144044411281963938887885122183737825718323085742166478814244487826142739316912825108119923134650114448852027175596409261040785251960282224262646730580045290345624004790802075089681015303677913137320976449466438887618361002173038542082224365591925827496447764934379628113981412803867212, packet.multiplicative_inverse)
                self.assertEqual(139532912857315397011523035644843176776151710894775368601014486122287996033032916950264453756670103931886467806621808994979952830255575825892733252189327341137279453844065286003484830946612715485585426152724606843752478265363778372626963305366611139845010717913504961702203877138406852487225780777149738894297, packet.prime_p)
                self.assertEqual(156967979978309688678515666724764495861571025634369063413405818694684099156517872158707735457891195565502197944591749637596486087790938219823267253746022554280110796566005442268749455022900009636729701496036202969242049529755409798440046489540964969540070293182209068502547724769043080406309693772135222947329, packet.prime_q)
                self.assertEqual(193234878814520174493413988006231232798224891638964463956506744515940994815625406504569783033473105374621784254686175763923946642777191221282023504939040393369373111205448725923369710581234663366342012075695057331696195508139319427534489660578085475266571763231313075938047967692014702815752692375958374707593083648528534297319658268074967699604107187523467700350045754777506043868591583264691952008157421901666329736652297310633663749361504690533685201679551118755471746344943799536867329533867065394328453174675830576256620445226273280512580544084083686533706967592768811656301009576469902959709139327341615937025, packet.exponent_d)
                self.assertEqual(b'1ECD3CA59A48964DB53157028712CDECDB20A411', packet.fingerprint)

    def test_parse_plain(self):
        '''The raw values below were extracted from the C version of pgpdump.
        The hex strings it outputs were converted to base 10 by running the
        following function over the hex strings:
                def to_int(x):
                    return  int(x.replace(' ', ''), 16)
        '''
        rawdata = self.load_data('v4_secret_plain.gpg')
        data = BinaryData(rawdata)
        packets = list(data.packets())
        self.assertEqual(7, len(packets))
        subs_seen = 0
        for packet in packets:
            self.assertFalse(packet.new)

            if isinstance(packet, SecretSubkeyPacket):
                subs_seen += 1
                if subs_seen == 1:
                    # elg packet
                    self.assertEqual("elg", packet.pub_algorithm_type)
                    self.assertEqual(0, packet.s2k_id)
                    self.assertEqual(None, packet.s2k_type)
                    self.assertEqual(None, packet.s2k_iv)
                    self.assertEqual(245799026332407193298181926223748572866928987611495184689013385965880161244176879821250061522687647728, packet.exponent_x)
                    self.assertEqual(b'5BF533A67E818D85367401DE68B8F33DF39E9B10', packet.fingerprint)
                elif subs_seen == 2:
                    # rsa packet
                    self.assertEqual("rsa", packet.pub_algorithm_type)
                    self.assertEqual(0, packet.s2k_id)
                    self.assertEqual(None, packet.s2k_type)
                    self.assertEqual(None, packet.s2k_iv)
                    self.assertEqual(107429307998432888320715351604215972074903508478185926034856042440678824041847327442082101397552291647796540657257050768251344941490371163761048934745124363183224819621105784780195398083026664006729876758821509430352212953204518272377415915285011886868211417421097179985188014641310204357388385968166040278287, packet.multiplicative_inverse)
                    self.assertEqual(139930219416447408374822893460828502304441966752753468842648203646336195082149424690339775194932419616945814365656771053789999508162542355224095838373016952414720809190039261860912609841054241835835137530162417625471114503804567967161522096406622711734972153324109508774000862492521907132111400296639152885151, packet.prime_p)
                    self.assertEqual(141774976438365791329330227605232641244334061384594969589427240157587195987726021563323880620442249788289724672124037112182500862823754846020398652238714637523098123565121790819658975965315629614215592460191153065569430777288475743983312129144619017542854009503581558744199305796137178366407180728113362644607, packet.prime_q)
                    self.assertEqual(5830467418164177455383939797360032476940913805978768568081128075462505586965694225559897974113088818228809697270431492119090365699278285350171676334156873270109344274747057694689185206358606371235913423003163252354603704380371252575866102476793736443620998412227609599802054206292004785471167177881398711806191315950196087041018693839148033680564198494910540148825273531803832541184563811332315506727878483469747798396155096313345751606322830230368849084875744911041500024805242117661173352379509490605300753957220916597285056567409410296154792321206401452887335121085203916552891062930596871199021743741984622581173, packet.exponent_d)
                    self.assertEqual(b'FF7720B35330111D99C8C9325956A394BAC325CF', packet.fingerprint)
            elif isinstance(packet, SecretKeyPacket):
                self.assertEqual("dsa", packet.pub_algorithm_type)
                self.assertEqual(254, packet.s2k_id)
                self.assertEqual("GnuPG S2K", packet.s2k_type)
                self.assertEqual("CAST5", packet.s2k_cipher)
                self.assertEqual("SHA1", packet.s2k_hash)
                self.assertEqual(None, packet.s2k_iv)
                self.assertEqual(b'FB05FA6F149E07881BE04B4EB449453A3CF56443', packet.fingerprint)

    def test_parse_mode_1002(self):
        rawdata = self.load_data('secret_key_mode_1002.bin')
        data = BinaryData(rawdata)
        packets = list(data.packets())
        self.assertEqual(7, len(packets))

        for packet in packets:
            self.assertFalse(packet.new)

            if isinstance(packet, SecretKeyPacket):
                # this block matches both top-level and subkeys
                self.assertEqual("rsa", packet.pub_algorithm_type)
                self.assertEqual(255, packet.s2k_id)
                self.assertEqual("GnuPG S2K", packet.s2k_type)
                self.assertEqual("Plaintext or unencrypted", packet.s2k_cipher)
                self.assertEqual("Unknown", packet.s2k_hash)
                self.assertEqual(None, packet.s2k_iv)

class EllipticCurveTestCase(TestCase, Helper):
    def test_parse_with_decryption(self):
        rawdata = self.load_data('ecc_encrypted.gpg')
        data = BinaryData(rawdata, secret_keys=True, passphrase="password")
        packets = list(data.packets())
        self.assertEqual(7, len(packets))
        subs_seen = 0
        for packet in packets:
            self.assertFalse(packet.new)
            if isinstance(packet, SecretSubkeyPacket):
                if subs_seen == 0:
                    self.assertEqual("ecdh", packet.pub_algorithm_type)
                    self.assertEqual("NIST P-256", packet.curve)
                    self.assertEqual(254, packet.s2k_id)
                    self.assertEqual("Iterated and Salted S2K", packet.s2k_type)
                    self.assertEqual("AES with 128-bit key", packet.s2k_cipher)
                    self.assertEqual("SHA1", packet.s2k_hash)
                    self.assertEqual("AES with 128-bit key", packet.kdf_wrapalgo)
                    self.assertRegex("SHA256", packet.kdf_hash)
                    self.assertEqual(bytearray(b"\x78\x6d\xef\x08\xfa\x9b\x56\x59"), packet.s2k_salt)
                    self.assertEqual(28311552, packet.s2k_count)
                    self.assertEqual(
                        bytearray(b"\x69\xc2\x68\x99\x24\x7e\x92\xb9\xef\x54\x90\x8c\xee\xd5\xc6\x1f"),
                        packet.s2k_iv)
                    self.assertEqual(60847587359509871693348204363743321775971164599256235759414459546653631611529142239218205958137558240350795129315392112029882542591919766718800104409262372, packet.point_q)
                    self.assertEqual(55720486738090255346749591914685028996401302864030399621406699639213008763959, packet.private_d)
                    self.assertEqual(b'DB8131F15297D679F8D3892B5E551CF8CE2FD3E7', packet.fingerprint)
                    subs_seen += 1
                else:
                    self.assertEqual("ecdsa", packet.pub_algorithm_type)
                    self.assertEqual("Brainpool P256 r1", packet.curve)
                    self.assertEqual(254, packet.s2k_id)
                    self.assertEqual("Iterated and Salted S2K", packet.s2k_type)
                    self.assertEqual("AES with 128-bit key", packet.s2k_cipher)
                    self.assertEqual("SHA1", packet.s2k_hash)
                    self.assertEqual(bytearray(b"\xea\xc4\x6e\x02\x5d\xd0\x03\xc0"), packet.s2k_salt)
                    self.assertEqual(28311552, packet.s2k_count)
                    self.assertEqual(
                        bytearray(b"\xc2\x90\x81\xa3\x99\x8c\x7f\xaf\x46\x6a\x8d\xbc\x7e\x9b\x02\xd0"),
                        packet.s2k_iv)
                    self.assertEqual(61123302340171845673889019232255994071820340743193990019879367428466517697750227033886079901156536636551607718612458727003711929326593246061224475278688353, packet.point_q)
                    self.assertEqual(58943201301004546689478726307889505814853557172638532197351536147387509515362, packet.private_d)
                    self.assertEqual(b'D6CDA1DD0A7CA1D653C3F9ABA68D5C0B3DAF53CE', packet.fingerprint)
            elif isinstance(packet, SecretKeyPacket):
                self.assertEqual("ecdsa", packet.pub_algorithm_type)
                self.assertEqual("NIST P-256", packet.curve)
                self.assertEqual(254, packet.s2k_id)
                self.assertEqual("Iterated and Salted S2K", packet.s2k_type)
                self.assertEqual("AES with 128-bit key", packet.s2k_cipher)
                self.assertEqual("SHA1", packet.s2k_hash)
                self.assertEqual(bytearray(b"\x11\x2b\xd4\xba\x91\x8b\x97\xbc"), packet.s2k_salt)
                self.assertEqual(28311552, packet.s2k_count)
                self.assertEqual(
                    bytearray(b"\xd9\x5b\x9b\xa5\xc4\x92\xe0\x17\x07\x77\x43\x8d\x46\xf5\x82\xff"),
                    packet.s2k_iv)
                self.assertEqual(60151785822551309368517310407206789096699074153486904473288170198587060401748197137933769333804491078674810607956244241888631169281225495410113452867492752, packet.point_q)
                self.assertEqual(79708619561552795594821242702836405022166909448726484446501657545687562933583, packet.private_d)
                self.assertEqual(b'ED3969EDD0574FF5C1E3A8D47C1C5EB897C14A8C', packet.fingerprint)

if __name__ == '__main__':
    main()
