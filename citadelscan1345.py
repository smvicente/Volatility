# Volatility
#
# Authors:
# Michael Hale Ligh <michael.ligh@mnin.org>
#
# Citadel support:
# Santiago Vicente <smvicente@invisson.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

import os, sys
import volatility.obj as obj
import volatility.debug as debug
import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.addrspace as addrspace
import volatility.plugins.malware as malware
import hashlib
import yara
import struct


zeus_types = {
    '_ZEUS_MAGIC' : [ 0x11C, {
    'struct_size' :   [ 0x0, ['unsigned int']], \
    'guid' :   [ 0x4, ['array', 0x30, ['unsigned short']]], \
    'guid2' : [ 0x7C, ['array', 0x10, ['unsigned char']]], \
    'exefile' : [ 0x9C, ['array', 0x14, ['unsigned char']]], \
    'keyname' : [ 0xEC, ['array', 0xA, ['unsigned char']]], \
    'value1' : [ 0xF6, ['array', 0xA, ['unsigned char']]], \
    'value2' : [ 0x100, ['array', 0xA, ['unsigned char']]], \
    'value3' : [ 0x10A, ['array', 0xA, ['unsigned char']]], \
    'guid_xor_key' : [ 0x114, ['unsigned int']], \
    'xorkey' : [ 0x118, ['unsigned int']], \
    }]}
    

"""
These YARA rules use locate assembly instructions that reference 
the BO_LOGIN_KEY data in the unpacked Zeus binary.
    
The z1 rules looks for this:
    
0015C92E    8BEC               MOV EBP,ESP
0015C930    83EC 0C            SUB ESP,0C
0015C933    8A82 00010000      MOV AL,BYTE PTR DS:[EDX+100]
0015C939    8845 FE            MOV BYTE PTR SS:[EBP-2],AL
0015C93C    8A82 01010000      MOV AL,BYTE PTR DS:[EDX+101]
0015C942    8845 FD            MOV BYTE PTR SS:[EBP-3],AL
0015C945    8A82 02010000      MOV AL,BYTE PTR DS:[EDX+102]
0015C94B    B9 801A1300        MOV ECX,131A80                 ; BO_LOGIN_KEY
0015C950    8845 FF            MOV BYTE PTR SS:[EBP-1],AL
0015C953    E8 BEF2FFFF        CALL 0015BC16


These YARA rules use locate assembly instructions that reference 
the configuration data in the unpacked Zeus binary. 

The z2 rules looks for this:

0040AD68    56                 PUSH ESI
0040AD69    BA 54050000        MOV EDX,554                    ; config_size
0040AD6E    52                 PUSH EDX
0040AD6F    68 602A4000        PUSH pyko.00402A60             ; config_data
0040AD74    50                 PUSH EAX
0040AD75    E8 47E30100        CALL pyko.004290C1
0040AD7A    8B0D B4394300      MOV ECX,DWORD PTR DS:[4339B4]
0040AD80    030D 943D4300      ADD ECX,DWORD PTR DS:[433D94]
0040AD86    8BF2               MOV ESI,EDX
0040AD88    2BC8               SUB ECX,EAX

The z3 rules looks for this:

0040ADF5    68 03010000        PUSH 103
0040ADFA    8D85 10FBFFFF      LEA EAX,[LOCAL.316]
0040AE00    50                 PUSH EAX
0040AE01    8D85 FCFEFFFF      LEA EAX,[LOCAL.65]
0040AE07    50                 PUSH EAX
0040AE08    E8 B4E20100        CALL pyko.004290C1             ; custom_memcopy
0040AE0D    B8 1C010000        MOV EAX,11C
0040AE12    50                 PUSH EAX
0040AE13    68 283C4300        PUSH pyko.00433C28             ; encoded_magic

The z4 rules looks for this:

00411D1D    68 03010000        PUSH 103
00411D22    8D8424 DE040000    LEA EAX,DWORD PTR SS:[ESP+4DE]
00411D29    50                 PUSH EAX
00411D2A    8D4424 08          LEA EAX,DWORD PTR SS:[ESP+8]
00411D2E    50                 PUSH EAX
00411D2F    E8 8D730100        CALL 95e8858b.004290C1         ; custom_memcopy
00411D34    B8 1C010000        MOV EAX,11C
00411D39    50                 PUSH EAX
00411D3A    68 A0414300        PUSH 95e8858b.004341A0         ; encoded_magic

These YARA rules use locate assembly instructions that reference 
the communication RC4 keys in the unpacked Zeus binary.

The z5 rules looks for this:

0042A84D    33F6               XOR ESI,ESI
0042A84F    C745 0C AD0DF8AD   MOV DWORD PTR SS:[],AFF80DAD   ; RC4 init vector salt key
0042A856    5B                 POP EBX
0042A857    8A4C3D 0C          MOV CL,BYTE PTR SS:[EBP+EDI+C]
0042A85B    8AD1               MOV DL,CL
0042A85D    80E2 07            AND DL,7
0042A860    C0E9 03            SHR CL,3
0042A863    47                 INC EDI
0042A864    83FF 04            CMP EDI,4

"""

zeus_key_sigs = {

    'namespace1':'rule z1 {strings: $a = {8B EC 83 EC 0C 8A 82 ?? ?? ?? ?? 88 45 FE 8A 82 01 01 00 00 88 45 FD 8A 82 02 01 00 00 B9 ?? ?? ?? ?? 88 45 FF E8 ?? ?? ?? ??} condition: $a}',
    'namespace2':'rule z2 {strings: $a = {56 BA ?? ?? 00 00 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 03 0D ?? ?? ?? ?? 8B F2 2B C8} condition: $a}',
    'namespace3':'rule z3 {strings: $a = {68 ?? ?? 00 00 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? B8 ?? ?? 00 00 50 68 ?? ?? ?? ??} condition: $a}',
    'namespace4':'rule z4 {strings: $a = {68 ?? ?? 00 00 8D 84 24 ?? ?? ?? ?? 50 8D 44 24 ?? 50 E8 ?? ?? ?? ?? B8 ?? ?? 00 00 50 68 ?? ?? ?? ??} condition: $a}',
    'namespace5':'rule z5 {strings: $a = {33 F6 C7 45 ?? ?? ?? ?? ?? 5B 8A 4C 3D ?? 8A D1 80 E2 07 C0 E9 03 47 83 FF 04} condition: $a}'
}

class CitadelScan1345(malware.ApiHooks):
    "Scan for and dump Citadel RC4 and AES keys"

    def __init__(self, config, *args):
        malware.ApiHooks.__init__(self, config, *args)
        config.remove_option("KERNEL")
        config.add_option('DUMP-DIR', short_option = 'D', default = None,
                          help = 'Directory in which to dump the files')

    def rc4(self, key, encoded, loginKey):
        """ Perform a basic RC4 operation """
        # Turn the buffers into lists so the elements are mutable
        key_copy = [ord(c) for c in key]
        enc_copy = [ord(c) for c in encoded]
        # Start with the last two bytes in the key
        var1 = key_copy[0x100]
        var2 = key_copy[0x101]
        var3 = 0
        loginKeyLen = len(loginKey);
        # Do the RC4 algorithm
        for i in range(0, len(enc_copy)):
            var1 += 1
            a = var1 & 0xFF
            b = key_copy[a]
            var2 += b
            var2 &= 0xFF
            key_copy[a]  = key_copy[var2]
            key_copy[var2] = b
            enc_copy[i] ^= key_copy[(key_copy[a] + b) & 0xFF]
            enc_copy[i] ^= ord(loginKey[var3])
            var3 += 1
            if (var3 == loginKeyLen):
                var3 = 0

        # Return the decoded bytes as a string
        decoded = [chr(c) for c in enc_copy]
        return ''.join(decoded)

    def rc4_init(self, key, magicKey):
        """ Initialize the RC4 keystate """
        
        hash = []
        box = []
        keyLength = len(key)
        magicKeyLen = len(magicKey)
        
        for i in range(0, 256):
            hash.append(ord(key[i % keyLength]))
            box.append(i)
        
        y = 0
        for i in range(0, 256):
            y = (y + box[i] + hash[i]) % 256
            tmp = box[i]
            box[i] = box[y]
            box[y] = tmp;

        y= 0
        for i in range(0, 256):
            magicKeyPart1 = ord(magicKey[y])  & 0x07;
            magicKeyPart2 = ord(magicKey[y]) >> 0x03;
            y += 1
            if (y == magicKeyLen):
                y = 0
            
            if (magicKeyPart1 == 0):
                box[i] = ~box[i]
            elif (magicKeyPart1 == 1):
                box[i] ^= magicKeyPart2
            elif (magicKeyPart1 == 2):
                box[i] += magicKeyPart2
            elif (magicKeyPart1 == 3):
                box[i] -= magicKeyPart2
            elif (magicKeyPart1 == 4):
                box[i] = box[i] >> (magicKeyPart2 % 8) | (box[i] << (8 - (magicKeyPart2 % 8)))
            elif (magicKeyPart1 == 5):
                box[i] = box[i] << (magicKeyPart2 % 8) | (box[i] >> (8 - (magicKeyPart2 % 8)))
            elif (magicKeyPart1 == 6):
                box[i] += 1
            elif (magicKeyPart1 == 7):
                box[i] -= 1
            
            box[i] = box[i]  & 0xff

        return ''.join([chr(c) for c in box])

    def decode_config(self, encoded_config, last_sec_data):
        """ Decode the config buffer with the bytes at the start of the last PE section """
        decoded_config = ''
        for i in range(0, len(encoded_config)):
            decoded_config += chr(ord(last_sec_data[i]) ^ ord(encoded_config[i]))
        return decoded_config

    def parse_string(self, buf):
        s = ''.join([chr(c) for c in buf])
        if s.find('\x00'):
            s = s[0:s.find('\x00')]
        return s

    def get_hex(self, buf):
        # for Volatility 2.0 use the following
        return malware.hd(buf)
        # for Volatility >= 2.1 use the following
        #return "\n".join(["{0:#010x}  {1:<48}  {2}".format(o, h, ''.join(c)) for o, h, c in utils.Hexdump(buf)])
        
    def get_only_hex(self, buf, start=0, length=16):
        """Hexdump formula seen at http://code.activestate.com/recipes/142812-hex-dumper"""
        
        FILTER = ''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
        result = ''
        for i in xrange(0, len(buf), length):
            s = buf[i:i+length]
            result = result + ''.join(["%02x"%ord(x) for x in s])
        return result  

    def calculate(self):
        addr_space = malware.get_malware_space(self._config)
        addr_space.profile.add_types(zeus_types)

        RC4_KEYSIZE = 0x102

        # cycle the processes
        for p in self.filter_tasks(tasks.pslist(addr_space)):

            # get the process address space
            ps_ad = p.get_process_address_space()
            if ps_ad == None:
                continue

            rules  = yara.compile(sources = zeus_key_sigs)

            # traverse the VAD
            for vad in p.VadRoot.traverse():

                if vad == None:
                    continue

                # find the start and end range
                
                ## for Volatility 2.0 use the following
                start = vad.StartingVpn << 12
                end   = ((vad.EndingVpn + 1) << 12) - 1
                data  = malware.get_vad_data(ps_ad, start, end) 
                ## For Volatility >= 2.1 use the following
                #start = vad.get_start()
                #end   = vad.get_end()
                #data  = vad.get_data()

                # last check for PE headers at the base 
                if data[0:2] != 'MZ':
                    continue

                # check for the signature with YARA, both hits must be present
                matches = rules.match(data=data)

                if len(matches) != 4:
                    continue

                # get the NT header
                dos_header = obj.Object("_IMAGE_DOS_HEADER", start, ps_ad)
                nt_header = dos_header.get_nt_header()

                # there must be more than 2 sections 
                if nt_header.FileHeader.NumberOfSections < 2:
                    continue

                # get the last PE section's data 
                sections = list(nt_header.get_sections(unsafe=False))
                
                last_sec = sections[-1]
                last_sec_data = ps_ad.read((last_sec.VirtualAddress + start), last_sec.Misc.VirtualSize)
                if len(last_sec_data) == 0:
                    continue

                # contains C2 URL, RC4 key for decoding local.ds and the magic buffer
                decoded_config = ''
                # contains hw lock info, the user.ds RC4 key, and XOR key
                encoded_magic  = ''
                # contains BO_LOGIN_KEY
                longinKey = ''
                # contains Salt RC4 Init key
                salt_rc4_initKey = ''

                for match in matches:
                    sigaddr = (match.strings[0][0] + start)
                    debug.debug('Found {0} at {1:#x}'.format(match.rule, sigaddr))

                    if match.rule == 'z1':
                        loginKey = ps_ad.read(
                            obj.Object('unsigned long', offset = sigaddr + 30, vm = ps_ad),0x20)
                    elif match.rule == 'z2':
                        encoded_config = ps_ad.read(
                            obj.Object('unsigned long', offset = sigaddr + 8, vm = ps_ad),
                            obj.Object('unsigned long', offset = sigaddr + 2, vm = ps_ad))
                        decoded_config = self.decode_config(encoded_config, last_sec_data)
                    elif match.rule == 'z3':
                        encoded_magic = ps_ad.read(
                            obj.Object('unsigned long', offset = sigaddr + 31, vm = ps_ad),
                            addr_space.profile.get_obj_size('_ZEUS_MAGIC'))
                    elif match.rule == 'z4':
                        encoded_magic = ps_ad.read(
                            obj.Object('unsigned long', offset = sigaddr + 30, vm = ps_ad),
                            addr_space.profile.get_obj_size('_ZEUS_MAGIC'))
                    elif match.rule == 'z5':
                        salt_rc4_initKey = ps_ad.read(sigaddr + 5,0x4)
                    
                if not decoded_config or not encoded_magic:
                    continue

                debug.debug("encoded_config:\n{0}\n".format(self.get_hex(encoded_config)))
                debug.debug("decoded_config:\n{0}\n".format(self.get_hex(decoded_config)))
                debug.debug("encoded_magic:\n{0}\n".format(self.get_hex(encoded_magic)))

                offset = 0 

                decoded_magic = ''
                config_key = ''
                aes_key = ''
                rc4_comKey = ''

                found = False

                while offset < len(decoded_config) - RC4_KEYSIZE:
                    
                    config_key = decoded_config[offset:offset+RC4_KEYSIZE]
                    decoded_magic = self.rc4(config_key, encoded_magic, loginKey)

                    # When the first four bytes of the decoded magic buffer equal the size
                    # of the magic buffer, then we've found a winning RC4 key
                    (struct_size,) = struct.unpack("=I", decoded_magic[0:4])

                    if struct_size == addr_space.profile.get_obj_size('_ZEUS_MAGIC'):
                        found = True
                        # With the RC4 key and the BO_LOGIN_KEY, we can now calculate the AES Key
                        aes_key = self.rc4(config_key,hashlib.md5(loginKey).digest(),loginKey)
                        # Initialize the RC4 communication key
                        rc4_comKey = self.rc4_init(aes_key,salt_rc4_initKey)
                        break
                    offset += 1

                if not found:
                    debug.debug('Error, cannot decode magic')
                    continue
                
                debug.debug("decoded_magic:\n{0}\n".format(self.get_hex(decoded_magic)))
                debug.debug("config_key:\n{0}\n".format(self.get_hex(config_key)))

                # grab the URLs from the decoded buffer
                urls = []
                while "http" in decoded_config:
                    url = decoded_config[decoded_config.find("http"):]
                    urls.append(url[:url.find('\x00')])
                    decoded_config = url[url.find('\x00'):]
                
                yield p, start, urls, config_key, decoded_config, decoded_magic, loginKey, aes_key, rc4_comKey

    def render_text(self, outfd, data):

        for p, start, urls, config_key, decoded_config, decoded_magic, loginKey, aes_key, rc4_comKey in data:

            # get a magic object from the buffer
            buffer_space = addrspace.BufferAddressSpace(config=self._config, data=decoded_magic)
            buffer_space.profile.add_types(zeus_types)
            magic_obj = obj.Object('_ZEUS_MAGIC', offset = 0, vm = buffer_space)
            
            url_string = ''
            number = 1
            for url in urls:
                url_string += "URL" + str(number) + ":        {0}\n".format(url)
                number += 1

            syntax = "-" * 50 + '\n' + \
                     "Process:     {0}\n".format(p.ImageFileName) + \
                     "Pid:         {0}\n".format(p.UniqueProcessId) + \
                     "Address:     0x{0:X}\n".format(start) + \
                     url_string + \
                     "Identifier:  {0}\n".format(''.join([chr(c) for c in magic_obj.guid if c != 0])) + \
                     "Mutant key:  0x{0:X}\n".format(magic_obj.guid_xor_key) + \
                     "XOR key:     0x{0:X}\n".format(magic_obj.xorkey) + \
                     "Registry:    HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\{0}\n".format(self.parse_string(magic_obj.keyname)) + \
                     "  Value 1:   {0}\n".format(self.parse_string(magic_obj.value1)) + \
                     "  Value 2:   {0}\n".format(self.parse_string(magic_obj.value2)) + \
                     "  Value 3:   {0}\n".format(self.parse_string(magic_obj.value3)) + \
                     "Executable:  {0}\n".format(self.parse_string(magic_obj.exefile)) + \
                     "Login Key:   {0}\n".format(loginKey).upper() + \
                     "AES Key:     {0}\n".format(self.get_only_hex(aes_key)).upper() + \
                     "Config RC4 Key:\n{0}\n".format(self.get_hex(config_key)) + \
                     "Communication RC4 Key:\n{0}\n".format(self.get_hex(rc4_comKey))

            if self._config.DUMP_DIR:

                fname_conf = "{0}.{1:#x}.conf.key".format(p.UniqueProcessId, start)

                f = open(os.path.join(self._config.DUMP_DIR, fname_conf), "wb")
                if f:
                    f.write(config_key)
                    f.close()

            outfd.write(syntax)

