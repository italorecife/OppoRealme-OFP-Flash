# python3
# (c) Italo Almeida 2022, GPL-3.0 License
import os
import sys
import time
import shutil
import hashlib
import tempfile
import subprocess
import xml.etree.ElementTree as ET
from Cryptodome.Cipher import AES
from Cryptodome.Hash import MD5
from binascii import hexlify
from struct import unpack
os.system("")
cpcount = 0
invalidsuper = False
fatalerror = ""
def byebye():
    wait = input("Press Enter to continue...")
    exit(0)
    
def cleanprevious(x):
    for i in range(x):
        sys.stdout.write("\033[A")
        sys.stdout.write("\033[K")

def printc(msg):
    global cpcount
    cpcount += 1 + msg.count("\n")
    print(msg)

def ROR(x, n, bits = 32):
    mask = (2**n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (bits - n))

def ROL(x, n, bits = 32):
    return ROR(x, bits - n, bits)

def bytestolow(data):
    h = MD5.new()
    h.update(data)
    shash = h.digest()
    return hexlify(shash).lower()[0:16]

def deobfuscate(data,mask):
    ret=bytearray()
    for i in range(0, len(data)):
        v = ROL((data[i] ^ mask[i]), 4, 8)
        ret.append(v)
    return ret

def generatekey(filename):
    keys = [
        # R9s/A57t
        ["V1.4.17/1.4.27",
         "27827963787265EF89D126B69A495A21",
         "82C50203285A2CE7D8C3E198383CE94C",
         "422DD5399181E223813CD8ECDF2E4D72"],

        # a3s
        ["V1.6.17",
         "E11AA7BB558A436A8375FD15DDD4651F",
         "77DDF6A0696841F6B74782C097835169",
         "A739742384A44E8BA45207AD5C3700EA"],

        ["V1.5.13",
         "67657963787565E837D226B69A495D21",
         "F6C50203515A2CE7D8C3E1F938B7E94C",
         "42F2D5399137E2B2813CD8ECDF2F4D72"],

         #R15 Pro CPH1831 V1.6.6 / FindX CPH1871 V1.6.9 / R17 Pro CPH1877 V1.6.17 / R17 PBEM00 V1.6.17 / A5 2020 V1.7.6 / K3 CPH1955 V1.6.26 UFS
         #Reno 5G CPH1921 V1.6.26 / Realme 3 Pro RMX1851 V1.6.17 / Reno 10X Zoom V1.6.26 / R17 CPH1879 V1.6.17 / R17 Neo CPH1893 / K1 PBCM30

        ["V1.6.6/1.6.9/1.6.17/1.6.24/1.6.26/1.7.6",
         "3C2D518D9BF2E4279DC758CD535147C3",
         "87C74A29709AC1BF2382276C4E8DF232",
         "598D92E967265E9BCABE2469FE4A915E"],

        #RM1921EX V1.7.2, Realme X RMX1901 V1.7.2, Realme 5 Pro RMX1971 V1.7.2, Realme 5 RMX1911 V1.7.2
        ["V1.7.2",
         "8FB8FB261930260BE945B841AEFA9FD4",
         "E529E82B28F5A2F8831D860AE39E425D",
         "8A09DA60ED36F125D64709973372C1CF"],

        # OW19W8AP_11_A.23_200715
        ["V2.0.3",
         "E8AE288C0192C54BF10C5707E9C4705B",
         "D64FC385DCD52A3C9B5FBA8650F92EDA",
         "79051FD8D8B6297E2E4559E997F63B7F"]

    ]

    for dkey in keys:
        key = bytearray()
        iv = bytearray()
        
        mc = bytearray.fromhex(dkey[1])
        userkey=bytearray.fromhex(dkey[2])
        ivec=bytearray.fromhex(dkey[3])


        key=deobfuscate(userkey,mc)
        iv=deobfuscate(ivec,mc)

        key=bytestolow(key)
        iv=bytestolow(iv)
        pagesize,data=extract_xml(filename,key,iv)
        if pagesize!=0:
            return pagesize,key,iv,data
    return 0,None,None,None


def extract_xml(filename,key,iv):
    filesize=os.stat(filename).st_size
    with open(filename,'rb') as rf:
        pagesize = 0
        for x in [0x200, 0x1000]:
            rf.seek(filesize-x+0x10)
            if unpack("<I",rf.read(4))[0]==0x7CEF:
                pagesize = x
                break 
            
        xmloffset=filesize-pagesize
        rf.seek(xmloffset+0x14)
        offset=unpack("<I",rf.read(4))[0]*pagesize
        length=unpack("<I",rf.read(4))[0]
        if length<200:
            length=xmloffset-offset-0x57
        rf.seek(offset)
        data=rf.read(length)
        dec=aes_cfb(data,key,iv)

        if b"<?xml" in dec:
            return pagesize,dec
        else:
            return 0,""

def aes_cfb(data,key,iv):
    ctx = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
    decrypted = ctx.decrypt(data)
    return decrypted

def copysub(rf,wf,start,length):
    rf.seek(start)
    rlen=0
    while length > 0:
        if length < 0x100000:
            size = length
        else:
            size = 0x100000
        data = rf.read(size)
        wf.write(data)
        rlen+=len(data)
        length -= size
    return rlen

def copy(filename, path, wfilename, start, length, checksums):
    print(f"\nEXTRACTING: {os.path.splitext(wfilename)[0]}")
    with open(filename, 'rb') as rf:
        with open(os.path.join(path, wfilename), 'wb') as wf:
            rf.seek(start)
            data=rf.read(length)
            wf.write(data)

    checkhashfile(os.path.join(path, wfilename), checksums)

def decryptfile(issuper, key, iv, filename, path, wfilename, start, length, rlength, checksums, decryptsize):
    if not issuper:
        print(f"\nEXTRACTING: {os.path.splitext(wfilename)[0]}")
    if rlength==length:
        tlen=length
        length=(length//0x4*0x4)
        if tlen%0x4!=0:
            length+=0x4

    with open(filename, 'rb') as rf:
        with open(os.path.join(path, wfilename), 'wb') as wf:
            rf.seek(start)
            size=decryptsize
            if rlength<decryptsize:
                size=rlength
            data=rf.read(size)
            if size%4:
                data+=(4-(size%4))*b'\x00'
            outp = aes_cfb(data, key, iv)
            wf.write(outp[:size])

            if rlength > decryptsize:
                copysub(rf, wf, start + size, rlength-size)

    checkhashfile(path, wfilename, checksums)
            
def checkhashfile(path, wfilename, checksums):
    global invalidsuper
    sha256sum = checksums[0]
    md5sum = checksums[1]
    with open(os.path.join(path, wfilename),"rb") as rf:
        size = os.stat(os.path.join(path, wfilename)).st_size
        md5 = hashlib.md5(rf.read(0x40000))
        sha256bad=False
        md5bad=False
        md5status="empty"
        sha256status="empty"
        if sha256sum != "":
            for x in [0x40000, size]:
                rf.seek(0)
                sha256 = hashlib.sha256(rf.read(x))
                if sha256sum != sha256.hexdigest():
                    sha256bad=True
                    sha256status="bad"
                else:
                    sha256status="verified"
                    break
        if md5sum != "":
            if md5sum != md5.hexdigest():
                md5bad=True
                md5status="bad"
            else:
                md5status="verified"
        if wfilename in ["super0.img", "super1.img", "super2.img"]:
            if sha256bad and md5bad:
                invalidsuper = True
            return
        if sha256bad and md5bad:
            print(f"EXTRACT ERROR: Error on hashes. OFP {os.path.splitext(wfilename)[0]} partiton might be broken!")
        else:
            flashpartition(os.path.splitext(wfilename)[0], str(os.path.join(path, wfilename)))
    os.remove(os.path.join(path, wfilename))
    
def flashpartition(partition, file):
    global fatalerror
    print(f"FLASHING: {partition}")
    try:
        flashreturn = str(subprocess.check_output(["fastboot", "flash", partition, file], stderr=subprocess.STDOUT))
    except subprocess.CalledProcessError as e:
        flashreturn = str(e.output)
    if "FAILED (remote: Flashing is not allowed for Critical Partitions" in flashreturn:
        print("FLASH FAIL: Changing this partition is not allowed for security reasons (Critical Partition)")
    elif "unknown partition" in flashreturn:
        print("FLASH FAIL: Unknown partition")
    elif "FAILED" in flashreturn:
        print("FLASH FAILED!")
    else:
        print("FLASH SUCCESS!")
    if "read failed (Too many links)" in flashreturn:
        fatalerror = "Use another USB port or another cable, and try flash again!"
    
def decryptitem(item, pagesize):
    sha256sum=""
    md5sum=""
    wfilename=""
    start=-1
    rlength=0
    decryptsize=0x40000
    if "Path" in item.attrib:
        wfilename = item.attrib["Path"]
    elif "filename" in item.attrib:
        wfilename = item.attrib["filename"]
    if "sha256" in item.attrib:
        sha256sum=item.attrib["sha256"]
    if "md5" in item.attrib:
        md5sum=item.attrib["md5"]
    if "FileOffsetInSrc" in item.attrib:
        start = int(item.attrib["FileOffsetInSrc"]) * pagesize
    elif "SizeInSectorInSrc" in item.attrib:
        start = int(item.attrib["SizeInSectorInSrc"]) * pagesize
    if "SizeInByteInSrc" in item.attrib:
        rlength = int(item.attrib["SizeInByteInSrc"])
    if "SizeInSectorInSrc" in item.attrib:
        length = int(item.attrib["SizeInSectorInSrc"]) * pagesize
    else:
        length=rlength
    return wfilename, start, length, rlength,[sha256sum,md5sum],decryptsize
        
def main():
    global cpcount, invalidsuper, fatalerror
    print("Oppo/Realme Flash .OFP File on Bootloader | 1.0 (c) 2022 | Italo Almeida (@SirCDA) - GPL-3.0 License\n")
    print("Usage: Put the .ofp file in the same folder as the program,\nthen put your device in mode fastboot to start flash.")
    print("\nNote: if your device was not recognized in fastboot\nmode by the computer, try to install the adb drivers.")
    print("=======================\n\nSearching for .ofp files")
    filesofp = []
    for file in os.listdir():
        if os.path.splitext(file)[1] != ".ofp":
            continue
        filesofp.append(file)
    if len(filesofp) < 1:
        print("ERROR: No .ofp files were found in the folder!")
        byebye()
    elif len(filesofp) > 1:
        chosed = -1
        while chosed < 1 or chosed > len(filesofp):
            cleanprevious(cpcount)
            cpcount = 0
            printc(">> Choose a file <<")
            for file in filesofp:
                printc(f"{filesofp.index(file)+1} - {file}")
            chosed = input("Choice: ")
            cpcount += 1
            try:
                chosed = int("".join(filter(str.isdigit, chosed)))
            except:
                chosed = -1
        ofpfile = filesofp[chosed-1]
        print(f"Chosen file: {ofpfile}")
    else:
        ofpfile = filesofp[0]
        print(f"File found: {ofpfile}")

    pk=False
    with open(ofpfile,"rb") as rf:
        if rf.read(2)==b"PK":
            pk=True
    if not pk:
        pagesize,key,iv,data=generatekey(ofpfile)
    if pk==True or pagesize==0:
        print("ERROR: Corrupt or incompatible file!")
        byebye()
    xml=data[:data.rfind(b">")+1].decode('utf-8')
    root = ET.fromstring(xml)
    print("OK: Ofp Compatible")
    
    regions = []
    for child in root:
        for item in child:
            if child.tag != "NVList":
                continue
            found = False
            for subregion in regions:
                if subregion[2] == item.attrib["super0"] and subregion[3] == item.attrib["super1"] and subregion[4] == item.attrib["super2"]:
                    found = True
                    break
            if found:
                continue
            regions.append((item.attrib["id"], item.attrib["text"], item.attrib["super0"], item.attrib["super1"], item.attrib["super2"]))
    if len(regions) < 1:
        region = (None, None, None, None)
    elif len(regions) > 1:
        chosed = -1
        cpcount = 0
        while chosed < 0 or chosed > len(regions):
            cleanprevious(cpcount)
            cpcount = 0
            printc("\n>> Choose a Region <<")
            printc("0 - Auto detect with adb")
            for x in regions:
                printc(f"{regions.index(x)+1} - {x[1]} - [ID: {x[0]}]")
            chosed = input("Choice: ")
            cpcount += 1
            try:
                chosed = int("".join(filter(str.isdigit, chosed)))
            except:
                chosed = -1    
            if chosed == 0:
                waitdevice = True
                nvid = ""
                printc("\n>> Waiting for device in adb mode <<")
                while waitdevice:
                    try:
                        nvid = subprocess.check_output(["adb", "shell", "getprop", "ro.build.oplus_nv_id"], stderr=subprocess.STDOUT)
                        nvid = "".join(filter(str.isdigit, str(nvid)))
                        waitdevice = False
                        break
                    except subprocess.CalledProcessError as e:
                        pass
                    time.sleep(1)
                find = False
                if nvid != "" and len(nvid) == 8:
                    for x in regions:
                        if x[0] == nvid:
                            find = True
                            chosed = regions.index(x)+1
                            break
                if not find:
                    printc("INFO: Unable to identify region by adb, choose manually or try another .ofp file!")
                    wait = input("Press Enter to continue...")
                    cpcount += 1
                    chosed = -1
        region = regions[chosed-1]
        print(f"Chosen region: {region[1]} - [ID: {region[0]}]")
    else:
        region = regions[0]
        print(f"Region: {region[1]}")
    
    blacklist = ["ocdt", "oppodycnvbk", "oppostanvbk", "opporeserve1", "modem", "persist"] #Partitions with potential risk of HardBrick, IMEI loss and sensors miscalibration
    cpcount = 0
    while True:
        cleanprevious(cpcount)
        cpcount = 0
        printc("\n>> Can keep some partitions without changing <<")
        printc("0 - Start Flash")
        printc(f"1 - USERDATA(app, settings, internal memory) | STATUS: {'NEW' if 'userdata' not in blacklist else 'KEEP OLD'}")
        printc(f"2 - BOOT | STATUS: {'NEW' if 'boot' not in blacklist else 'KEEP OLD'}")
        printc(f"3 - RECOVERY | STATUS: {'NEW' if 'recovery' not in blacklist else 'KEEP OLD'}")
        chosed = input("Choose to toggle status or start flash: ")
        cpcount += 1
        try:
            chosed = int("".join(filter(str.isdigit, chosed)))
        except:
            continue
        if chosed == 0:
            break
        if chosed == 1:
            blacklist.append('userdata') if 'userdata' not in blacklist else blacklist.remove('userdata')
        if chosed == 2:
            blacklist.append('boot') if 'boot' not in blacklist else blacklist.remove('boot')
        if chosed == 3:
            blacklist.append('recovery') if 'recovery' not in blacklist else blacklist.remove('recovery')
            
        
    cpcount = 0
    while True:
        cleanprevious(cpcount)
        cpcount = 0
        printc("\n=================DISCLAIMER=================")
        printc("We are not responsible for bricked devices, dead SD cards,")
        printc("thermonuclear war, or you getting fired because the alarm app failed. Please")
        printc("do some research if you have any concerns about features included in this ROM")
        printc("before flashing it! YOU are choosing to make these modifications, and if")
        printc("you point the finger at us for messing up your device, we will laugh at you.")
        printc("=================DISCLAIMER=================")
        printc("1 - I understand and wish to continue")
        printc("0 - Exit")
        chosed = input("Choice: ")
        cpcount += 1
        try:
            chosed = int("".join(filter(str.isdigit, chosed)))
        except:
            continue
        if chosed == 0:
            exit(0)
        if chosed == 1:
            break
    
    print("\n>> Waiting for device in fastboot mode to start <<")
    try:
        subprocess.check_output(["adb", "reboot", "bootloader"], stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        pass
    allvar = subprocess.check_output(["fastboot", "getvar", "all"], stderr=subprocess.STDOUT)
    partitions = []
    incompatible = True
    for line in str(allvar).split("\\n"):
        line = line.replace(" ", "").replace(" ", "").replace("\\r", "")
        if "partition-type" in line:
            partition = line.replace("(bootloader)partition-type:", "").split(":")[0]
            if partition.replace("_a", "").replace("_b", "") in blacklist:
                continue
            partitions.append(partition)
        elif "unlocked:no" in line:
            print("ERROR: Your device needs to have an unlocked bootloader!")
            byebye()
        elif "unlocked:yes" in line:
            print("OK: Device unlocked")
            incompatible = False
    if incompatible:
        print("ERROR: Potentially incompatible device, contact developer!")
        byebye()
        
    print("\nStarting process....\nNote: this may take a while, it will make some popcorn for now.")
    path = tempfile.mkdtemp()
    xmlfiles = []
    for child in root:
        for item in child:
            if "Path" not in item.attrib and "filename" not in item.attrib:
                for subitem in item:
                    wfilename, start, length, rlength, checksums, decryptsize = decryptitem(subitem, pagesize)
                    if wfilename=="" or start==-1:
                        continue
                    xmlfiles.append((wfilename, start, length, rlength, checksums, decryptsize, False))
            wfilename, start, length, rlength, checksums, decryptsize = decryptitem(item, pagesize)
            iscopy = False
            if wfilename=="" or start==-1:
                continue
            if child.tag in ["Sahara"]:
                decryptsize=rlength
            if child.tag in ["Config","Provision","ChainedTableOfDigests","DigestsToSign", "Firmware"]:
                length=rlength
            if child.tag in ["DigestsToSign","ChainedTableOfDigests", "Firmware"]:
                iscopy = True
            xmlfiles.append((wfilename, start, length, rlength, checksums, decryptsize, iscopy))
    for child in root:
        for item in child:
            if child.tag != "ProgramList" or item.attrib["label"] not in partitions or item.attrib["filename"] == "":
                continue
            for file in xmlfiles:
                if item.attrib["filename"] == file[0] and "ddr4" not in file[0] and "ddr5" not in file[0]:
                    if file[6]:
                        copy(ofpfile, path, f'{item.attrib["label"]}.img', file[1], file[2], file[4])
                    else:
                        decryptfile(False, key, iv, ofpfile, path, f'{item.attrib["label"]}.img', file[1], file[2], file[3], file[4], file[5])
    if len(regions) >= 1:
        print("\nEXTRACTING: super")
        for file in xmlfiles:
            if file[0] in region:
                decryptfile(True, key, iv, ofpfile, path, "super0.img" if "super.0" in file[0] else "super1.img" if "super.1" in file[0] else "super2.img", file[1], file[2], file[3], file[4], file[5])
        if invalidsuper:
            print("EXTRACT ERROR: Error on hashes. OFP super partiton might be broken!")
        else:
            try:
                subprocess.check_output(["simg2img", str(os.path.join(path, "super0.img")), str(os.path.join(path, "super1.img")), str(os.path.join(path, "super2.img")), str(os.path.join(path, "super.img"))], stderr=subprocess.STDOUT)
                flashpartition("super", str(os.path.join(path, "super.img")))
            except subprocess.CalledProcessError as e:
                print("EXTRACT ERROR: Error on super's. OFP super partiton might be broken!")
    shutil.rmtree(path)
    if fatalerror == "":
        print("\nDone. ofp file flashed with success!")
    else:
        print(f"\nFATALERROR: {fatalerror}")
    byebye()


if __name__=="__main__":
    main()
