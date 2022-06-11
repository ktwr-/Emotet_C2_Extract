import socket
import struct
import json
import argparse
import threading
import subprocess
import os

import pefile
import yara

rule_source ="""
rule Emotet
{
    strings:
    $c2_buf1 = { c7 44 ?4 30 ?? ?? ?? ?? c7 04 ?4 ?? ?? ?? ?? c7 44 ?4 28 ?? ?? ?? ?? c7 44 ?4 38 ?? ?? ?? ??  }
    $c2_buf2 = { c7 44 ?4 40 ?? ?? ?? ?? c7 04 ?4 ?? ?? ?? ?? c7 44 ?4 38 ?? ?? ?? ?? c7 44 ?4 48 ?? ?? ?? ??  }

    condition:
        uint16(0) == 0x5A4D and ($c2_buf1 or $c2_buf2)
}
"""

parser = argparse.ArgumentParser(description='Emotet C2\'s Extractor only tested 64bit environment')
parser.add_argument('--pid', dest='target_pid', type=int, help='PID of the process running the Emotet', required=True)
parser.add_argument('--o', dest='output_file', type=str, help='Filename of the output file')
parser.add_argument('--is32bit',action='store_true', help='Specify this flag if the target process is a 32-bit process')

MAX_IP_STRING_SIZE=16
OUTPUT_DIR_PREFIX = "process_"

class PESieve(object):
    active = False

    def __init__(self, workingDir="",is64bit=True):
        if not workingDir:
            self.workingDir = os.getcwd()
        else:
            self.workingDir = workingDir
        
        self.peSieve = os.path.join(workingDir, 'tools/pe-sieve32.exe'.replace("/", os.sep))
        if is64bit:
            self.peSieve = os.path.join(workingDir, 'tools/pe-sieve64.exe'.replace("/", os.sep))

        if self.isAvailable():
            self.active = True
        else:
            print("[-] Cannot find PE-Sieve in expected location {0} ".format(self.peSieve))
            
    def isAvailable(self):
        if not os.path.exists(self.peSieve):
            return False
        return True

    def runProcess(self, command, timeout=10):
        output = ""
        returnCode = 0

        # Kill check
        kill_check = threading.Event()
        def _kill_process_after_a_timeout(pid):
            os.kill(pid, signal.SIGTERM)
            kill_check.set()
            print("[+] timeout hit - killing pid {0}".format(pid))
            return "", 1
        try:
            p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            returnCode = e.returncode
            traceback.print_exc()
        pid = p.pid
        watchdog = threading.Timer(timeout, _kill_process_after_a_timeout, args=(pid, ))
        watchdog.start()
        stdout = p.communicate()[0].decode('utf-8').strip()
        stderr = p.communicate()[1].decode('utf-8').strip()
        watchdog.cancel()
        success = not kill_check.isSet()
        kill_check.clear()
        return stdout, returnCode

    def scan(self, pid, pesieveshellc = False):
        # Presets
        results = {"patched": 0, "replaced": 0, "unreachable_file": 0, "implanted_pe": 0, "implanted_shc": 0}
        # Compose command
        command = [self.peSieve, '/pid', str(pid), '/quiet','/dmode', '1', '/json', '/minidmp'] + (['/shellc'] if pesieveshellc else [])
        # Run PE-Sieve on given process
        output, returnCode = self.runProcess(command)

        if output == '' or not output:
            return results
        try:
            results_raw = json.loads(output)
            results = results_raw["scans"]
        except ValueError as v:
            traceback.print_exc()
            print("[+]Couldn't parse the JSON output.")
        except Exception as e:
            traceback.print_exc()
            print("[+] Something went wrong during PE-Sieve scan.")
        return results

def yara_scan(raw_data):
    res = []
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == "Emotet":
            for item in match.strings:
                res.append(item[2])
    return res

def calc_c2(buf):
    x1 = struct.unpack("<L", buf[4:8])[0]
    x2 = struct.unpack("<L", buf[11:15])[0]
    x3 = struct.unpack("<L", buf[19:23])[0]
    x4 = struct.unpack("<L", buf[27:31])[0]

    ip = socket.inet_ntoa(struct.pack("<I", x1 ^ x3))
    port = (x2 ^ x4) >> 16
    return [ip, port]

def extract_c2(filebuf):
    c2_list = []
    pe = None
    try:
        pe = pefile.PE(data=filebuf, fast_load=False)
    except Exception:
        pass

    if pe is None:
        print("None")
        return

    image_base = pe.OPTIONAL_HEADER.ImageBase
    c2found = False

    yara_matches = yara_scan(filebuf)
    #print(yara_matches)
    if yara_matches != []:
        for dat in yara_matches:
            c2_list.append(calc_c2(dat))

    return c2_list

def write_results(args, c2_matches):
    # print on file if the -o flag is specified
    if args.output_file:
        file = open(args.output_file, "w+")
        file.write("Emotet C2's: \n")
        file.write("\n".join(c2.strip() for c2 in c2_matches))

    # print on the command-line
    print("[+] Emotet C2's:")
    print("\n".join(c2.strip() for c2 in c2_matches))


def main():
    args = parser.parse_args()
    pesieve_instance = None
    c2_lists = []
    if args.is32bit:
        pesieve_instance = PESieve(is64bit=False)
    else:
        pesieve_instance = PESieve()

    if pesieve_instance.active:
        result = pesieve_instance.scan(pid=args.target_pid)
        pesieve_output_dir = os.path.join(pesieve_instance.workingDir, OUTPUT_DIR_PREFIX + str(args.target_pid) + os.sep)
        for scan in result:
            if "workingset_scan" in scan:
                suspicious_workingset_scan = scan["workingset_scan"]
                if suspicious_workingset_scan["pe_artefacts"]["is_dll"] == 1 and suspicious_workingset_scan["pe_artefacts"]["is_64_bit"] == 1:
                    injected_dll_module = suspicious_workingset_scan["module"]
                    injected_dll = open(os.path.join(pesieve_output_dir, injected_dll_module + ".dll"), 'rb')
                    data = injected_dll.read()
                    injected_dll.close()
                    c2_list = [ i[0] + ":" + str(i[1]) for i in extract_c2(data)]
                    if not c2_list in c2_lists:
                        c2_lists.append(c2_list)
    for c2_list in c2_lists:
        write_results(args,c2_list)


if __name__ == "__main__":
    main()