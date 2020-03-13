# Date 03/12/2020 - March
# CVE-2020-0796 (SMBGhost,CoronaBlue) Workaround Scanner - Created by Ahmad Almorabea @almorabea
# Description: SMBv3 "SMB 3.1.1" has an unauthenticated RCE vulnerability and it's critical - Remember WannaCry/Petya/NotPetya ?!

from winreg import *
import platform, os
from ctypes import *

print("Your system information as follows")
print(platform.uname())

if "Windows-7" in platform.platform() or "Windows-8" in platform.platform():
    exit("Your System is not Vulnerable to SMBv3 ")


Registry = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
path = "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters"
RawKey = OpenKey(Registry, path)
name, value, type = EnumValue(RawKey, 9)

try:
    is_admin = os.getuid() == 0
except AttributeError:
    is_admin = windll.shell32.IsUserAnAdmin() != 0

if value == 1:
    print("Not Vulnerable")
else:
    if is_admin:
        res = input("Your System is Vulnerable, You want to apply the workarounds? y/n  ")
        if res == "y":
            try:
                registry_key = OpenKey(HKEY_LOCAL_MACHINE, path, 0, KEY_WRITE)
                SetValueEx(registry_key, "DisableCompression", 0, REG_DWORD, 1)
                CloseKey(registry_key)
                exit("Workarounds applied!!")
            except WindowsError as message:
                print(message)
        else:
            exit("Good luck, you didn't choose yes so live with this option!")
    else:
        exit("Please run this script as administrator, Now you are not an admin to execute the commands!")
