
import time
from dexlib import get_api_access_token
from dexlib import get_devices, get_modbus_devices
from dexlib import get_devices_access_token
from dexlib import get_device_server_attributes
from dexlib import push_device_data
from pyModbusTCP.client import ModbusClient
from pyModbusTCP import utils

from config import ACCOUNTS
from config import HOST_LIST, PORT, VOLTAGE_ADDRESS, CURRENT_ADDRESS

devices = []
dashboards = []

# conversion logic functions goes Here
def U8_conversion(regs,divide):
    return (regs / divide)
def S16_conversion(regs,divide):
    return (regs / divide) 
def STRING_NORM_conversion(regs,divide):
    return (regs / divide)
def S32_conversion(regs,divide):
    return (regs / divide)
def U32_conversion(regs,divide):
    return (regs / divide)
def U16_conversion(regs, divide):
    return (regs / divide)

print("------- Starting DX-SNMP-Module -------")

print(" --- Getting Accesstokens ---")
user_accounts = []
for email, password in ACCOUNTS:
    user_accounts.append(get_api_access_token(email, password))
print(" --- Successfully Acquired Access Tokens ---")

print(" --- Getting Devices ---")
for _, __, access_token in user_accounts:
    devices += get_devices(access_token)
    devices = get_modbus_devices(devices)
print(" --- Successfully Acquired List of Devices ---")

print(" --- Getting Devices Attributes ---")
for _, __, access_token in user_accounts:
    devices = get_device_server_attributes(devices, access_token)
print(" --- Successfully Acquired Attributes of Devices ---")

while True:
    for d in devices:
        print(d)
        try:
            HOST = d['server_attr']['ip']
            PORT = d['server_attr']['port']
            REG_DETAILS = d['server_attr']['reg_address']
            UNIT_ID = d['server_attr']['unit_id']

            c = ModbusClient(host=HOST, port=int(PORT), unit_id=int(UNIT_ID))
            c.open()
            if not c.is_open():
                if not c.open():
                    print("unable to connect to Host Server")
                else:
                    # write for loop here
                    for reg in REG_DETAILS.split(","):
                        ADDRESS = reg.split(",")[0].split("-")[0]
                        WORDCOUNT = reg.split(",")[0].split("-")[1]
                        DTYPE =  reg.split(",")[0].split("-")[2]
                        # check DATATYPE of register and then SET DIVIDENT Acoording to that
                        if str(DTYPE) == 'STRING_NORM' or str(DTYPE) == 'U8' or str(DTYPE) == 'S32' or str(DTYPE) == 'S16' or str(DTYPE) == 'U32':
                            DIVIDENT= 1
                        else:
                            DIVIDENT= reg.split(",")[0].split("-")[3]
                            DIVIDENT = int(DIVIDENT)
                        # store WORDCOUNT in REGISTERS
                        REGISTERS = WORDCOUNT  
                        # if open() is ok, read register (modbus function 0x03)
                        if c.is_open():
                            # read 10 registers at address 0, store result in regs list
                            try:
                                regs = c.read_holding_registers(int(ADDRESS),int(REGISTERS))
                                
                                # regs = utils.word_list_to_long(regs)
                                if DTYPE == 'U8':
                                    for regss in regs:
                                        regs = U8_conversion(float(regss),DIVIDENT)
                                elif DTYPE == 'S16':
                                    for regss in regs:
                                        regs = S16_conversion(float(regss),DIVIDENT)
                                elif DTYPE == 'STRING_NORM':
                                    for regss in regs:
                                        regs = STRING_NORM_conversion(float(regss),DIVIDENT)
                                elif DTYPE == 'S32':
                                    if type(regs) == list:
                                        for regss in regs:
                                            regs = S32_conversion(float(regss),DIVIDENT)
                                    else :
                                        regs = str(regs)
                                elif DTYPE == 'U32':
                                    regs = utils.word_list_to_long(regs)
                                    for register in regs:
                                        regs = U32_conversion(float(register),DIVIDENT)
                                elif DTYPE == 'U16':
                                    for register in regs:
                                        regs = U16_conversion(float(register), DIVIDENT)
                                    print(regs)
                                else :
                                    regs = utils.word_list_to_long(regs)
                                    for register in regs:
                                        regs = register
                                
                                push_device_data(d, {ADDRESS:regs})
                            except:
                                push_device_data(d, {ADDRESS: "None Type"})
                                print("error")
        except Exception as e:
            print("Error:")
            print(e)
        time.sleep(0.5)

            
        
