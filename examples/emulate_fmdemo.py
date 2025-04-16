import logging
import os
import urllib.request
from pathlib import Path

from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS
from chomper.objc import ObjC
from chomper.utils import pyobj2nsobj

from unicorn import arm64_const

base_path = os.path.abspath(os.path.dirname(__file__))

log_format = "%(asctime)s - %(name)s - %(levelname)s: %(message)s"
logging.basicConfig(
    format=log_format,
    level=logging.INFO,
)

logger = logging.getLogger()


def download_sample_file(binary_path: str) -> str:
    filepath = os.path.join(base_path, "..", binary_path)

    path = Path(filepath).resolve()
    if path.exists():
        return filepath

    if not path.parent.exists():
        path.parent.mkdir(parents=True)

    url = "https://sourceforge.net/projects/chomper-emu/files/%s/download" % binary_path
    print(f"Downloading sample file: {url}")
    urllib.request.urlretrieve(url, path)

    return filepath



def hook_CC_MD5(uc, address, size, user_data):
    emu = user_data["emu"]
    emu.logger.info("CC_MD5 called")

#+[ViewController md5FromString:]:
def hook_md5FromString(uc, address, size, user_data):
    emu = user_data["emu"]
    emu.logger.info("+[ViewController md5FromString:]: called")

# def hook_ui_device_identifier_for_vendor(uc, address, size, user_data):
#     emu = user_data["emu"]
#     objc = ObjC(emu)
#     return objc.msg_send("NSUUID", "UUID")

def hook_retval(retval): #hook 修改返回值
    def decorator(uc, address, size, user_data):
        return retval

    return decorator


    

def hook_arc4random(uc, address, size, user_data):
    emu = user_data["emu"]
    emu.logger.info("arc4random called")
    #emu.set_retval(0)
    random = emu.get_retval()
    print(f"arc4random value: {random}")
    return 0

    #return 1

def hook_cf_uuid_create_string(uc, address, size, user_data):
    emu = user_data["emu"]
    cf_uuid = emu.call_symbol("_CFUUIDCreate", 0)
    cf_uuid_str = emu.call_symbol("_CFUUIDCreateString", 0, cf_uuid)
    return cf_uuid_str

def printDataHexStr(data):    
    hex_str = ' '.join(f'{byte:02X}' for byte in data)
    print(hex_str)
    return hex_str

def trace_inst_callback(uc, address, size, user_data):
    emu = user_data["emu"]
    #emu.logger.info("x777: %i", size);
    inst = next(emu.cs.disasm_lite(uc.mem_read(address, size), 0))
    emu.logger.info(
        f"Trace at2 {emu.debug_symbol(address)}: {inst[-2]} {inst[-1]}"
    )

    # Display all register status
    regs = []
    for i in range(31):
        regs.append(f"x{i}: {hex(emu.uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X{i}')))}")
    regs.append(f"sp: {hex(emu.uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_SP')))}") 
    emu.logger.info(", ".join(regs))



    #emu.logger.info("x888: %2X", address);
    #emu.logger.info("x999: %d", uc.mem_read(address, size));

    #instrctData = uc.mem_read(address, size)
    #logger.info("instrctData_hex_str: %s", printDataHexStr(instrctData))

    # 0xb2c600000

    # if address == 0x100070abc:
    #     x8 = emu.uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X{8}'));
    #     #emu.logger.info("x888: %i", x8);
    #     emu.logger.info("x888: %i", address);

    #     emu.logger.info("x999: %i", uc.mem_read(address, size));



    
    #inst = next(emu.cs.disasm_lite(uc.mem_read(address, size), 0))
    # emu.logger.info(
    #     f"Trace at {emu.debug_symbol(address)}: {inst[-2]} {inst[-1]}"
    # )

    #emu.logger.info(emu.debug_symbol(address))
    # symbol = emu.debug_symbol(address);

    # if isinstance(symbol, str) and "FMDeviceManagerDemo" in symbol:
    #     inst = next(emu.cs.disasm_lite(uc.mem_read(address, size), 0))
    #     emu.logger.info(f"Trace at {emu.debug_symbol(address)}: {inst[-2]} {inst[-1]}")

    # # Display all register status
    #     regs = []
    #     for i in range(31):
    #         regs.append(f"x{i}: {hex(emu.uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X{i}')))}")
    #     emu.logger.info(", ".join(regs))

def hook_retval(retval):
    def decorator(uc, address, size, user_data):
        print("hook_retval")
        return retval
    return decorator

def hook_dlopen(uc, address, size, user_data):
    emu = user_data["emu"]
    emu.logger.info("interceptor_dlopen called")
    print(user_data)    
    emu.logger.info(user_data)


def hook_ui_device_current_device(uc, address, size, user_data):
    emu = user_data["emu"]
    emu.logger.info("+[UIDevice currentDevice] called")
    
def hook_ui_device_identifier_for_vendor(uc, address, size, user_data):
    emu = user_data["emu"]
    print("idfv413")    
    objc = ObjC(emu)
    uuid = objc.msg_send("NSUUID", "alloc")
    fixed_uuid= pyobj2nsobj(emu, "922510A7-A0EF-46B9-AA27-BB392944EB04")
    idfv = objc.msg_send(uuid, "initWithUUIDString:", fixed_uuid)
    idfvStr = objc.msg_send(idfv, "UUIDString")
    idfvStrBuf = emu.read_string(objc.msg_send(idfvStr, "cStringUsingEncoding:", 4))
    print("idfv5")
    print(type(idfvStrBuf))
    print(idfvStrBuf)

    return idfv;
    #return objc.msg_send("NSUUID", "UUID")

def hook_CNCopySupportedInterfaces(uc, address, size, user_data):
    print("hook_CNCopySupportedInterfaces")
    print(user_data)
    emu = user_data["emu"]
    objc = ObjC(emu)
    array = objc.msg_send("NSArray", "array")
    return array

def hook_res_9_ninit(uc, address, size, user_data):
    return -1;

def hook_ui_screen_initialize(uc, address, size, user_data):
    pass

def hook_UIScreen_mainScreen(uc, address, size, user_data):
    print("hook_UIScreen_screens")
    emu = user_data["emu"]
    objc = ObjC(emu)
    #screen = objc.msg_send(objc.msg_send("UIScreen", "alloc"),"init");
    return objc.msg_send("UIScreen", "alloc");
    
def hook_UIScreen_brightness(uc, address, size, user_data):
    emu = user_data["emu"]
    objc = ObjC(emu)
    return 0.5

def hook_UIScreen_screens(uc, address, size, user_data):
    emu = user_data["emu"]
    objc = ObjC(emu)
    print("hook_UIScreen_screens")
    return 

def hook_getpid(uc, address, size, user_data):
    emu = user_data["emu"]
    objc = ObjC(emu)
    print("hook_getpid")
    retval = emu.get_retval();
    print(f"hook_getpid_retval: {retval}")

def hook_CC_SHA256(uc, address, size, user_data):
    emu = user_data["emu"]
    objc = ObjC(emu)
    buf = emu.get_arg(2)    
    print("hook_CC_SHA256")
    # hashStr_str = emu.read_string(emu.get_arg(0))
    # print(hashStr_str)

    print(emu.get_arg(1))

    hashStr_str2 = emu.read_string(emu.get_arg(2))
    print(hashStr_str2)
    print(emu.get_arg(2))
    print("hook_CC_SHA256_end")

def hook_dyld_image_count(uc, address, size, user_data):
    print("hook_dyld_image_count")
    print(f"address : {address} size: {size}")
    print(type(user_data))
    print(user_data.keys())
    print(user_data)
    emu = user_data["emu"]

    retval = emu.get_retval()
    print(f"retval: {retval}")
    print(retval)
    print(emu)
    print(type(emu))
    #print(emu.modules)

# hook_strlen
def hook_strlen(uc, address, size, user_data):
    print("hook_strlen")
    emu = user_data["emu"]
    str1 = emu.get_arg(0)
    print(f"str: {str1}")
    #retval = emu.get_retval()
    #print(f"retval: {retval}")



def hook_IOServiceGetMatchingService(uc, address, size, user_data):
    print("hook_IOServiceGetMatchingService")
    return 0

def hook_IORegistryEntryCreateCFProperties(uc, address, size, user_data):
    print("hook_IORegistryEntryCreateCFProperties")
    return 0    

def hook_NSTimeZone_time(uc, address, size, user_data):
    emu = user_data["emu"]
    objc = ObjC(emu)
    print("hook_NSTimeZone_time")
    retval = emu.get_retval();
    timeZone_time = emu.read_string(objc.msg_send(retval, "cStringUsingEncoding:", 4))
    #print(f"hook_NSTimeZone_time: {timeZone_time}")
    logger.info("hook_NSTimeZone_time: %s", timeZone_time)   

def hook_malloc(uc, address, size, user_data): 
    emu = user_data["emu"]    
    print("hook_malloc")
    mallocSize = emu.get_arg(0)
    print(f"mallocSize: {mallocSize}");
    print(f"mallocSize1: {emu.get_arg(1)}");
    print(f"mallocSize2: {emu.get_arg(2)}");

def xor_with_55_and_print_ascii(data: bytes):

    header = "Offset  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  Decoded Text"
    separator = "-" * len(header)

    print(header)
    print(separator)

    # 每行处理 16 个字节
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]  # 获取当前行数据
        offset = f"{i:06X}"     # 当前行的偏移量（6 位十六进制）

        # 十六进制表示
        hex_values = " ".join(f"{b ^ 0x55:02X}" for b in chunk).ljust(3 * 16)

        # ASCII 解码
        ascii_text = "".join(chr(b ^ 0x55) if 32 <= (b ^ 0x55) <= 126 else "." for b in chunk)

        # 打印当前行
        print(f"{offset}  {hex_values}  |{ascii_text}|")

    print(separator)


def main():
    binary_path = "examples/binaries/ios/com.tongdun.FMDeviceManagerDemo1/FMDeviceManagerDemo"

    # Download sample file from SourceForge
    #download_sample_file(binary_path)
    #download_sample_file(f"{binary_path}/../Info.plist")

    emu = Chomper(
        arch=ARCH_ARM64,
        os_type=OS_IOS,
        rootfs_path=os.path.join(base_path, "../rootfs/ios"),
        enable_ui_kit=True,
        trace_inst=False,
        # Specify custom callback
        trace_inst_callback=trace_inst_callback
    )
    objc = ObjC(emu)

        # FMDIStruct *subFMDIStruct1 = NULL;
        # FMDIStruct_Init(&subFMDIStruct1, 200);

    #image = emu.load_module(os.path.join(base_path, "..", binary_path))
    image = emu.load_module(os.path.join(base_path, "..", binary_path),
        exec_init_array = True,
        exec_objc_init = True,
        #trace_inst = True,
        #trace_symbol_calls = trace_inst_callback
        )

    emu.add_hook("_arc4random", hook_arc4random)

    emu.add_interceptor(image.base + 0x1c5aa8, hook_retval(0))

    emu.add_interceptor("-[UIDevice identifierForVendor]", hook_ui_device_identifier_for_vendor)

    emu.add_interceptor("_CNCopySupportedInterfaces", hook_CNCopySupportedInterfaces)

    emu.add_interceptor("_res_9_ninit", hook_res_9_ninit)

    emu.add_interceptor("+[UIScreen initialize]", hook_ui_screen_initialize)
    emu.add_interceptor("+[UIScreen mainScreen]", hook_UIScreen_mainScreen)
    emu.add_interceptor("-[UIScreen brightness]", hook_UIScreen_brightness)

    emu.add_hook("+[UIScreen screens]", hook_UIScreen_screens)

    #emu.add_hook("_getpid", hook_getpid)

    #emu.add_hook("__dyld_image_count", hook_dyld_image_count)

    emu.add_interceptor("__dyld_image_count", hook_dyld_image_count)

    emu.add_interceptor("_IOServiceGetMatchingService", hook_IOServiceGetMatchingService)
    
    emu.add_interceptor("_IORegistryEntryCreateCFProperties", hook_IORegistryEntryCreateCFProperties)

    #emu.add_hook("+[NSData dataWithBytesNoCopy:length:]", hook_nsdata_WithBytesNoCopy_length)

    #emu.add_hook("_strlen", hook_strlen)
    #emu.add_interceptor("_strlen", hook_strlen)

    # emu.add_interceptor("_CC_SHA256", hook_CC_SHA256)

    # #emu.add_interceptor("-[NSTimeZone name]", hook_NSTimeZone_time)
    # emu.add_interceptor("_malloc", hook_malloc)

    #emu.add_hook("_dlopen", hook_dlopen)

    #emu.add_interceptor("_dlopen", hook_retval(0))
    #add_interceptor

# {
#   "timeLimit" : 15,
#   "channel" : "oversea",
#   "partner" : "LPZ13",
#   "allowd" : "allowd",
#   "42cbfcd0c5809fad" : "42cbfcd0c5809fad",
#   "proxy" : 0,
#   "profileUrl" : "https:\/\/cn-fp.apitd.net\/ios\/v1",
#   "searchBlackBoxUrl" : "http:\/\/10.59.81.216:8088\/restricted\/deviceQuery.json",
#   "location" : true,
#   "deviceName" : true,
#   "appKey" : "21e0888fe80cfeb4b3bb228928883ff3",
#   "appKeyAESPass" : true,
#   "clientKey" : "c219324c55c2a9bd0d782734076fda21",
#   "country" : "cn",
#   "IDFA" : true
# }



    # Call function
    # logger.info("create_buffer")
    # structBufPtr = emu.create_buffer(8);    
    # logger.info("structBufPtr: 0x%2X", structBufPtr)  


    # emu.call_address(image.base + 0x7076c, structBufPtr,100) #  FMDIStruct_Init

    # structBufPtr1 = emu.read_pointer(structBufPtr);
    # logger.info("structBufPtr1: 0x%2x", structBufPtr1)

    # #emu.call_address(image.base + 0x68e48, structBufPtr,100) #  FMDIStruct_Init


    # structBytes = emu.read_bytes(structBufPtr1,0x100)

    # hex_str = ' '.join(f'{byte:02X}' for byte in structBytes)
    # logger.info("hex_str: %s", hex_str)

    # headPtr = emu.read_pointer(structBufPtr1 + 24);
    # logger.info("headPtr: 0x%2x", headPtr)


    # #headPtr1 = emu.read_pointer(headPtr);
    # headMagic = emu.read_bytes(headPtr,16)

    # hex_str = ' '.join(f'{byte:02X}' for byte in headMagic)
    # logger.info("hex_str: %s", hex_str)

    

    with objc.autorelease_pool():
        logger.info("autorelease_pool")

        structBuf2Ptr = emu.create_buffer(8);
        #emu.call_address(image.base + 0x68e48, structBuf2Ptr,100) #  FMDIStruct_Init
        emu.call_address(image.base + 0x7076c, structBuf2Ptr,100) #  FMDIStruct_Init
        structBuf1Ptr = emu.read_pointer(structBuf2Ptr); 
        logger.info("structBuf1Ptr  :0x%2x", structBuf1Ptr)
        # 0x80c8000
        
        structBytes = emu.read_bytes(structBuf1Ptr,0x60)
        printDataHexStr(structBytes)

        #get addField 0x100070b7c
        structBytes = emu.read_bytes(structBuf1Ptr + 0x68,8)
        printDataHexStr(structBytes)

        headPtr = emu.read_pointer(structBuf1Ptr + 24);
        logger.info("headPtr: 0x%2x", headPtr)
        structBytes = emu.read_bytes(headPtr,4)
        printDataHexStr(structBytes)
        logger.info("printHeadMagic")


        deliverOptionsData = pyobj2nsobj(emu, b'{"channel" : "oversea","partner" : "LPZ13", "allowd" : "allowd",\
          "42cbfcd0c5809fad" : "42cbfcd0c5809fad",\
          "proxy" : 0,\
          "profileUrl" : "https:\/\/cn-fp.apitd.net\/ios\/v1",\
          "searchBlackBoxUrl" : "http:\/\/10.59.81.216:8088\/restricted\/deviceQuery.json",\
          "location" : false,\
           "timeLimit" : 15, \
         "deviceName" : true, \
          "appKey" : "21e0888fe80cfeb4b3bb228928883ff3", \
          "appKeyAESPass" : true, \
          "clientKey" : "c219324c55c2a9bd0d782734076fda21",\
          "country" : "cn",\
          "IDFA" : true \
        }')


        deliverOptions = objc.msg_send("NSJSONSerialization", "JSONObjectWithData:options:error:",deliverOptionsData,1,0);

        # keys = objc.msg_send(deliverOptions, "allKeys")
        # firstKey = objc.msg_send(keys, "firstObject")
        # firstKeyStr = emu.read_string(objc.msg_send(firstKey, "cStringUsingEncoding:", 4))
        # logger.info("firstKeyStr: %s", firstKeyStr)

        # logger.info("deliverOptions: %s", deliverOptions)
        
        emu.call_address(image.base + 0x075198, 0,structBuf1Ptr,deliverOptions)  #  collectSub1
        print("finished collectSub1")

        dataObj = emu.call_address(image.base + 0x0715d4, structBuf1Ptr)  #  FMDIStruct_GetStructData    
        print("FMDIStruct_GetStructData")

        dataBytes = objc.msg_send(dataObj, "bytes")
        length = objc.msg_send(dataObj, "length")
        print(f"dataLength: {length}")
        structBytes = emu.read_bytes(dataBytes,length)
        #printDataHexStr(structBytes)

        mDataOffset = emu.read_s32(structBuf1Ptr + 56); 
        print(f"mDataOffset: {mDataOffset}")
        mData =  emu.read_pointer(structBuf1Ptr + 64);

        deviceData = emu.read_bytes(mData, mDataOffset)
        xor_with_55_and_print_ascii(deviceData)
        #printDataHexStr(deviceData)


        #mDataOffset = femu.read_s32(structBuf1Ptr + 56); 



if __name__ == "__main__":
    main()
