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



    

def hook_arc4random(uc, address, size, user_data):
    emu = user_data["emu"]
    emu.logger.info("arc4random called")

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

    #emu.add_hook("_arc4random", hook_arc4random)

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

        #cf_uuid_create_string_addr = emu.find_symbol("_CFUUIDCreateString").address
        #emu.add_interceptor(cf_uuid_create_string_addr, hook_cf_uuid_create_string)

        #print("count_result0")
        #count_result = emu.call_symbol("_CFUUIDCreateString");
        #print("count_result")

        # charStr = call_symbol("_CFStringToCString",count_result);    
        # print("count_result")



        # count_result = emu.call_symbol("dyld_image_count");
        # print("count_result_begin")
        # print(count_result)
        # print("count_result_end")

        
        #  crash 0x100145aa4
        #  tongduncollect_idfa


        # ViewControllerClass = objc.msg_send("ViewController", "alloc")
        # viewCtrl =  objc.msg_send(ViewControllerClass, "init")

        # inputStr = pyobj2nsobj(emu, "abcdef")
        # key = pyobj2nsobj(emu, "secret")

        # hashStr = objc.msg_send("ViewController", "xorString:withKey:", inputStr, key);

        # hashStr_str = emu.read_string(objc.msg_send(hashStr, "UTF8String"))

        # logger.info("hash result: %s", hashStr_str)

        # # Decrypt
        # headers = pyobj2nsobj(emu, {
        #     "sks": "2,1,0",
        #     "Content-Type": "application/json;charset=UTF-8",
        # })
        # data = pyobj2nsobj(emu, b'{"code": 200,"data": "A3El6CecquxeBgFfJp6x_tKc1zVwCWWkH0UTXyaXo-27jC1_2U_nzggUCwgmnq39TletamG4gewYWlRRPtElIo7RMypAbgcKy74TXyafq-oSY1TcqMAlfht9VAomyeCqumtCsGCdb4leBgFDV6OXtJ74awXPXPNYXAYBQzTe-6BYmxA64jWhjV8BAUE9x_GpVGOrgZbXdftAFEIDcbqmu2004a9i_OXuWxoTB22Hrvxwvtn2UVu9Yd0W1siLFkchnGB_P5aHzZPxBAWWoFQnFeIwr2Y3ltOh1o7UxLoVSCSOYEJTjWml5cTTn-3icGJxh0TR-QVTSxyFkqGWs00lI72GG4aKXYEnw47U_q8UVgYFMP4Xnu98Df3frNHhRHy7OxV9MQ98ZLNWDwFDKNGu9jeAYGrEtjVuBEJFA3fJ7baMZguGC2ITEQNYHxBrnu3pTshTK2Y3UM8eX1Yaat6r9Ce570Nr1dudXA4eEmfKofzfFA5ly6XdNFgCVxIykKOsAACEhQl9gJFfVFJdboOluw-5BzK576TDARQLQjTD8KqVozD5MxCnmAl4UB5h0fi70vkfySKTJqQfG14VcJasu4fsLCH7VZtZVgYdUW2Ajf-ThHzndnPBqRlYRRZ20fitAnuXZt3rFysPQhNJJpu27TIw4dJtty4zCUFEXWecr7bRKmw-Nfbvnx5ZVQZnh-3Jb-MggsYgs1cYV1gfO4Cy7B1aN07b6d-7VAcGVXect-vjjDIASPwIpgNZRR5lganqrX_VbJgKwb0VYFAfcZaL_bD2-6-kQEFzWgQXAG-Gi_3HW95e-4IPxFUGFxdhh6PwQgdk-sLS_71JAXNWNsGn4WajbZMgjflsH2BQHyHB8LwtvLXFxzfcCl4TAzAhwfD8asE_HHfSeJc6V11WNsHnqt4gg7VujYf7SQRyVjbBp-G9Fbgkv3IbmjpXXVY2weeq0RCS0FmUD21JBHJWNsGn4b0VuCS_chuaJFNYFGyH56vaMcPHJiG5AUIAAkUhwfC8b7x-CzGW2r8_QkgfYae76Ru3HzHfKdohXgQAVjbB565STWNSiaiQJwlERQpSkq7srPPkb-PNAtdUBghDMsHuuw3mpNADBjY3XQ4CRzTK-6nqSqLhgushjjhEUBBtnaXdHeZ9qqicyRVATRMBa4SJ_APfNbNjZnVCXw4DQTHB8qlwG-HRnstQXFwGAUM0w_KpSkxVLZZyKbJBDwNBN8D1qaWxJ2IdugJHXwYBQCbf4OpSGax4iYKMhVgAA0c1we678N2msCTz2cSKipqbjkLifPKjCIxr1p-KXQYBQ-FPYqiNcCp5fEn7C-CzEZWGXyQVwvfigRxjLbzWjtTEutP2fOzuUgD5IdIWThoTA3aaofzNo_qVJziCbwBZVhxRga67BM9Ry-jiea1DGVIXat2y9lvahqiOpwOlQ0ZDHCmar_506ahYxsBVmgVbVlw2w_CtDBp_9mkeOwpbBwVGZpXz-MZpkqqhwCmUDlBUQGCV8Ph56t-7Mxt6VQsUHVF3nK79aNHI4yd1fXVaAh1Rd5y360gTkVRgyjXuTlBeHHCeo-uCIeAIszD7K04aExp3t6f12rq3uOSMpBkKUBNJNN_g-pA7aDU0Ma67XRoTAWGXq-sdsh6mV0a1sRhGQkkr3K-3nLS9vp59bJZDRF4GcJawtsAVE85aLqigPEReF3GQtt1bj3PAMDwefRl_VU41x_avPAAskKxRHeQeVVQ9ZZ6npNL5H8kikyakHxBBAWuDp-sZViAuo_mIDAgLBUsxy_Oq_hmlK80hA2wICwZCPMD2rWPSVZcX8rs7BVp0C3C-o-nfPHXL5gOqBhRCeB5jp7D4VR6FTw0UcShJBXBWNsHzvCThnQokPcvTCU5FOmmUlvbnTp65O29HoF93FEE2w-erFLMxdneGfJ4UQngeY7et7rYB4gRejkOgX3cUQTbC56sUszF2d4Z8nhRCeB5jt63u819cef613npeBBRARdbwq_HTdVCu0tlESQRyVjbBq_Q4bVTX4mK6WhxTFEE21vHYilV38-Rjcq5bchNfJoOw9o5NixAvPGWsGVN4FybJ9qFyxgrm1v5F_k5FWgZNl-CjGfNobMgC-j1cGhMQa56v9o2O1_7BsSu9KFdFEibJueT1I7t5tSkv1xgUCyh_0ab4AjqcDEC3vA9UAAVDNN_g9RZOArz2d5yfHllGOGGK4KPODRWF-cn-Sl4DA0M0w5HJBGKqv2rr0FRcBAhHN8P1r4qWWHlLbSiAH0ZEOmDR-Khd6cbQCCM1DU5CWAdoluCjSjiGSVYUEviLjb6WgUsnNAu-Yf5L9y9YWNOV1OF_R3_h0k48jep7Q4mBj5WOTiUjQzuuFHicuSPCqNfwpBthHNiPHwR6Zs7d_NOGzeNJenwm1o6uIISqWYm7mpSQbCUjHeiU9ICmQxHxlNTEutHuu8qHb_4wSNKkXAYdUWicpfayj6fkXYt4LhhGQkkr3KH9aFd1HIOs6WJCVV4eK4Ow9meDoL3K2063C19fXm2epbasaCc3x54rmENXUkpnlvT4J_KKqHbDWYsKVwcQZcagqTJ9cfBgI-IWDxhbA2PR7ruWbUCL78IoN1YHAUM2wPq1jID_edsx3VgNW1RRPtGk9n_VdGlFyDqGQBRYAECWrrtfk1dEX0CpZgoUC0Mo0bbw_W42AdeCqtsYX1wWJsnzrnhzSPbowhIJVQQCXyaDsPaOTYsQLzxlrBlTeBcmyfahpFYXaMg64EhORFQXbYGn-iFmwxhDz2dAHwweXGndpvxlFVeenxvYLANDRRZ23LLrHWYrdyIq0rMDUkQQcLen7VH18sCjxHhYCAsARzHL8qGZGvSdqr1G3Ql4UB5hzqT2YKJ6jcV-kzkcRF4DYYG24ITAF7OB3pu3WA4ESzTK8q9rRmUkPY4iKlsHCUAww_ugdhMOxMwjMWYpTkU-ZYP_vHJJna8LziNXJVtWJ3aSrOp9Ddt7isGLqi0TA0E11vCrYe2B8dpMHAoYf1wUUJyyzyNb54b-g3sZSQQDQyHB8Lxm3xvAerHwhSVbVjdrhKzPI1vnhv6DexlJBANCIcHwvGbfG8B6sfCFJVtWN2uErNFt11OOcZZozUkFcFY2wfK3fzZSQv5Gdv0vEwNBbZ6lypnTtDNJOICTSQQDVjey56sx1Z0iENqzKk4aEwBvhov9jDShr3Xz8UxVDwFfJpCt9A5sCkTKXm8FAlF1EnCS4KNv5h9wDa0I2Rt9VAomyeCqumtCsGCdb4leBgFDV6OXtA5OD9Sme8bqVQICQjbD9qp6YJrlnVzU1Bl_VVE-wvat8f8n2pEWEBMFQl0WJsngf9nk-R0l1qZ5496q3eN1SKjkeiLcNzPBw4q5oZagVCcVI6UEujWdo-WJir6Vjk4lIwQX61tvM0-K7tOA8eJmcrs7FX0xD3xks1YHAUM03-D1MZHSPl9oGO9OXkUHdID4tswmlWfVwlRVFllfXWecr7Y7zd4tcwt8uwNEWBRtne_wOE1cLK2srRJUBglcZ5GkrhQfaLWfuwvLWFAEFj3L9fsf-rLFZ9pRH1pTUBYqmbL-BqTZeyQki3QZWxNJM8fxr_AFjKXyyY0qCXhQHmHR-LvS-R_JIpMmpB8UHVFtgIb8klOEAHForigjUFdRPsPuuzWJO-3r0ycKQBRFGmmW4KPi7faQgWrpUV8ECUMw3-DpMLoK3NGvTqcNWkQWTZfgo5mT5j_AQ7acXxoTAWGXq-sdsh6mV0a1sRhGQkkr3K-3nLS9vp59bJZDRF4GcJawtsAVE85aLqigPEReF3GQtt1bj3PAMDwefRl_VU41x_avPAAskKxRHeQeVVQ9ZZ6npNL5H8kikyakHxBBAWuDp-sZViAuo_mIDAgLBUsxy_Oq_hmlK80hA2wICwZCPMD2rWPSVZcX8rs7BVp0C3C-o-nfPHXL5gOqBhRCeB5jp7D4VR6FTw0UcShJBXBWNsHzvCThnQokPcvTCU5FOmmUlvbnTp65O29HoF93FEE2w-erFLMxdneGfJ4UQngeY7et7rYB4gRejkOgX3cUQTbC56sUszF2d4Z8nhRCeB5jt63u819cef613npeBBRARdbwq_HTdVCu0tlESQRyVjbBq_Q4bVTX4mK6WhxTFEE21vHYilV38-Rjcq5bchNfJoCp7Js22M5AhLvZWAIBSjTf4PrPXuybmiRQtg9fXxRAkrb4C7DtnJjBputAFF0Sd4eL_Sd0vd3HtWwtVAQDRjbD8qnblDT0OjooaF8BAUE9x_Goy9teGPwfs04RGhMAcJK27BUTsooxQVQxbDYxcwTzwplYUXlHc_MEMQ==","status": 200}')
        # path = pyobj2nsobj(emu, "/api/v1/app/index/ice/flow/product/detailV5")

        # decrypt_result = objc.msg_send("DuSanwaSDK", "duSecDouDecodeWithHeader:origionData:path:", headers, data, path)
        # decrypt_result_str = emu.read_string(objc.msg_send(decrypt_result, "bytes"))

        # logger.info("Decrypt result: %s", decrypt_result_str)


if __name__ == "__main__":
    main()
