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

def trace_inst_callback(uc, address, size, user_data):
    emu = user_data["emu"]

    inst = next(emu.cs.disasm_lite(uc.mem_read(address, size), 0))
    emu.logger.info(
        f"Trace at {emu.debug_symbol(address)}: {inst[-2]} {inst[-1]}"
    )

    #Display all register status
    regs = []
    for i in range(31):
        regs.append(f"x{i}: {hex(emu.uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X{i}')))}")
    emu.logger.info(", ".join(regs))

def hook_CC_MD5(uc, address, size, user_data):
    global md5X0
    emu = user_data["emu"]
    emu.logger.info("CC_MD5 called")

    emu.log_backtrace();
    arg0 = emu.get_arg(0)
    md5X0 = emu.get_arg(2)
    print(md5X0)
    originInput_Str = emu.read_string(arg0)
    logger.info("hook_CC_MD5_origin input  arg: %s", originInput_Str)



def get_CC_MD5_Result(uc, address, size, user_data):
    emu = user_data["emu"]
    emu.logger.info("get_CC_MD5_Result")
    emu.log_backtrace();
    retValue = emu.get_arg(0)
    print(f"x0 : {retValue}")
    md5Bytes = emu.read_bytes(retValue,16)
    print(md5Bytes)
    print(f"md5Str: {md5Bytes}")
    print(list(md5Bytes)) 

#+[ViewController md5FromString:]:
# def hook_md5FromString(uc, address, size, user_data):
#     emu = user_data["emu"]
#     emu.logger.info("+[ViewController md5FromString:]: called")

# def hook_ui_device_identifier_for_vendor(uc, address, size, user_data):
#     emu = user_data["emu"]
#     objc = ObjC(emu)
#     return objc.msg_send("NSUUID", "UUID")


# can't call origin md5FromString
def interceptor_md5FromString(uc, address, size, user_data):
    emu = user_data["emu"]
    emu.logger.info("interceptor_md5FromString called")
    arg0 = emu.get_arg(0)
    objc = ObjC(emu)
    originInput_Str = emu.read_string(objc.msg_send(arg0, "UTF8String"))
    logger.info("origin input  arg: %s", originInput_Str)
    emu.set_retval(pyobj2nsobj(emu,"123456789"))

    #emu.del_hook(interceptor_md5FromString)
    #result = emu.call_symbol("_md5FromString",pyobj2nsobj(emu,"123456789"))
    #result_Str = emu.read_string(objc.msg_send(result, "UTF8String"))
    #logger.info("_md5FromString_result: %s", result_Str)
    #emu.set_retval(pyobj2nsobj(emu,"123456789"))


    
def hook_md5FromString(uc, address, size, user_data):
    emu = user_data["emu"]
    emu.logger.info("hook_md5FromString called")
    arg0 = emu.get_arg(0)
    objc = ObjC(emu)
    originInput_Str = emu.read_string(objc.msg_send(arg0, "UTF8String"))
    logger.info("origin input  arg: %s", originInput_Str)    

def modify_md5FromString_arg(uc, address, size, user_data):
    emu = user_data["emu"]
    emu.logger.info("modify_md5FromString_arg called")
    emu.set_arg(0, pyobj2nsobj(emu,"123456789"))
    #emu.set_retval(pyobj2nsobj(emu,"123456789"))


def hook_ui_device_current_device(uc, address, size, user_data):
    emu = user_data["emu"]
    emu.logger.info("+[UIDevice currentDevice] called")

def hook_ui_device_identifier_for_vendor(uc, address, size, user_data):
    emu = user_data["emu"]
    objc = ObjC(emu)
    return objc.msg_send("NSUUID", "UUID")

def hook_UIViewController_alloc(uc, address, size, user_data):
    print("hook_UIViewController_alloc")
    pass

def main():
    binary_path = "examples/binaries/ios/com.ttt.ChomperTest/build1/ChomperTest"

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
        #trace_inst_callback=trace_inst_callback
    )
    objc = ObjC(emu)

    emu.add_hook("_CC_MD5", hook_CC_MD5)

    # stat = emu.find_symbol("_stat")
    stat = emu.find_symbol("+[UIDevice currentDevice]")
    print("find_currentDevice")
    print(stat.address)

    # Hook Objetive-C function by symbol name
    emu.add_hook("+[UIDevice currentDevice]", hook_ui_device_current_device)

    # Hook and intercept
    emu.add_interceptor("-[UIDevice identifierForVendor]", hook_ui_device_identifier_for_vendor)




    # error
    #emu.add_hook("+[ViewController md5FromString:]", hook_md5FromString)

    #image = emu.load_module(os.path.join(base_path, "..", binary_path))
    image = emu.load_module(os.path.join(base_path, "..", binary_path),
        exec_init_array = False,
        exec_objc_init =True,
        trace_inst = True,
        trace_symbol_calls = True,
        )
    #emu.add_hook(image.base + 0x000047d8, hook_md5FromString)

    # skip alloc
    emu.add_interceptor(image.base + 0xc770, hook_UIViewController_alloc)
    #emu.add_hook(image.base + 0xc770, hook_UIViewController_alloc)

    #emu.add_hook( image.base + 0x484c , get_CC_MD5_Result)

    # emu.add_hook("_md5FromString", hook_md5FromString)

    #emu.add_interceptor("_md5FromString", interceptor_md5FromString)

    #emu.add_interceptor(image.base + 0x4760 , modify_md5FromString_arg)
    #emu.add_hook(image.base + 0x4764 , modify_md5FromString_arg)
    #emu.add_hook("_md5FromString" , modify_md5FromString_arg)
    

    with objc.autorelease_pool():

        # ViewControllerClass = objc.msg_send("ViewController", "alloc")
        # viewCtrl =  objc.msg_send(ViewControllerClass, "init")

        inputStr = pyobj2nsobj(emu, "abcdef")
        key = pyobj2nsobj(emu, "secret")

        hashStr = objc.msg_send("ViewController", "xorString:withKey:", inputStr, key);

        #hashStr_str = emu.read_string(objc.msg_send(hashStr, "UTF8String"))

        #logger.info("hash result: %s", hashStr_str)

        print("end_simulator")



if __name__ == "__main__":
    main()
