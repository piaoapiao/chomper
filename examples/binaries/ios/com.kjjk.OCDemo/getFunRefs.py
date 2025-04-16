import idautils
import idc
import json

# # 目标函数的名称
# target_function_name = "_kXQbWDEnWf"

# # 获取目标函数的地址
# target_function_ea = idc.get_name_ea_simple(target_function_name)

# if target_function_ea == idc.BADADDR:
#     print(f"Error: Function '{target_function_name}' not found!")
# else:
#     print(f"Found function '{target_function_name}' at address: 0x{target_function_ea:X}")

#     # 遍历所有调用目标函数的指令
#     for caller_ea in idautils.CodeRefsTo(target_function_ea, 0):
#         # 获取调用指令的地址
#         #print(f"Caller at address: 0x{caller_ea:X}")

#         # 获取调用指令所属函数的起始地址
#         func_ea = idc.get_func_attr(caller_ea, idc.FUNCATTR_START)
#         offset = func_ea - 0x0000000100000000
#         print(f"  Belongs to function at address: 0x{func_ea:X}")

#         # 如果需要打印调用指令的汇编代码
#         #disasm = idc.generate_disasm_line(caller_ea, 0)
#         #print(f"  Instruction: {disasm}")


def get_caller_offsets(target_function_name):
    """
    获取调用目标函数的所有调用者函数的偏移量。

    :param target_function_name: 目标函数的符号名称（如 "_kXQbWDEnWf"）。
    :return: 包含所有调用者函数偏移量的列表。
    """
    # 获取目标函数的地址
    target_function_ea = idc.get_name_ea_simple(target_function_name)

    # 如果目标函数未找到，返回空列表
    if target_function_ea == idc.BADADDR:
        print(f"Error: Function '{target_function_name}' not found!")
        return []

    print(f"Found function '{target_function_name}' at address: 0x{target_function_ea:X}")

    # 用于保存调用者函数偏移量的数组
    caller_offsets = []

    # 遍历所有调用目标函数的指令
    for caller_ea in idautils.CodeRefsTo(target_function_ea, 0):
        # 获取调用指令所属函数的起始地址
        func_ea = idc.get_func_attr(caller_ea, idc.FUNCATTR_START)

        # 计算偏移量（假设基地址为 0x0000000100000000）
        offset = func_ea - 0x0000000100000000

        # 将偏移量添加到数组中
        caller_offsets.append(offset)

        # 打印调试信息
        print(f"  Belongs to function at address: 0x{func_ea:X}, offset: 0x{offset:X}")

    # 返回调用者函数偏移量数组
    return caller_offsets

# 示例调用
if __name__ == "__main__":
    # 用于保存所有符号的偏移量
    all_offsets = []

    # 获取第一个符号的偏移量
    target_function1 = "_kXQbWDEnWf"
    offsets1 = get_caller_offsets(target_function1)
    print(f"Caller offsets for {target_function1}: {offsets1}")
    all_offsets.extend(offsets1) # 328

    # 获取第二个符号的偏移量
    target_function2 = "_ZAJMhYxYpe"
    offsets2 = get_caller_offsets(target_function2)
    print(f"Caller offsets for {target_function2}: {offsets2}")
    all_offsets.extend(offsets2) # 312

    # 获取第三个符号的偏移量
    target_function3 = "_HYTMNWzyLg"
    offsets3 = get_caller_offsets(target_function3)
    print(f"Caller offsets for {target_function3}: {offsets3}")
    all_offsets.extend(offsets3) # 271

    # 打印合并后的偏移量列表
    print(f"All caller offsets: {all_offsets}")

    # 将偏移量列表保存为 JSON 文件
    output_file = "caller_offsets.json"
    with open(output_file, "w") as f:
        json.dump(all_offsets, f, indent=4)

    print(f"Results saved to {output_file}")





