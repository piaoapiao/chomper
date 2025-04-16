import json
import idc
import idautils

# 从 JSON 文件中加载结果字典
def load_results_from_json(file_path):
    try:
        with open(file_path, "r") as f:
            results = json.load(f)
        print(f"Successfully loaded results from {file_path}")
        return results
    except Exception as e:
        print(f"Failed to load results from {file_path}: {str(e)}")
        return {}

# JSON 文件路径
json_file = "decrypt_results.json"

# 从 JSON 文件中加载结果字典
results = load_results_from_json(json_file)

# 遍历 JSON 中的偏移量和解密结果
for offset, decrypt_result_str in results.items():
    # 将 offset 转换为整数
    offset = int(offset)

    # 计算实际地址（加上基地址 0x100000000）
    actual_address = offset + 0x100000000

    # 获取当前符号名
    current_name = idc.get_name(actual_address)
    if not current_name:
        print(f"No symbol found at offset 0x{offset:X}")
        continue
    else:
        print(f"{current_name}: 0x{offset:X}")
        new_name = decrypt_result_str + "_"  +  current_name 
        print(new_name)
        new_name = new_name.replace("/", "_").replace("\\", "_").replace("<", "_").replace(">", "_")
        new_name = new_name.replace("'", "_").replace('"', "_")
        new_name = new_name.replace("#", "_sharp_").replace("|", "_or_")
        new_name = "_" + new_name

        # 重命名符号
        idc.set_name(actual_address, new_name)
