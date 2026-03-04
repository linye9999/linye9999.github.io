import binascii
import os

def hex_file_to_exe(hex_file_path="hex.txt", output_exe_path="output.exe",
                    target_bytes=b'D3"\x11', replace_bytes=b'3\x00\x00\x00'):
    """
    从hex.txt文件读取十六进制文本，转换为EXE文件，并执行指定的二进制替换
    """
    try:
        # 步骤1：从文件读取hex文本
        with open(hex_file_path, "r", encoding="utf-8") as f:
            hex_text = f.read()
        print(f"✅ 成功读取hex文件：{hex_file_path}")

        # 步骤2：清理hex文本（去除换行、空格等无关字符）
        clean_hex = hex_text.replace(" ", "").replace("\n", "").replace("\r", "")
        print(f"✅ 清理后hex长度：{len(clean_hex)} 字符")

        # 步骤3：将十六进制文本解码为二进制数据
        binary_data = binascii.unhexlify(clean_hex)
        print(f"✅ 成功解码为二进制数据，长度：{len(binary_data)} 字节")

        # 步骤4：执行二进制数据替换
        modified_data = binary_data.replace(target_bytes, replace_bytes)
        print(f"✅ 完成二进制替换：{target_bytes} → {replace_bytes}")

        # 步骤5：将处理后的二进制数据写入EXE文件
        with open(output_exe_path, 'wb') as f:
            f.write(modified_data)

        # 验证文件生成结果
        if os.path.exists(output_exe_path):
            file_size = os.path.getsize(output_exe_path)
            print(f"🎉 EXE文件生成成功！")
            print(f"📁 文件路径：{os.path.abspath(output_exe_path)}")
            print(f"📏 文件大小：{file_size} 字节")
        else:
            print("❌ 错误：EXE文件生成失败")

    except FileNotFoundError:
        print(f"❌ 错误：未找到hex文件 {hex_file_path}，请确保文件在脚本同目录下")
    except binascii.Error as e:
        print(f"❌ HEX解码错误：{e}")
        print("请检查hex.txt内容是否为有效的十六进制格式（仅包含0-9、a-f、A-F）")
    except Exception as e:
        print(f"❌ 程序执行错误：{e}")

if __name__ == "__main__":
    # 直接运行即可，默认读取当前目录下的hex.txt，生成output.exe
    hex_file_to_exe()