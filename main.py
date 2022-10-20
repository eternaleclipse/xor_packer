import pefile

def align(value, alignment):
    return (value + alignment - 1) // alignment * alignment

def generate_unpacker_x64(unpacker_addr, code_addr, code_size, xor_key, jmp_addr):
    unpacker = b''

    # lea rax, [current_address - address_of_code_section]
    lea_size = 7
    unpacker += b'\x48\x8d\x05' + (code_addr - unpacker_addr - lea_size).to_bytes(4, 'little', signed=True)

    # mov rcx, size of the code section
    unpacker += b'\x48\xb9' + code_size.to_bytes(8, byteorder='little', signed=False)

    # xor byte ptr [rax], xor_key
    unpacker += b'\x80\x30' + xor_key.to_bytes(1, byteorder='little', signed=False)

    # inc rax
    unpacker += b'\x48\xff\xc0'

    # loop to xor the rest of the code section, until rcx == 0
    unpacker += b'\xe2\xf8'

    # jmp to original entry point
    jmp_size = 5
    reljmp = jmp_addr - (unpacker_addr + len(unpacker) + jmp_size)
    unpacker += b'\xe9' + reljmp.to_bytes(4, byteorder='little', signed=True)
    return unpacker

def xor_bytes(data, key):
    return bytes([data[i] ^ key for i in range(len(data))])

def create_unpacker_section(pe, vaddr, data_len):
    last_section = pe.sections[-1]

    unpacker_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
    unpacker_section.__unpack__(bytearray(unpacker_section.sizeof()))
    unpacker_section.set_file_offset(last_section.get_file_offset() + last_section.sizeof())
    unpacker_section.Name = b'.new'
    unpacker_section.SizeOfRawData = align(data_len, pe.OPTIONAL_HEADER.FileAlignment)
    unpacker_section.PointerToRawData = len(pe.__data__)
    unpacker_section.Misc = data_len
    unpacker_section.PhysicalAddress = data_len
    unpacker_section.Misc_VirtualSize = data_len
    unpacker_section.VirtualAddress = vaddr
    unpacker_section.Characteristics = \
        pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'] | \
        pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] | \
        pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']

    return unpacker_section

def pack(path, out_path):
    # Load the file
    pe = pefile.PE(path)

    # Find the code section
    for section in pe.sections:
        if section.Name == b'.text\x00\x00\x00':
            break
    else:
        raise Exception('No .text section found')

    code_section: pefile.SectionStructure = section
    print('[+] Found code section: %s' % code_section.Name)

    # XOR the contents of the code section
    xor_key = 0x41
    pe.set_bytes_at_offset(section.PointerToRawData, xor_bytes(code_section.get_data(), xor_key))
    print('[+] XOR done')

    # Set section as writable
    code_section.Characteristics |= pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']

    # Calculate the address of the unpacker section (needed for unpacking)
    last_section = pe.sections[-1]
    unpacker_section_vaddr = last_section.VirtualAddress + align(last_section.Misc_VirtualSize, pe.OPTIONAL_HEADER.SectionAlignment)

    unpacker_section_data = generate_unpacker_x64(
        unpacker_addr=unpacker_section_vaddr,
        code_addr=code_section.VirtualAddress,
        code_size=code_section.Misc_VirtualSize,
        xor_key=xor_key,
        jmp_addr=pe.OPTIONAL_HEADER.AddressOfEntryPoint
    )

    unpacker_len = len(unpacker_section_data)

    # align existing data to file alignment
    pe.__data__ = bytearray(pe.__data__) + \
        b'\x00' * ((pe.OPTIONAL_HEADER.FileAlignment - len(pe.__data__)) % pe.OPTIONAL_HEADER.FileAlignment)

    # Create the unpacker section
    unpacker_section = create_unpacker_section(pe, unpacker_section_vaddr, unpacker_len)

    # Add the unpacker section header to the section table
    pe.sections.append(unpacker_section)
    pe.__structures__.append(unpacker_section)
    print('[+] Added unpacker section header')

    # add section data to pe data
    pe.__data__ += bytearray(unpacker_section_data.ljust(unpacker_section.SizeOfRawData, b'\x00'))
    print('[+] Added unpacker section data')

    # set entry point to new section
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = unpacker_section.VirtualAddress

    # adjust size of image
    pe.OPTIONAL_HEADER.SizeOfImage += \
        align(unpacker_len, pe.OPTIONAL_HEADER.SectionAlignment)

    # increase number of sections
    pe.FILE_HEADER.NumberOfSections += 1

    # write the new file
    pe.write(out_path)
    print(f'[+] Done, wrote to {out_path}')

if __name__ == '__main__':
    pack('putty.exe', 'packed.exe')
