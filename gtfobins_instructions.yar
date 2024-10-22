rule isElf
{
        strings:
                $elf_header_bytes = {7f 45 4c 46}
        condition:
                $elf_header_bytes
}
