/*
 * Copyright 2016, The EFIDroid Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include <elf.h>

#include <lib/boot.h>
#include <lib/boot/internal/boot_internal.h>

static int ldrmodule_load(bootimg_context_t *context, boot_uintn_t type, boot_uint8_t recursive)
{
    int rc;
    int ret = -1;
    boot_uintn_t i;
    Elf64_Ehdr *hdr = NULL;
    Elf64_Phdr *phdr = NULL;
    Elf64_Shdr *shdr = NULL;
    char* cmdline = NULL;

    // allocate elf header
    hdr = libboot_internal_io_alloc(context->io, sizeof(*hdr));
    if (!hdr) goto out;

    // read elf header
    rc = libboot_internal_io_read(context->io, hdr, 0, sizeof(*hdr), (void **)&hdr);
    if (rc<0) goto out;

    int is_32bit_elf = (hdr->e_ident[EI_CLASS] != ELFCLASS64);
    if(is_32bit_elf) {
        Elf32_Ehdr hdr32;
        libboot_platform_memmove(&hdr32, hdr, sizeof(hdr32));
        hdr->e_type = hdr32.e_type;
        hdr->e_machine = hdr32.e_machine;
        hdr->e_version = hdr32.e_version;
        hdr->e_entry = hdr32.e_entry;
        hdr->e_phoff = hdr32.e_phoff;
        hdr->e_shoff = hdr32.e_shoff;
        hdr->e_flags = hdr32.e_flags;
        hdr->e_ehsize = hdr32.e_ehsize;
        hdr->e_phentsize = hdr32.e_phentsize;
        hdr->e_phnum = hdr32.e_phnum;
        hdr->e_shentsize = hdr32.e_shentsize;
        hdr->e_shnum = hdr32.e_shnum;
        hdr->e_shstrndx = hdr32.e_shstrndx;
    }

    // allocate program header
    phdr = libboot_internal_io_alloc(context->io, hdr->e_phnum * hdr->e_phentsize);
    if (!phdr) goto out;

    // read program headers
    rc = libboot_internal_io_read(context->io, phdr, hdr->e_phoff, hdr->e_phnum * hdr->e_phentsize, (void **)&phdr);
    if (rc<0) goto out;

    // load all program files
    for(i=0; i<hdr->e_phnum; i++) {
        Elf64_Phdr phent;
        void* phent_ptr = (void*)(((boot_uintn_t)phdr)+(i*hdr->e_phentsize));
        if(is_32bit_elf) {
            Elf32_Phdr phent32;
            libboot_platform_memmove(&phent32, phent_ptr, sizeof(phent32));
            phent.p_type = phent32.p_type;
            phent.p_flags = phent32.p_flags;
            phent.p_offset = phent32.p_offset;
            phent.p_vaddr = phent32.p_vaddr;
            phent.p_paddr = phent32.p_paddr;
            phent.p_filesz = phent32.p_filesz;
            phent.p_memsz = phent32.p_memsz;
            phent.p_align = phent32.p_align;
        }
        else {
            libboot_platform_memmove(&phent, phent_ptr, sizeof(Elf64_Phdr));
        }

        // we only care about loadable entries
        if(phent.p_type!=PT_LOAD)
            continue;

        // allocate
        void* data = libboot_internal_io_alloc(context->io, phent.p_filesz);
        if (!phdr) goto out;

        // read
        rc = libboot_internal_io_read(context->io, data, phent.p_offset, phent.p_filesz, (void **)&data);
        if (rc<0) goto out;

        if(i==0) {
            if(!(type&LIBBOOT_LOAD_TYPE_KERNEL)) {
                libboot_free(data);
                continue;
            }
            libboot_free(context->kernel_data);
            context->kernel_data = data;
            context->kernel_size = phent.p_filesz;
            context->kernel_addr = phent.p_paddr;
        }
        else if(i==1) {
            if(!(type&LIBBOOT_LOAD_TYPE_RAMDISK)) {
                libboot_free(data);
                continue;
            }
            libboot_free(context->ramdisk_data);
            context->ramdisk_data = data;
            context->ramdisk_size = phent.p_filesz;
            context->ramdisk_addr = phent.p_paddr;
        }
        else if(i==2) {
            if(!(type&LIBBOOT_LOAD_TYPE_TAGS)) {
                libboot_free(data);
                continue;
            }
            libboot_free(context->tags_data);
            context->tags_data = data;
            context->tags_size = phent.p_filesz;
            context->tags_addr = phent.p_paddr;
        }
        else {
            libboot_free(data);
            goto out;
        }
    }

    // allocate sections headers
    shdr = libboot_internal_io_alloc(context->io, hdr->e_shnum * hdr->e_shentsize);
    if (!shdr) goto out;

    // read sections headers
    rc = libboot_internal_io_read(context->io, shdr, hdr->e_shoff, hdr->e_shnum * hdr->e_shentsize, (void **)&shdr);
    if (rc<0) goto out;

    boot_uint8_t found_cmdline = 0;
    for(i=0; i<hdr->e_shnum; i++) {
        Elf64_Shdr shent;
        void* shent_ptr = (void*)(((boot_uintn_t)shdr)+(i*hdr->e_shentsize));
        if(is_32bit_elf) {
            Elf32_Shdr shent32;
            libboot_platform_memmove(&shent32, shent_ptr, sizeof(shent32));
            shent.sh_name = shent32.sh_name;
            shent.sh_type = shent32.sh_type;
            shent.sh_flags = shent32.sh_flags;
            shent.sh_addr = shent32.sh_addr;
            shent.sh_offset = shent32.sh_offset;
            shent.sh_size = shent32.sh_size;
            shent.sh_link = shent32.sh_link;
            shent.sh_info = shent32.sh_info;
            shent.sh_addralign = shent32.sh_addralign;
            shent.sh_entsize = shent32.sh_entsize;
        }
        else {
            libboot_platform_memmove(&shent, shent_ptr, sizeof(Elf64_Shdr));
        }

        // allocate cmdline
        cmdline = libboot_internal_io_alloc(context->io, shent.sh_size);
        if (!cmdline) goto out;

        // cmdline cmdline
        rc = libboot_internal_io_read(context->io, cmdline, shent.sh_offset, shent.sh_size, (void **)&cmdline);
        if (rc<0) goto out;

        // there are two uint32_t values in front of the cmdline:
        // 0x1 and the tags_offset
        cmdline += 8;

        // add cmdline
        libboot_cmdline_addall(&context->cmdline, cmdline, 1);

        // free cmdline
        libboot_free(cmdline);
        cmdline = NULL;
        found_cmdline = 1;

        // ignore other sections for now
        break;
    }

    if(!found_cmdline) {
        libboot_format_error(LIBBOOT_ERROR_GROUP_ELF, LIBBOOT_ERROR_ELF_NO_CMDLINE);
        goto out;
    }

    context->kernel_is_linux = 1;
    context->type = BOOTIMG_TYPE_RAW;

    ret = 0;

out:
    libboot_free(hdr);
    libboot_free(phdr);
    libboot_free(shdr);

    return ret;
}

static ldrmodule_t ldrmodule = {
    .type = BOOTIMG_TYPE_ELF,
    .magic_custom_test = NULL,
    .magic_off = 0,
    .magic_sz = 4,
    .magic_val = ELFMAG,

    .load = ldrmodule_load,
};

int libboot_internal_ldrmodule_elf_init(void)
{
    libboot_internal_ldrmodule_register(&ldrmodule);
    return 0;
}
