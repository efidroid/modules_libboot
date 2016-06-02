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

#include <lib/boot.h>
#include <lib/boot/internal/boot_internal.h>

#define LIBOOT_INTERNAL_ERROR_STACK_SIZE 64

static libboot_list_node_t ldrmodules;
static libboot_list_node_t tagmodules;
static libboot_list_node_t error_formats;
static char* error_stack[LIBOOT_INTERNAL_ERROR_STACK_SIZE];
static boot_uintn_t error_stack_count = 0;

boot_uintn_t libboot_internal_strlcpy(char *dst, const char *src, boot_uintn_t size) {
	boot_uintn_t srclen;

	size--;
	srclen = libboot_platform_strlen(src);

	if (srclen > size)
		srclen = size;

	libboot_platform_memmove(dst, src, srclen);
	dst[srclen] = '\0';

	return srclen;
}

int libboot_internal_load_rawdata_to_kernel(bootimg_context_t* context) {
    int rc;

    // calculate size
    boot_uintn_t size = context->io->numblocks*context->io->blksz;

    // allocate data
    void* data = libboot_internal_io_bigalloc(context, size);
    if(!data) return -1;

    // read data
    rc = libboot_internal_io_read(context->io, data, 0, size);
    if(rc<0) {
        libboot_platform_free(data);
        return -1;
    }
    rc = 0;

    context->kernel_data = data;

    return rc;
}

void libboot_internal_ldrmodule_register(ldrmodule_t* mod) {
    libboot_list_add_tail(&ldrmodules, &mod->node);
}

void libboot_internal_tagmodule_register(tagmodule_t* mod) {
    libboot_list_add_tail(&tagmodules, &mod->node);
}

void* libboot_internal_io_alloc(boot_io_t* io, boot_uintn_t sz) {
    return libboot_platform_alloc(IO_ALIGN(io, sz));
}

void* libboot_internal_io_bigalloc(bootimg_context_t* context, boot_uintn_t sz) {
    return context->bigalloc(IO_ALIGN(context->io, sz));
}

boot_intn_t libboot_internal_io_read(boot_io_t* io, void* buf, boot_uintn_t off, boot_uintn_t sz) {
    return io->read(io, buf, IO_ALIGN(io, off)/io->blksz, IO_ALIGN(io, sz)/io->blksz);
}

void libboot_internal_free_io(boot_io_t* io) {
    if(!io) return;

    if(io->pdata_is_allocated)
        libboot_platform_free(io->pdata);

    libboot_platform_free(io);
}

int libboot_identify(boot_io_t* io, bootimg_context_t* context) {
    bootimg_type_t type = BOOTIMG_TYPE_RAW;
    int rc = 0;

    ldrmodule_t *mod;
    libboot_list_for_every_entry(&ldrmodules, mod, ldrmodule_t, node) {
        // custom test
        if(mod->magic_custom_test) {
            if(mod->magic_custom_test(io)==0)
                type = mod->type;
        }

        // automatic test
        else {
            boot_uint32_t* magic = libboot_internal_io_alloc(io, mod->magic_sz);
            if(!magic) return -1;

            rc = libboot_internal_io_read(io, magic, mod->magic_off, mod->magic_sz);
            if(rc<0) goto do_free;
            rc = 0;

            if(!libboot_platform_memcmp(magic, mod->magic_val, mod->magic_sz))
                type = mod->type;

        do_free:
            libboot_platform_free(magic);
        }

        // we have a match
        if(type!=BOOTIMG_TYPE_RAW) {
            libboot_internal_free_io(context->io);
            context->type = type;
            context->io = io;
            rc = 0;
            break;
        }
    }

    // no match
    if(type==BOOTIMG_TYPE_RAW) {
        libboot_internal_free_io(context->io);
        context->type = type;
        context->io = io;
        rc = 0;
    }

    return rc;
}

static boot_intn_t internal_io_fn_mem_read(boot_io_t* io, void* buf, boot_uintn_t blkoff, boot_uintn_t count) {
    boot_uintn_t src = ((boot_uintn_t)io->pdata)+blkoff;

    if(blkoff+count>io->numblocks)
        return -1;

    libboot_platform_memmove(buf, (void*)src, count);

    return count;
}

int libboot_identify_memory(void* mem, boot_uintn_t sz, bootimg_context_t* context) {
    boot_io_t* io = libboot_platform_alloc(sizeof(boot_io_t));
    if(!io) return -1;
    io->read = internal_io_fn_mem_read;
    io->blksz = 1;
    io->numblocks = sz;
    io->pdata = mem;
    io->pdata_is_allocated = 0;

    int rc = libboot_identify(io, context);
    if(rc) {
        libboot_platform_free(io);
    }

    return rc;
}

void libboot_internal_register_error(libboot_error_group_t group, libboot_error_type_t type, const char* fmt) {
    libboot_error_format_t* format = libboot_platform_alloc(sizeof(libboot_error_format_t));
    if(!format) return;

    format->group = group;
    format->type = type;
    format->fmt = fmt;

    libboot_list_add_tail(&error_formats, &format->node);
}

libboot_error_format_t* libboot_internal_get_error_format(libboot_error_group_t group, libboot_error_type_t type) {
    libboot_error_format_t *format;
    libboot_list_for_every_entry(&error_formats, format, libboot_error_format_t, node) {
        if(format->group==group && format->type==type) {
            return format;
        }
    }

    return NULL;
}

char* libboot_internal_error_stack_alloc(void) {
    if(error_stack_count>=LIBOOT_INTERNAL_ERROR_STACK_SIZE)
        return NULL;

    char* buf = libboot_platform_alloc(4096);
    if(!buf) return NULL;

    buf[0] = 0;
    error_stack[error_stack_count++] = buf;
    return buf;
}

char** libboot_error_stack_get(void) {
    return error_stack;
}

boot_uintn_t libboot_error_stack_count(void) {
    return error_stack_count;
}

void libboot_error_stack_reset(void) {
    boot_uintn_t i;
    for(i=0; i<error_stack_count; i++) {
        libboot_platform_free(error_stack[i]);
    }

    error_stack_count = 0;
}

int libboot_init(void) {
    // loader modules
    libboot_list_initialize(&ldrmodules);
    libboot_internal_ldrmodule_android_init();
    libboot_internal_ldrmodule_efi_init();
    libboot_internal_ldrmodule_elf_init();
    libboot_internal_ldrmodule_zimage_init();
    libboot_internal_ldrmodule_qcmbn_init();
    libboot_internal_ldrmodule_gzip_init();

    // tag modules
    libboot_list_initialize(&tagmodules);
    libboot_internal_tagmodule_qcdt_init();
    libboot_internal_tagmodule_fdt_init();
    libboot_internal_tagmodule_atags_init();

    // error messages
    libboot_list_initialize(&error_formats);
    libboot_internal_register_error(LIBBOOT_ERROR_GROUP_ANDROID, LIBBOOT_ERROR_ANDROID_SECOND_UNSUPPORTED, "secondary loaders are not supported. size: "LIBBOOT_FMT_UINT32);
    libboot_internal_register_error(LIBBOOT_ERROR_GROUP_ANDROID, LIBBOOT_ERROR_ANDROID_ZERO_KERNEL, "kernel size is 0");
    libboot_internal_register_error(LIBBOOT_ERROR_GROUP_ANDROID, LIBBOOT_ERROR_ANDROID_READ_KERNEL, "can't read kernel: "LIBBOOT_FMT_INT);
    libboot_internal_register_error(LIBBOOT_ERROR_GROUP_ANDROID, LIBBOOT_ERROR_ANDROID_READ_RAMDISK, "can't read ramdisk: "LIBBOOT_FMT_INT);
    libboot_internal_register_error(LIBBOOT_ERROR_GROUP_ANDROID, LIBBOOT_ERROR_ANDROID_READ_TAGS, "can't read tags: "LIBBOOT_FMT_INT);
    libboot_internal_register_error(LIBBOOT_ERROR_GROUP_ANDROID, LIBBOOT_ERROR_ANDROID_ALLOC_CMDLINE, "can't allocate cmdline");
    libboot_internal_register_error(LIBBOOT_ERROR_GROUP_COMMON, LIBBOOT_ERROR_COMMON_OUT_OF_MEMORY, "can't allocate memory");

    return 0;
}

void libboot_init_context(bootimg_context_t* context) {
    if(!context) return;

    libboot_platform_memset(context, 0, sizeof(*context));
    libboot_cmdline_init(&context->cmdline);
}

void libboot_free_context(bootimg_context_t* context) {
    if(!context) return;

    libboot_platform_free(context->io);
    context->bigfree(context->kernel_data);
    context->bigfree(context->ramdisk_data);
    context->bigfree(context->tags_data);
    libboot_cmdline_free(&context->cmdline);
}

int libboot_load(bootimg_context_t* context) {
    int rc = 0;
    int matched;

    while(context->type!=BOOTIMG_TYPE_RAW) {
        matched = 0;

        ldrmodule_t *mod;
        libboot_list_for_every_entry(&ldrmodules, mod, ldrmodule_t, node) {
            if(mod->load && mod->type==context->type) {
                // load
                rc = mod->load(context);

                // abort on error
                if(rc) return rc;

                // start over
                matched = 1;
                break;
            }
        }

        // abort
        if(!matched) break;
    }

    // this was a raw image in first place
    if(rc==0 && context->type==BOOTIMG_TYPE_RAW && !context->kernel_data) {
        // calculate size
        boot_uintn_t size = context->io->numblocks*context->io->blksz;

        // allocate data
        void* data = libboot_internal_io_bigalloc(context, size);
        if(!data) return -1;

        // read data
        rc = libboot_internal_io_read(context->io, data, 0, size);
        if(rc<0) {
            libboot_platform_free(data);
            return -1;
        }
        rc = 0;

        context->kernel_data = data;
    }

    // no kernel was loaded
    if(!context->kernel_data)
        rc = -1;

    return rc;
}

static int libboot_identify_tags(bootimg_context_t* context) {
    libboot_tags_type_t type = LIBBOOT_TAGS_TYPE_UNKNOWN;

    if(context->tags_data!=NULL) {
        tagmodule_t *mod;
        libboot_list_for_every_entry(&tagmodules, mod, tagmodule_t, node) {
            // custom test
            if(mod->magic_custom_test) {
                if(mod->magic_custom_test(context)==0)
                    type = mod->type;
            }

            // automatic test
            else {
                boot_uint8_t* data = context->tags_data;
                boot_uint8_t* magicptr = data+mod->magic_off;

                if(!libboot_platform_memcmp(magicptr, mod->magic_val, mod->magic_sz))
                    type = mod->type;
            }

            // we have a match
            if(type!=LIBBOOT_TAGS_TYPE_UNKNOWN) {
                break;
            }
        }
    }

    // set type
    context->tags_type = type;

    return 0;
}

static int libboot_generate_tags(bootimg_context_t* context) {
    int rc;
    int matched;

    // identify existing tags
    rc = libboot_identify_tags(context);
    if(rc) return rc;

    while(!context->tags_ready) {
        matched = 0;

        // define type to search for
        libboot_tags_type_t type = context->tags_type;
        if(context->tags_data==NULL) {
            if(context->default_qcdt)
                type = LIBBOOT_TAGS_TYPE_QCDT;
            else if(context->default_fdt)
                type = LIBBOOT_TAGS_TYPE_FDT;
            else
                type = LIBBOOT_TAGS_TYPE_ATAGS;
        }

        // convert tags
        tagmodule_t *mod;
        libboot_list_for_every_entry(&tagmodules, mod, tagmodule_t, node) {
            if(mod->patch && mod->type==type) {
                // convert
                rc = mod->patch(context);

                // abort on error
                if(rc) return rc;

                // start over
                matched = 1;
                break;
            }
        }

        // abort
        if(!matched) break;
    }

    // no tags were loaded
    if(!matched || !context->tags_data)
        rc = -1;

    return rc;
}

int libboot_prepare(bootimg_context_t* context) {
    int rc;

    if(!context->bootalloc)
        return -1;

    context->kernel_arguments[0] = 0;
    context->kernel_arguments[1] = 0;
    context->kernel_arguments[2] = 0;

    if(context->kernel_is_linux) {
        // generate tags
        rc = libboot_generate_tags(context);
        if(rc) return rc;
    }

    // allocate loading addresses
    if(context->kernel_addr) {
        context->kernel_addr = (boot_uintn_t)context->bootalloc(context->kernel_addr, context->kernel_size);
        if(!context->kernel_addr) return -1;
    }
    if(context->ramdisk_addr) {
        context->ramdisk_addr = (boot_uintn_t)context->bootalloc(context->ramdisk_addr, context->ramdisk_addr);
        if(!context->ramdisk_addr) return -1;
    }
    if(context->tags_addr) {
        context->tags_addr = (boot_uintn_t)context->bootalloc(context->tags_addr, context->tags_size);
        if(!context->tags_addr) return -1;
    }

    // load images to final addresses
    libboot_platform_memmove((void*)context->kernel_addr, context->kernel_data, context->kernel_size);
    if(context->ramdisk_size)
        libboot_platform_memmove((void*)context->ramdisk_addr, context->ramdisk_data, context->ramdisk_size);
    if(context->tags_size)
        libboot_platform_memmove((void*)context->tags_addr, context->tags_data, context->tags_size);

    if(context->kernel_is_linux) {
        int machtype = 0;
        if(context->getmachtype)
            machtype = context->getmachtype(context);

        // set arguments
        context->kernel_arguments[0] = 0;
        context->kernel_arguments[1] = machtype;
        context->kernel_arguments[2] = context->tags_addr;
    }

    return 0;
}
