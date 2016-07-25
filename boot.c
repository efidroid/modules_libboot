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
#define DEBUG_ALLOCATIONS 0

static libboot_list_node_t ldrmodules;
static libboot_list_node_t tagmodules;
static libboot_list_node_t error_formats;
static char *error_stack[LIBOOT_INTERNAL_ERROR_STACK_SIZE];
static boot_uintn_t error_stack_count = 0;

static libboot_list_node_t allocations;

typedef struct {
    libboot_list_node_t node;

    boot_uintn_t addr;
    boot_uintn_t size;
    boot_uintn_t refs;
} allocation_t;

boot_uintn_t libboot_internal_strlcpy(char *dst, const char *src, boot_uintn_t size)
{
    boot_uintn_t srclen;

    size--;
    srclen = libboot_platform_strlen(src);

    if (srclen > size)
        srclen = size;

    libboot_platform_memmove(dst, src, srclen);
    dst[srclen] = '\0';

    return srclen;
}

int libboot_internal_load_rawdata_to_kernel(bootimg_context_t *context)
{
    int rc;

    // calculate size
    boot_uintn_t size = context->io->numblocks*context->io->blksz;

    // allocate data
    void *data = libboot_internal_io_alloc(context->io, size);
    if (!data) return -1;

    // read data
    rc = libboot_internal_io_read(context->io, data, 0, size, &data);
    if (rc<0) {
        libboot_free(data);
        return -1;
    }
    rc = 0;

    // replace kernel data
    libboot_free(context->kernel_data);
    context->kernel_data = data;

    return rc;
}

void libboot_internal_ldrmodule_register(ldrmodule_t *mod)
{
    libboot_list_add_tail(&ldrmodules, &mod->node);
}

void libboot_internal_tagmodule_register(tagmodule_t *mod)
{
    libboot_list_add_tail(&tagmodules, &mod->node);
}

void *libboot_alloc(boot_uintn_t size)
{
    void *mem = libboot_platform_alloc(size);
    if (!mem) return NULL;

    allocation_t *alloc = libboot_platform_alloc(sizeof(allocation_t));
    if (!alloc) {
        libboot_free(mem);
        return NULL;
    }

    alloc->addr = (boot_uintn_t)mem;
    alloc->size = size;
    alloc->refs = 1;

    libboot_list_add_tail(&allocations, &alloc->node);

#if DEBUG_ALLOCATIONS
    LOGI("ALLOC=0x%08"LIBBOOT_FMT_ADDR" size=%"LIBBOOT_FMT_UINTN" refs=%"LIBBOOT_FMT_UINTN"\n", alloc->addr, alloc->size, alloc->refs);
#endif

    return mem;
}

void *libboot_refalloc(void *ptr, boot_uintn_t size)
{
    if (!ptr) return NULL;

    boot_uintn_t addr = (boot_uintn_t) ptr;
    allocation_t *alloc;
    libboot_list_for_every_entry(&allocations, alloc, allocation_t, node) {
        if (addr>=alloc->addr && addr<alloc->addr+alloc->size) {
            // the size exceeds the range
            if (addr+size>alloc->addr+alloc->size)
                return NULL;

            alloc->refs++;
#if DEBUG_ALLOCATIONS
            LOGI("REFALLOC=0x%08"LIBBOOT_FMT_ADDR" size=%"LIBBOOT_FMT_UINTN" refs=%"LIBBOOT_FMT_UINTN"\n", alloc->addr, alloc->size, alloc->refs);
#endif
            return ptr;
        }
    }

    return NULL;
}

boot_uintn_t libboot_get_refcount(void *ptr)
{
    if (!ptr) return 0;

    boot_uintn_t addr = (boot_uintn_t) ptr;
    allocation_t *alloc;
    libboot_list_for_every_entry(&allocations, alloc, allocation_t, node) {
        if (addr>=alloc->addr && addr<alloc->addr+alloc->size) {
            return alloc->refs;
        }
    }

    return 0;
}

void libboot_free(void *ptr)
{
    if (!ptr) return;

    boot_uintn_t addr = (boot_uintn_t) ptr;
    allocation_t *alloc;
    libboot_list_for_every_entry(&allocations, alloc, allocation_t, node) {
        if (addr>=alloc->addr && addr<alloc->addr+alloc->size) {
            alloc->refs--;

            if (alloc->refs<=0) {
#if DEBUG_ALLOCATIONS
                LOGI("FREE=0x%08"LIBBOOT_FMT_ADDR" size=%"LIBBOOT_FMT_UINTN" refs=%"LIBBOOT_FMT_UINTN"\n", alloc->addr, alloc->size, alloc->refs);
#endif

                libboot_platform_free((void *)alloc->addr);
                libboot_list_delete(&alloc->node);
                libboot_platform_free(alloc);
            }

            else {
#if DEBUG_ALLOCATIONS
                LOGI("DEREF=0x%08"LIBBOOT_FMT_ADDR" size=%"LIBBOOT_FMT_UINTN" refs=%"LIBBOOT_FMT_UINTN"\n", alloc->addr, alloc->size, alloc->refs);
#endif
            }
            return;
        }
    }
}

void *libboot_internal_io_alloc(boot_io_t *io, boot_uintn_t sz)
{
    boot_uintn_t allocsz = io->blksz + IO_ALIGN(io, sz);
    return libboot_alloc(allocsz);
}

boot_intn_t libboot_internal_io_read(boot_io_t *io, void *buf, boot_uintn_t off, boot_uintn_t sz, void **bufoff)
{
    boot_uintn_t off_aligned = ROUNDDOWN(off, io->blksz);
    boot_uintn_t alignment_off = off - off_aligned;
    boot_intn_t rc = io->read(io, buf, off_aligned/io->blksz, IO_ALIGN(io, alignment_off+sz)/io->blksz);
    if (rc<=0) return rc;

    *bufoff = buf + alignment_off;

    return rc - alignment_off;
}

void libboot_internal_io_destroy(boot_io_t *io)
{
    if (!io) return;

    // only delete the actual data if there's just one ref left
    if (libboot_get_refcount(io)<=1) {
        if (io->pdata_is_allocated)
            libboot_free(io->pdata);
    }

    libboot_free(io);
}

int libboot_identify(boot_io_t *io, bootimg_context_t *context)
{
    bootimg_type_t type = BOOTIMG_TYPE_UNKNOWN;
    int rc = 0;

    ldrmodule_t *mod;
    libboot_list_for_every_entry(&ldrmodules, mod, ldrmodule_t, node) {
        // custom test
        if (mod->magic_custom_test) {
            if (mod->magic_custom_test(io)==0)
                type = mod->type;
        }

        // automatic test
        else {
            boot_uint32_t *magic = libboot_internal_io_alloc(io, mod->magic_sz);
            if (!magic) return -1;
            rc = libboot_internal_io_read(io, magic, mod->magic_off, mod->magic_sz, (void **)&magic);
            if (rc<0) goto do_free;
            rc = 0;

            if (!libboot_platform_memcmp(magic, mod->magic_val, mod->magic_sz))
                type = mod->type;

do_free:
            libboot_free(magic);
        }

        // we have a match
        if (type!=BOOTIMG_TYPE_UNKNOWN) {
            // this is is initial check
            if (!context->rootio) {
                boot_io_t *rootio = libboot_refalloc(io, 0);
                if (!rootio) return -1;
                context->rootio = rootio;
                context->outer_type = type;

                // generate a checksum
                if (mod->checksum)
                    context->checksum = mod->checksum(io);
            }

            // replace current kernel-IO
            libboot_internal_io_destroy(context->io);
            context->io = io;
            context->type = type;

            rc = 0;
            break;
        }
    }

    // no match
    if (type==BOOTIMG_TYPE_UNKNOWN) {
        // this is the first scan and we don't have a match!
        if (!context->rootio) {
            rc = -1;
        }

        // assume raw image
        else {
            libboot_internal_io_destroy(context->io);
            context->io = io;
            context->type = BOOTIMG_TYPE_RAW;
            rc = 0;
        }
    }

    return rc;
}

static boot_intn_t internal_io_fn_mem_read(boot_io_t *io, void *buf, boot_uintn_t blkoff, boot_uintn_t count)
{
    boot_uintn_t src = ((boot_uintn_t)io->pdata)+blkoff;

    if (blkoff+count>io->numblocks)
        return -1;

    libboot_platform_memmove(buf, (void *)src, count);

    return count;
}

int libboot_identify_memory(void *mem, boot_uintn_t sz, bootimg_context_t *context)
{
    boot_io_t *io = libboot_alloc(sizeof(boot_io_t));
    if (!io) return -1;
    io->read = internal_io_fn_mem_read;
    io->blksz = 1;
    io->numblocks = sz;
    io->pdata = mem;
    io->pdata_is_allocated = 0;
    io->is_memio = 1;

    int rc = libboot_identify(io, context);
    if (rc) {
        libboot_internal_io_destroy(io);
    }

    return rc;
}

void libboot_internal_register_error(libboot_error_group_t group, libboot_error_type_t type, const char *fmt)
{
    libboot_error_format_t *format = libboot_alloc(sizeof(libboot_error_format_t));
    if (!format) return;

    format->group = group;
    format->type = type;
    format->fmt = fmt;
    libboot_list_add_tail(&error_formats, &format->node);
}

libboot_error_format_t *libboot_internal_get_error_format(libboot_error_group_t group, libboot_error_type_t type)
{
    libboot_error_format_t *format;
    libboot_list_for_every_entry(&error_formats, format, libboot_error_format_t, node) {
        if (format->group==group && format->type==type) {
            return format;
        }
    }

    return NULL;
}

char *libboot_internal_error_stack_alloc(void)
{
    if (error_stack_count>=LIBOOT_INTERNAL_ERROR_STACK_SIZE)
        return NULL;

    char *buf = libboot_alloc(4096);
    if (!buf) return NULL;

    buf[0] = 0;
    error_stack[error_stack_count++] = buf;
    return buf;
}

char **libboot_error_stack_get(void)
{
    return error_stack;
}

boot_uintn_t libboot_error_stack_count(void)
{
    return error_stack_count;
}

void libboot_error_stack_reset(void)
{
    boot_uintn_t i;
    for (i=0; i<error_stack_count; i++) {
        libboot_free(error_stack[i]);
    }

    error_stack_count = 0;
}

int libboot_init(void)
{
    libboot_list_initialize(&allocations);

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
    libboot_internal_register_error(LIBBOOT_ERROR_GROUP_ANDROID, LIBBOOT_ERROR_ANDROID_SECOND_UNSUPPORTED, "secondary loaders are not supported. size: %"LIBBOOT_FMT_UINT32);
    libboot_internal_register_error(LIBBOOT_ERROR_GROUP_ANDROID, LIBBOOT_ERROR_ANDROID_ZERO_KERNEL, "kernel size is 0");
    libboot_internal_register_error(LIBBOOT_ERROR_GROUP_ANDROID, LIBBOOT_ERROR_ANDROID_READ_KERNEL, "can't read kernel: %"LIBBOOT_FMT_INT);
    libboot_internal_register_error(LIBBOOT_ERROR_GROUP_ANDROID, LIBBOOT_ERROR_ANDROID_READ_RAMDISK, "can't read ramdisk: %"LIBBOOT_FMT_INT);
    libboot_internal_register_error(LIBBOOT_ERROR_GROUP_ANDROID, LIBBOOT_ERROR_ANDROID_READ_TAGS, "can't read tags: %"LIBBOOT_FMT_INT);
    libboot_internal_register_error(LIBBOOT_ERROR_GROUP_ANDROID, LIBBOOT_ERROR_ANDROID_ALLOC_CMDLINE, "can't allocate cmdline");
    libboot_internal_register_error(LIBBOOT_ERROR_GROUP_COMMON, LIBBOOT_ERROR_COMMON_OUT_OF_MEMORY, "can't allocate memory");

    return 0;
}

void libboot_uninit(void)
{
    // error messages
    while (!libboot_list_is_empty(&error_formats)) {
        libboot_error_format_t *format = libboot_list_remove_tail_type(&error_formats, libboot_error_format_t, node);
        libboot_free(format);
    }

    // error messages
    while (!libboot_list_is_empty(&allocations)) {
        allocation_t *alloc = libboot_list_remove_tail_type(&allocations, allocation_t, node);

        LOGE("MEMLEAK: 0x%08"LIBBOOT_FMT_ADDR"-0x%08"LIBBOOT_FMT_ADDR" size=0x%08"LIBBOOT_FMT_ADDR" refs=%"LIBBOOT_FMT_UINTN"\n", alloc->addr, alloc->addr+alloc->size, alloc->size, alloc->refs);
        alloc->refs = 1;
        libboot_free((void *)alloc->addr);
    }
}

void libboot_init_context(bootimg_context_t *context)
{
    if (!context) return;

    libboot_platform_memset(context, 0, sizeof(*context));
    libboot_cmdline_init(&context->cmdline);
    context->type = BOOTIMG_TYPE_UNKNOWN;
    context->outer_type = BOOTIMG_TYPE_UNKNOWN;
    context->tags_type = LIBBOOT_TAGS_TYPE_UNKNOWN;
}

void libboot_free_context(bootimg_context_t *context)
{
    if (!context) return;

    libboot_internal_io_destroy(context->io);
    libboot_internal_io_destroy(context->rootio);
    libboot_free(context->kernel_data);
    libboot_free(context->ramdisk_data);
    libboot_free(context->tags_data);
    libboot_cmdline_free(&context->cmdline);
}

int libboot_load_partial(bootimg_context_t *context, boot_uintn_t type, boot_uint8_t recursive)
{
    int rc = 0;
    int matched;

    // the image wasn't identified correctly
    if (context->type==BOOTIMG_TYPE_UNKNOWN)
        return -1;

    if (!context->io)
        return -1;

    while (context->type!=BOOTIMG_TYPE_RAW) {
        matched = 0;

        ldrmodule_t *mod;
        libboot_list_for_every_entry(&ldrmodules, mod, ldrmodule_t, node) {
            if (mod->load && mod->type==context->type) {
                // load
                rc = mod->load(context, type, recursive);

                // abort on error
                if (rc) return rc;

                // start over
                matched = 1;
                break;
            }
        }

        // abort
        if (!matched) {
            rc = -1;
            break;
        }

        if (!recursive) break;
    }

    return rc;
}

int libboot_load(bootimg_context_t *context)
{
    return libboot_load_partial(context, LIBBOOT_LOAD_TYPE_ALL, 1);
}

int libboot_unload(bootimg_context_t *context)
{
    if (!context) return -1;

    // destroy kernel IO
    libboot_internal_io_destroy(context->io);
    context->io = NULL;

    // refalloc rootio
    if (context->rootio) {
        boot_io_t *io = libboot_refalloc(context->rootio, 0);
        if (!io) return -1;
        context->io = io;
    }

    // reset type
    context->type = context->outer_type;

    // delete data
    libboot_free(context->kernel_data);
    libboot_free(context->ramdisk_data);
    libboot_free(context->tags_data);
    libboot_cmdline_free(&context->cmdline);

    // reset all values
    context->kernel_data = NULL;
    context->kernel_size = 0;
    context->kernel_addr = 0;
    context->kernel_is_linux = 0;
    context->ramdisk_data = NULL;
    context->ramdisk_size = 0;
    context->ramdisk_addr = 0;
    context->tags_data = NULL;
    context->tags_size = 0;
    context->tags_addr = 0;
    context->tags_ready = 0;
    context->tags_type = LIBBOOT_TAGS_TYPE_UNKNOWN;

    return 0;
}

static int libboot_identify_tags(bootimg_context_t *context)
{
    libboot_tags_type_t type = LIBBOOT_TAGS_TYPE_UNKNOWN;

    if (context->tags_data!=NULL) {
        tagmodule_t *mod;
        libboot_list_for_every_entry(&tagmodules, mod, tagmodule_t, node) {
            // custom test
            if (mod->magic_custom_test) {
                if (mod->magic_custom_test(context)==0)
                    type = mod->type;
            }

            // automatic test
            else {
                boot_uint8_t *data = context->tags_data;
                boot_uint8_t *magicptr = data+mod->magic_off;

                if (!libboot_platform_memcmp(magicptr, mod->magic_val, mod->magic_sz))
                    type = mod->type;
            }

            // we have a match
            if (type!=LIBBOOT_TAGS_TYPE_UNKNOWN) {
                break;
            }
        }
    }

    // set type
    context->tags_type = type;

    return 0;
}

static int libboot_generate_tags(bootimg_context_t *context)
{
    int rc;
    int matched;

    // identify existing tags
    rc = libboot_identify_tags(context);
    if (rc) return rc;

    while (!context->tags_ready) {
        matched = 0;

        // define type to search for
        libboot_tags_type_t type = context->tags_type;
        if (context->tags_data==NULL) {
            if (context->default_qcdt)
                type = LIBBOOT_TAGS_TYPE_QCDT;
            else if (context->default_fdt)
                type = LIBBOOT_TAGS_TYPE_FDT;
            else
                type = LIBBOOT_TAGS_TYPE_ATAGS;
        }

        // convert tags
        tagmodule_t *mod;
        libboot_list_for_every_entry(&tagmodules, mod, tagmodule_t, node) {
            if (mod->patch && mod->type==type) {
                // convert
                rc = mod->patch(context);

                // abort on error
                if (rc) return rc;

                // start over
                matched = 1;
                break;
            }
        }

        // abort
        if (!matched) break;
    }

    // no tags were loaded
    if (!matched || !context->tags_data)
        rc = -1;

    return rc;
}

int libboot_prepare(bootimg_context_t *context)
{
    int rc;

    // the image wasn't loaded correctly
    if (context->type!=BOOTIMG_TYPE_RAW)
        return -1;

    context->kernel_arguments[0] = 0;
    context->kernel_arguments[1] = 0;
    context->kernel_arguments[2] = 0;

    if (context->kernel_is_linux) {
        // generate tags
        rc = libboot_generate_tags(context);
        if (rc) return rc;
    }

    // allocate loading addresses
    if (context->kernel_addr && context->kernel_size) {
        context->kernel_addr = (boot_uintn_t)libboot_platform_bootalloc(context->kernel_addr, context->kernel_size);
        if (!context->kernel_addr) return -1;
    }
    if (context->ramdisk_addr && context->ramdisk_size) {
        context->ramdisk_addr = (boot_uintn_t)libboot_platform_bootalloc(context->ramdisk_addr, context->ramdisk_size);
        if (!context->ramdisk_addr) return -1;
    }
    if (context->tags_addr && context->tags_size) {
        context->tags_addr = (boot_uintn_t)libboot_platform_bootalloc(context->tags_addr, context->tags_size);
        if (!context->tags_addr) return -1;
    }

    // load images to final addresses
    libboot_platform_memmove((void *)context->kernel_addr, context->kernel_data, context->kernel_size);
    if (context->ramdisk_size)
        libboot_platform_memmove((void *)context->ramdisk_addr, context->ramdisk_data, context->ramdisk_size);
    if (context->tags_size)
        libboot_platform_memmove((void *)context->tags_addr, context->tags_data, context->tags_size);

    if (context->kernel_is_linux) {
        // set arguments
        context->kernel_arguments[0] = 0;
        if (context->tags_type==LIBBOOT_TAGS_TYPE_FDT)
            context->kernel_arguments[1] = 0;
        else
            context->kernel_arguments[1] = libboot_platform_machtype();
        context->kernel_arguments[2] = context->tags_addr;
    }

    return 0;
}
