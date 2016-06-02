#ifndef LIB_BOOT_INTERNAL_H
#define LIB_BOOT_INTERNAL_H

#include <lib/boot.h>
#include <lib/boot/internal/list.h>

// stdlib
#ifndef NULL
#define NULL ((void*)0)
#endif

// alignment
#define ROUNDUP(a, b) (((a) + ((b)-1)) & ~((b)-1))
#define ROUNDDOWN(a, b) ((a) & ~((b)-1))
#define ALIGN(a, b) ROUNDUP(a, b)
#define IS_ALIGNED(a, b) (!(((uintptr_t)(a)) & (((uintptr_t)(b))-1)))
#define IO_ALIGN(io, sz) ALIGN(sz, (io)->blksz)

// LOADERS
typedef int (*ldrmodule_magictest_t)(boot_io_t* io);
typedef int (*ldrmodule_load_t)(bootimg_context_t* context);

typedef struct {
    libboot_list_node_t node;

    // assigned type
    bootimg_type_t type;

    // magic
    ldrmodule_magictest_t magic_custom_test;
    boot_uintn_t magic_off;
    boot_uintn_t magic_sz;
    const void* magic_val;

    // loading
    ldrmodule_load_t load;
} ldrmodule_t;

typedef struct {
    libboot_list_node_t node;

    libboot_error_group_t group;
    libboot_error_type_t type;
    const char* fmt;
} libboot_error_format_t;

// tag modules
typedef int (*tagmodule_magictest_t)(bootimg_context_t* context);
typedef int (*tagmodule_patch_t)(bootimg_context_t* context);

typedef struct {
    libboot_list_node_t node;

    // assigned type
    libboot_tags_type_t type;

    // magic
    tagmodule_magictest_t magic_custom_test;
    boot_uintn_t magic_off;
    boot_uintn_t magic_sz;
    const void* magic_val;

    // patch
    tagmodule_patch_t patch;
} tagmodule_t;

// error handling

libboot_error_format_t* libboot_internal_get_error_format(libboot_error_group_t group, libboot_error_type_t type);
char* libboot_internal_error_stack_alloc(void);

#define libboot_format_error(group, type, ...) do {\
    char* buf = libboot_internal_error_stack_alloc();\
    if(!buf) break; \
    libboot_error_format_t *format = libboot_internal_get_error_format(group, type); \
    if(format) libboot_platform_format_string(buf, 4096, format->fmt, ##__VA_ARGS__); \
    else libboot_platform_format_string(buf, 4096, "unknown error "LIBBOOT_FMT_UINTN" in group "LIBBOOT_FMT_UINTN, group, type); \
} while(0)
void libboot_internal_register_error(libboot_error_group_t group, libboot_error_type_t type, const char* fmt);

// IO
void* libboot_internal_io_alloc(boot_io_t* io, boot_uintn_t sz);
boot_intn_t libboot_internal_io_read(boot_io_t* io, void* buf, boot_uintn_t off, boot_uintn_t sz);
void* libboot_internal_io_bigalloc(bootimg_context_t* context, boot_uintn_t sz);
void libboot_internal_free_io(boot_io_t* io);

boot_uintn_t libboot_internal_strlcpy(char *dst, const char *src, boot_uintn_t size);

// cmdline
void libboot_cmdline_init(libboot_list_node_t* list);
void libboot_cmdline_free(libboot_list_node_t* list);
void libboot_cmdline_addall(libboot_list_node_t* list, char* cmdline, int overwrite);
void libboot_cmdline_add(libboot_list_node_t* list, const char* name, const char* value, int overwrite);
int libboot_cmdline_has(libboot_list_node_t* list, const char* name);
const char* libboot_cmdline_get(libboot_list_node_t* list, const char* name);
boot_uintn_t libboot_cmdline_generate(libboot_list_node_t* list, char* buf, boot_uintn_t bufsize);
void libboot_cmdline_remove(libboot_list_node_t* list, const char* name);
boot_uintn_t libboot_cmdline_length(libboot_list_node_t* list);

// loaders
void libboot_internal_ldrmodule_register(ldrmodule_t* mod);
int libboot_internal_load_rawdata_to_kernel(bootimg_context_t* context);

int libboot_internal_ldrmodule_android_init(void);
int libboot_internal_ldrmodule_efi_init(void);
int libboot_internal_ldrmodule_elf_init(void);
int libboot_internal_ldrmodule_zimage_init(void);
int libboot_internal_ldrmodule_qcmbn_init(void);
int libboot_internal_ldrmodule_gzip_init(void);

// tag modules
void libboot_internal_tagmodule_register(tagmodule_t* mod);

int libboot_internal_tagmodule_qcdt_init(void);
int libboot_internal_tagmodule_fdt_init(void);
int libboot_internal_tagmodule_atags_init(void);

#endif // LIB_BOOT_INTERNAL_H
