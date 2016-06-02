#ifndef LIB_BOOT_H
#define LIB_BOOT_H

#include <lib/boot/boot_platform.h>

// LIST
struct libboot_list_node {
    struct libboot_list_node *prev;
    struct libboot_list_node *next;
};
typedef struct libboot_list_node libboot_list_node_t;

// IO
struct boot_io;

typedef boot_intn_t (*boot_io_fn_read_t)(struct boot_io* io, void* buf, boot_uintn_t blkoff, boot_uintn_t count);

struct boot_io {
    boot_io_fn_read_t read;
    boot_uintn_t blksz;
    boot_uintn_t numblocks;

    void* pdata;
    boot_uint8_t pdata_is_allocated;
};
typedef struct boot_io boot_io_t;

// TYPE
typedef enum {
    BOOTIMG_TYPE_RAW = -1,
    BOOTIMG_TYPE_ANDROID,
    BOOTIMG_TYPE_EFI,
    BOOTIMG_TYPE_ELF,
    BOOTIMG_TYPE_QCMBN,
    BOOTIMG_TYPE_ZIMAGE,
    BOOTIMG_TYPE_UIMAGE,
    BOOTIMG_TYPE_GZIP,
} bootimg_type_t;

typedef enum {
    LIBBOOT_TAGS_TYPE_UNKNOWN = -1,
    LIBBOOT_TAGS_TYPE_ATAGS,
    LIBBOOT_TAGS_TYPE_FDT,
    LIBBOOT_TAGS_TYPE_QCDT,
} libboot_tags_type_t;

// ERRORS
typedef enum {
    LIBBOOT_ERROR_GROUP_UNKNOWN = -1,
    LIBBOOT_ERROR_GROUP_COMMON,
    LIBBOOT_ERROR_GROUP_ANDROID,
} libboot_error_group_t;

typedef enum {
    LIBBOOT_ERROR_TYPE_UNKNOWN = -1,
} libboot_error_type_t;

typedef enum {
    LIBBOOT_ERROR_COMMON_UNKNOWN = -1,
    LIBBOOT_ERROR_COMMON_OUT_OF_MEMORY,
} libboot_error_common_t;

typedef enum {
    LIBBOOT_ERROR_ANDROID_UNKNOWN = -1,
    LIBBOOT_ERROR_ANDROID_SECOND_UNSUPPORTED,
    LIBBOOT_ERROR_ANDROID_ZERO_KERNEL,
    LIBBOOT_ERROR_ANDROID_READ_KERNEL,
    LIBBOOT_ERROR_ANDROID_READ_RAMDISK,
    LIBBOOT_ERROR_ANDROID_READ_TAGS,
    LIBBOOT_ERROR_ANDROID_ALLOC_CMDLINE,
} libboot_error_android_t;

char** libboot_error_stack_get(void);
boot_uintn_t libboot_error_stack_count(void);
void libboot_error_stack_reset(void);

// MAIN

struct bootimg_context;

typedef void* (*libboot_context_getmemory_callback_t)(void* pdata, boot_uintn_t addr, boot_uintn_t size);

typedef void* (*libboot_context_fn_bootalloc_t)(boot_uintn_t addr, boot_uintn_t sz);
typedef void* (*libboot_context_fn_bigalloc_t)(boot_uintn_t sz);
typedef void  (*libboot_context_fn_bigfree_t)(void* ptr);
typedef void* (*libboot_context_fn_getmemory_t)(void *pdata, libboot_context_getmemory_callback_t cb);
typedef void* (*libboot_context_fn_addatags_t)(void *tags);
typedef boot_uintn_t (*libboot_context_fn_getmachtype_t)(struct bootimg_context* context);

struct bootimg_context {
    // identify
    bootimg_type_t type;
    boot_io_t* io;

    // load: kernel
    boot_uintn_t kernel_size;
    void* kernel_data;
    boot_uintn_t kernel_arguments[3];
    int kernel_is_linux;
    // load: ramdisk
    boot_uintn_t ramdisk_size;
    void* ramdisk_data;
    // load: tags
    libboot_tags_type_t tags_type;
    boot_uintn_t tags_size;
    void* tags_data;
    int tags_ready;
    // load: cmdline
    libboot_list_node_t cmdline;

    // external configuration
    boot_uintn_t kernel_addr;
    boot_uintn_t ramdisk_addr;
    boot_uintn_t tags_addr;
    void* default_fdt;
    void* default_qcdt;
    libboot_context_fn_getmachtype_t getmachtype;
    libboot_context_fn_bootalloc_t bootalloc;
    libboot_context_fn_bigalloc_t bigalloc;
    libboot_context_fn_bigfree_t bigfree;
    libboot_context_fn_getmemory_t getmemory;
    libboot_context_fn_addatags_t add_custom_atags;
};
typedef struct bootimg_context bootimg_context_t;

int libboot_init(void);
void libboot_init_context(bootimg_context_t* context);
void libboot_free_context(bootimg_context_t* context);
int libboot_identify(boot_io_t* io, bootimg_context_t* context);
int libboot_identify_memory(void* mem, boot_uintn_t sz, bootimg_context_t* context);

int libboot_load(bootimg_context_t* context);
int libboot_prepare(bootimg_context_t* context);

#endif // LIB_BOOT_H
