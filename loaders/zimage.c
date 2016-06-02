#include <lib/boot.h>
#include <lib/boot/internal/boot_internal.h>

static boot_uintn_t magic_val = 0x016f2818;

static int ldrmodule_load(bootimg_context_t* context) {
    // we're first, just load the whole zImage into memory
    if(!context->kernel_data) {
        if(libboot_internal_load_rawdata_to_kernel(context))
            return -1;
    }

    // get zImage size
    boot_uint8_t* data8 = context->kernel_data;
    boot_uintn_t zimage_start, zimage_end, zimage_size;
    libboot_platform_memmove(&zimage_start, data8 + 0x28, sizeof(zimage_start));
    libboot_platform_memmove(&zimage_end,   data8 + 0x2C, sizeof(zimage_end));
    zimage_size = zimage_end - zimage_start;

    // TODO: find appended fdt
    

    // we'll need tags to boot
    context->kernel_is_linux = 1;
    context->type = BOOTIMG_TYPE_RAW;
    context->kernel_size = zimage_size;

    return 0;
}

static ldrmodule_t ldrmodule = {
    .type = BOOTIMG_TYPE_ZIMAGE,
    .magic_custom_test = NULL,
    .magic_off = 0x24,
    .magic_sz = sizeof(boot_uintn_t),
    .magic_val = &magic_val,

    .load = ldrmodule_load,
};

int libboot_internal_ldrmodule_zimage_init(void) {
    libboot_internal_ldrmodule_register(&ldrmodule);
    return 0;
}
