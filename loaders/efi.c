#include <lib/boot.h>
#include <lib/boot/internal/boot_internal.h>

static ldrmodule_t ldrmodule = {
    .type = BOOTIMG_TYPE_EFI,
    .magic_custom_test = NULL,
    .magic_off = 0,
    .magic_sz = 2,
    .magic_val = "MZ",
};

int libboot_internal_ldrmodule_efi_init(void) {
    libboot_internal_ldrmodule_register(&ldrmodule);
    return 0;
}
