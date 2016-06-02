#include <lib/boot.h>
#include <lib/boot/internal/boot_internal.h>

#define	ELFMAG		"\177ELF"

static ldrmodule_t ldrmodule = {
    .type = BOOTIMG_TYPE_ELF,
    .magic_custom_test = NULL,
    .magic_off = 0,
    .magic_sz = 4,
    .magic_val = ELFMAG,
};

int libboot_internal_ldrmodule_elf_init(void) {
    libboot_internal_ldrmodule_register(&ldrmodule);
    return 0;
}
