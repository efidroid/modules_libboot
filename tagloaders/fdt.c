#include <lib/boot.h>
#include <lib/boot/internal/boot_internal.h>
#include <libfdt.h>

static int tagmodule_patch(bootimg_context_t* context) {
    (void)(context);

    // use default fdt
    if(context->tags_data==NULL) {
        if(!context->default_fdt) return -1;

        context->tags_data = context->default_fdt;
        context->tags_size = fdt_totalsize(context->tags_data);
        context->tags_type = LIBBOOT_TAGS_TYPE_FDT;
    }

    // TODO: patch fdt

    context->tags_ready = 1;
    return 0;
}

static boot_uint32_t magic;
static tagmodule_t tagmodule = {
    .type = LIBBOOT_TAGS_TYPE_FDT,
    .magic_custom_test = NULL,
    .magic_off = 0,
    .magic_sz = 4,
    .magic_val = &magic,

    .patch = tagmodule_patch,
};

int libboot_internal_tagmodule_fdt_init(void) {
    magic = fdt32_to_cpu(FDT_MAGIC);
    libboot_internal_tagmodule_register(&tagmodule);
    return 0;
}
