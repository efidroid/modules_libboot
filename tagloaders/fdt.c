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
