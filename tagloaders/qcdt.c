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
#include <lib/boot/internal/qcdt.h>

#define DEV_TREE_MAGIC          0x54444351 /* "QCDT" */

static int tagmodule_patch(bootimg_context_t* context) {
    dt_table_t* table = (dt_table_t*) context->tags_data;
    boot_uint32_t dt_hdr_size;

    // try default qcdt
    if(!table) {
        table = context->default_qcdt;
    }

    // validate dt
    if (libboot_qcdt_validate(table, &dt_hdr_size) != 0) {
        return -1;
    }

    // get compatible dt entry offset
    dt_entry_t dt_entry;
    if(libboot_qcdt_get_entry_info(table, &dt_entry) != 0){
        return -1;
    }

    // allocate data
    void* data = libboot_bigalloc(dt_entry.size);
    if(!data) return -1;

    // copy fdt
    libboot_platform_memmove(data, (boot_uint8_t*)(table) + dt_entry.offset, dt_entry.size);
    libboot_bigfree(context->tags_data);
    context->tags_data = data;
    context->tags_size = dt_entry.size;
    context->tags_type = LIBBOOT_TAGS_TYPE_FDT;

    return 0;
}

static boot_uint32_t magic = DEV_TREE_MAGIC;
static tagmodule_t tagmodule = {
    .type = LIBBOOT_TAGS_TYPE_QCDT,
    .magic_custom_test = NULL,
    .magic_off = 0,
    .magic_sz = 4,
    .magic_val = &magic,

    .patch = tagmodule_patch,
};

int libboot_internal_tagmodule_qcdt_init(void) {
    libboot_internal_tagmodule_register(&tagmodule);
    return 0;
}
