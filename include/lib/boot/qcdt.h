/* Copyright (c) 2012-2014, The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * * Redistributions of source code must retain the above copyright
 *  notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 *  with the distribution.
 *   * Neither the name of The Linux Foundation nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef LIB_BOOT_QCDT_H
#define LIB_BOOT_QCDT_H

#define DEV_TREE_SUCCESS        0
#define DEV_TREE_MAGIC          0x54444351 /* "QCDT" */
#define DEV_TREE_MAGIC_LEN      4
#define DEV_TREE_VERSION_V1     1
#define DEV_TREE_VERSION_V2     2
#define DEV_TREE_VERSION_V3     3

#define DEV_TREE_HEADER_SIZE    12

#define DTB_MAGIC               0xedfe0dd0
#define DTB_OFFSET              0x2C

/*
 * For DTB V1: The DTB entries would be of the format
 * qcom,msm-id = <msm8974, CDP, rev_1>; (3 * sizeof(boot_uint32_t))
 * For DTB V2: The DTB entries would be of the format
 * qcom,msm-id   = <msm8974, rev_1>;  (2 * sizeof(boot_uint32_t))
 * qcom,board-id = <CDP, subtype_ID>; (2 * sizeof(boot_uint32_t))
 * The macros below are defined based on these.
 */
#define DT_ENTRY_V1_SIZE        0xC
#define PLAT_ID_SIZE            0x8
#define BOARD_ID_SIZE           0x8
#define PMIC_ID_SIZE           0x8


typedef struct {
    boot_uint32_t platform_id;
    boot_uint32_t variant_id;
    boot_uint32_t soc_rev;
    boot_uint32_t offset;
    boot_uint32_t size;
} dt_entry_v1_t;

typedef struct {
    boot_uint32_t platform_id;
    boot_uint32_t variant_id;
    boot_uint32_t board_hw_subtype;
    boot_uint32_t soc_rev;
    boot_uint32_t offset;
    boot_uint32_t size;
} dt_entry_v2_t;

typedef struct {
    boot_uint32_t platform_id;
    boot_uint32_t variant_id;
    boot_uint32_t board_hw_subtype;
    boot_uint32_t soc_rev;
    boot_uint32_t pmic_rev[4];
    boot_uint32_t offset;
    boot_uint32_t size;
} dt_entry_t;

typedef struct {
    boot_uint32_t platform_id;
    boot_uint32_t variant_id;
    boot_uint32_t board_hw_subtype;
    boot_uint32_t soc_rev;
    boot_uint32_t pmic_rev[4];

    void* dtb_data;
    boot_uint32_t dtb_size;
} dt_entry_local_t;

typedef struct {
    boot_uint32_t magic;
    boot_uint32_t version;
    boot_uint32_t num_entries;
} dt_table_t;

typedef struct  {
    boot_uint32_t platform_id;
    boot_uint32_t soc_rev;
} plat_id_t;

typedef struct {
    boot_uint32_t variant_id;
    boot_uint32_t platform_subtype;
} board_id_t;

typedef struct {
    boot_uint32_t pmic_version[4];
} pmic_id_t;

typedef struct {
    boot_uint32_t offset;
    boot_uint32_t mem_info_cnt;
    boot_uint32_t addr_cell_size;
    boot_uint32_t size_cell_size;
} dt_mem_node_info_t;

typedef enum {
    DTB_FOUNDRY = 0,
    DTB_SOC,
    DTB_MAJOR_MINOR,
    DTB_PMIC0,
    DTB_PMIC1,
    DTB_PMIC2,
    DTB_PMIC3,
    DTB_PMIC_MODEL,
    DTB_PANEL_TYPE,
    DTB_BOOT_DEVICE,
} dt_entry_info_t;

typedef enum {
    DT_OP_SUCCESS,
    DT_OP_FAILURE = -1,
} dt_err_codes_t;

typedef struct {
    libboot_list_node_t node;
    dt_entry_local_t *dt_entry_m;
} dt_entry_node_t;


dt_entry_node_t *dt_entry_list_alloc_node(void);
void dt_entry_list_insert(dt_entry_node_t *dt_list, dt_entry_node_t *dt_node_member);
void dt_entry_list_delete(dt_entry_node_t *dt_node_member);
dt_entry_node_t *dt_entry_list_create(void);
void dt_entry_list_free(dt_entry_node_t *dt_list);

int libboot_qcdt_validate(dt_table_t *table, boot_uint32_t *dt_hdr_size);
int libboot_qcdt_get_entry_info(dt_table_t *table, dt_entry_local_t *dt_entry_info);
void *libboot_qcdt_appended(void *fdt, boot_uintn_t fdt_size);
#endif // LIB_BOOT_QCDT_H
