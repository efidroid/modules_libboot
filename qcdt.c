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

#include <lib/boot.h>
#include <lib/boot/internal/boot_internal.h>
#include <lib/boot/internal/qcdt.h>
#include <libfdt.h>

//static dt_mem_node_info_t mem_node;
static int devtree_entry_is_excact_match(dt_entry_t *cur_dt_entry, dt_entry_node_t *dt_list);
static dt_entry_t *devtree_get_best_entry(dt_entry_node_t *dt_list);
static int devtree_delete_incompatible_entries2(dt_entry_node_t *dt_list, boot_uint32_t dtb_info);

/* Add function to allocate dt entry list, used for recording
*  the entry which conform to devtree_entry_is_excact_match()
*/
static dt_entry_node_t *dt_entry_list_init(void)
{
    dt_entry_node_t *dt_node_member = NULL;

    dt_node_member = (dt_entry_node_t *) libboot_alloc(sizeof(dt_entry_node_t));
    LIBBOOT_ASSERT(dt_node_member);

    libboot_list_clear_node(&dt_node_member->node);

    dt_node_member->dt_entry_m = (dt_entry_t *) libboot_alloc(sizeof(dt_entry_t));
    LIBBOOT_ASSERT(dt_node_member->dt_entry_m);

    libboot_platform_memset(dt_node_member->dt_entry_m , 0, sizeof(dt_entry_t));
    return dt_node_member;
}

static void insert_dt_entry_in_queue(dt_entry_node_t *dt_list, dt_entry_node_t *dt_node_member)
{
    libboot_list_add_tail(&dt_list->node, &dt_node_member->node);
}

static void dt_entry_list_delete(dt_entry_node_t *dt_node_member)
{
    if (libboot_list_in_list(&dt_node_member->node)) {
        libboot_list_delete(&dt_node_member->node);
        libboot_free(dt_node_member->dt_entry_m);
        libboot_free(dt_node_member);
    }
}

int libboot_qcdt_add_compatible_entries(void *dtb, boot_uint32_t dtb_size, dt_entry_node_t *dtb_list)
{
    int root_offset;
    const void *prop = NULL;
    const char *plat_prop = NULL;
    const char *board_prop = NULL;
    const char *pmic_prop = NULL;
    char *model = NULL;
    dt_entry_t *cur_dt_entry;
    dt_entry_t *dt_entry_array = NULL;
    board_id_t *board_data = NULL;
    plat_id_t *platform_data = NULL;
    pmic_id_t *pmic_data = NULL;
    int len;
    int len_board_id;
    int len_plat_id;
    int min_plat_id_len = 0;
    int len_pmic_id;
    boot_uint32_t dtb_ver;
    boot_uint32_t num_entries = 0;
    boot_uint32_t i, j, k, n;
    boot_uint32_t msm_data_count;
    boot_uint32_t board_data_count;
    boot_uint32_t pmic_data_count;

    root_offset = fdt_path_offset(dtb, "/");
    if (root_offset < 0)
        return 0;

    prop = fdt_getprop(dtb, root_offset, "model", &len);
    if (prop && len > 0) {
        model = (char *) libboot_alloc(sizeof(char) * len);
        LIBBOOT_ASSERT(model);
        libboot_internal_strlcpy(model, prop, len);
    } else {
        LOGI("model does not exist in device tree\n");
    }
    /* Find the pmic-id prop from DTB , if pmic-id is present then
    * the DTB is version 3, otherwise find the board-id prop from DTB ,
    * if board-id is present then the DTB is version 2 */
    pmic_prop = (const char *)fdt_getprop(dtb, root_offset, "qcom,pmic-id", &len_pmic_id);
    board_prop = (const char *)fdt_getprop(dtb, root_offset, "qcom,board-id", &len_board_id);
    if (pmic_prop && (len_pmic_id > 0) && board_prop && (len_board_id > 0)) {
        if ((len_pmic_id % PMIC_ID_SIZE) || (len_board_id % BOARD_ID_SIZE)) {
            LOGE("qcom,pmic-id(%d) or qcom,board-id(%d) in device tree is not a multiple of (%d %d)\n",
                 len_pmic_id, len_board_id, PMIC_ID_SIZE, BOARD_ID_SIZE);
            return 0;
        }
        dtb_ver = DEV_TREE_VERSION_V3;
        min_plat_id_len = PLAT_ID_SIZE;
    } else if (board_prop && len_board_id > 0) {
        if (len_board_id % BOARD_ID_SIZE) {
            LOGE("qcom,board-id in device tree is (%d) not a multiple of (%d)\n",
                 len_board_id, BOARD_ID_SIZE);
            return 0;
        }
        dtb_ver = DEV_TREE_VERSION_V2;
        min_plat_id_len = PLAT_ID_SIZE;
    } else {
        dtb_ver = DEV_TREE_VERSION_V1;
        min_plat_id_len = DT_ENTRY_V1_SIZE;
    }

    /* Get the msm-id prop from DTB */
    plat_prop = (const char *)fdt_getprop(dtb, root_offset, "qcom,msm-id", &len_plat_id);
    if (!plat_prop || len_plat_id <= 0) {
        LOGI("qcom,msm-id entry not found\n");
        return 0;
    } else if (len_plat_id % min_plat_id_len) {
        LOGI("qcom,msm-id in device tree is (%d) not a multiple of (%d)\n",
             len_plat_id, min_plat_id_len);
        return 0;
    }

    /*
     * If DTB version is '1' look for <x y z> pair in the DTB
     * x: platform_id
     * y: variant_id
     * z: SOC rev
     */
    if (dtb_ver == DEV_TREE_VERSION_V1) {
        cur_dt_entry = (dt_entry_t *)
                       libboot_alloc(sizeof(dt_entry_t));

        if (!cur_dt_entry) {
            LOGE("Out of memory\n");
            return 0;
        }
        libboot_platform_memset(cur_dt_entry, 0, sizeof(dt_entry_t));

        while (len_plat_id) {
            cur_dt_entry->platform_id = fdt32_to_cpu(((const dt_entry_v1_t *)plat_prop)->platform_id);
            cur_dt_entry->variant_id = fdt32_to_cpu(((const dt_entry_v1_t *)plat_prop)->variant_id);
            cur_dt_entry->soc_rev = fdt32_to_cpu(((const dt_entry_v1_t *)plat_prop)->soc_rev);
            cur_dt_entry->board_hw_subtype =
                fdt32_to_cpu(((const dt_entry_v1_t *)plat_prop)->variant_id) >> 0x18;
            cur_dt_entry->pmic_rev[0] = libboot_qcdt_pmic_target(0);
            cur_dt_entry->pmic_rev[1] = libboot_qcdt_pmic_target(1);
            cur_dt_entry->pmic_rev[2] = libboot_qcdt_pmic_target(2);
            cur_dt_entry->pmic_rev[3] = libboot_qcdt_pmic_target(3);
            cur_dt_entry->offset = (boot_uint32_t)dtb;
            cur_dt_entry->size = dtb_size;

            LOGV("Found an appended flattened device tree (%s - %u %u 0x%x)\n",
                 *model ? model : "unknown",
                 cur_dt_entry->platform_id, cur_dt_entry->variant_id, cur_dt_entry->soc_rev);

            if (devtree_entry_is_excact_match(cur_dt_entry, dtb_list)) {
                LOGV("Device tree exact match the board: <%u %u 0x%x> != <%u %u 0x%x>\n",
                     cur_dt_entry->platform_id,
                     cur_dt_entry->variant_id,
                     cur_dt_entry->soc_rev,
                     libboot_qcdt_platform_id(),
                     libboot_qcdt_hardware_id(),
                     libboot_qcdt_soc_version());

            } else {
                LOGV("Device tree's msm_id doesn't match the board: <%u %u 0x%x> != <%u %u 0x%x>\n",
                     cur_dt_entry->platform_id,
                     cur_dt_entry->variant_id,
                     cur_dt_entry->soc_rev,
                     libboot_qcdt_platform_id(),
                     libboot_qcdt_hardware_id(),
                     libboot_qcdt_soc_version());
                plat_prop += DT_ENTRY_V1_SIZE;
                len_plat_id -= DT_ENTRY_V1_SIZE;
                continue;
            }
        }
        libboot_free(cur_dt_entry);

    }
    /*
     * If DTB Version is '3' then we have split DTB with board & msm data & pmic
     * populated saperately in board-id & msm-id & pmic-id prop respectively.
     * Extract the data & prepare a look up table
     */
    else if (dtb_ver == DEV_TREE_VERSION_V2 || dtb_ver == DEV_TREE_VERSION_V3) {
        board_data_count = (len_board_id / BOARD_ID_SIZE);
        msm_data_count = (len_plat_id / PLAT_ID_SIZE);
        /* If dtb version is v2.0, the pmic_data_count will be <= 0 */
        pmic_data_count = (len_pmic_id / PMIC_ID_SIZE);

        /* If we are using dtb v3.0, then we have split board, msm & pmic data in the DTB
        *  If we are using dtb v2.0, then we have split board & msmdata in the DTB
        */
        board_data = (board_id_t *) libboot_alloc(sizeof(board_id_t) * (len_board_id / BOARD_ID_SIZE));
        LIBBOOT_ASSERT(board_data);
        platform_data = (plat_id_t *) libboot_alloc(sizeof(plat_id_t) * (len_plat_id / PLAT_ID_SIZE));
        LIBBOOT_ASSERT(platform_data);
        if (dtb_ver == DEV_TREE_VERSION_V3) {
            pmic_data = (pmic_id_t *) libboot_alloc(sizeof(pmic_id_t) * (len_pmic_id / PMIC_ID_SIZE));
            LIBBOOT_ASSERT(pmic_data);
        }
        i = 0;

        /* Extract board data from DTB */
        for (i = 0 ; i < board_data_count; i++) {
            board_data[i].variant_id = fdt32_to_cpu(((board_id_t *)board_prop)->variant_id);
            board_data[i].platform_subtype = fdt32_to_cpu(((board_id_t *)board_prop)->platform_subtype);
            /* For V2/V3 version of DTBs we have platform version field as part
             * of variant ID, in such case the subtype will be mentioned as 0x0
             * As the qcom, board-id = <0xSSPMPmPH, 0x0>
             * SS -- Subtype
             * PM -- Platform major version
             * Pm -- Platform minor version
             * PH -- Platform hardware CDP/MTP
             * In such case to make it compatible with LK algorithm move the subtype
             * from variant_id to subtype field
             */
            if (board_data[i].platform_subtype == 0)
                board_data[i].platform_subtype =
                    fdt32_to_cpu(((board_id_t *)board_prop)->variant_id) >> 0x18;

            len_board_id -= sizeof(board_id_t);
            board_prop += sizeof(board_id_t);
        }

        /* Extract platform data from DTB */
        for (i = 0 ; i < msm_data_count; i++) {
            platform_data[i].platform_id = fdt32_to_cpu(((plat_id_t *)plat_prop)->platform_id);
            platform_data[i].soc_rev = fdt32_to_cpu(((plat_id_t *)plat_prop)->soc_rev);
            len_plat_id -= sizeof(plat_id_t);
            plat_prop += sizeof(plat_id_t);
        }

        if (dtb_ver == DEV_TREE_VERSION_V3 && pmic_prop) {
            /* Extract pmic data from DTB */
            for (i = 0 ; i < pmic_data_count; i++) {
                pmic_data[i].pmic_version[0]= fdt32_to_cpu(((pmic_id_t *)pmic_prop)->pmic_version[0]);
                pmic_data[i].pmic_version[1]= fdt32_to_cpu(((pmic_id_t *)pmic_prop)->pmic_version[1]);
                pmic_data[i].pmic_version[2]= fdt32_to_cpu(((pmic_id_t *)pmic_prop)->pmic_version[2]);
                pmic_data[i].pmic_version[3]= fdt32_to_cpu(((pmic_id_t *)pmic_prop)->pmic_version[3]);
                len_pmic_id -= sizeof(pmic_id_t);
                pmic_prop += sizeof(pmic_id_t);
            }

            /* We need to merge board & platform data into dt entry structure */
            num_entries = msm_data_count * board_data_count * pmic_data_count;
        } else {
            /* We need to merge board & platform data into dt entry structure */
            num_entries = msm_data_count * board_data_count;
        }

        if ((((boot_uint64_t)msm_data_count * (boot_uint64_t)board_data_count * (boot_uint64_t)pmic_data_count) !=
                msm_data_count * board_data_count * pmic_data_count) ||
                (((boot_uint64_t)msm_data_count * (boot_uint64_t)board_data_count) != msm_data_count * board_data_count)) {

            libboot_free(board_data);
            libboot_free(platform_data);
            if (pmic_data)
                libboot_free(pmic_data);
            if (model)
                libboot_free(model);
            return 0;
        }

        dt_entry_array = (dt_entry_t *) libboot_alloc(sizeof(dt_entry_t) * num_entries);
        LIBBOOT_ASSERT(dt_entry_array);

        /* If we have '<X>; <Y>; <Z>' as platform data & '<A>; <B>; <C>' as board data.
         * Then dt entry should look like
         * <X ,A >;<X, B>;<X, C>;
         * <Y ,A >;<Y, B>;<Y, C>;
         * <Z ,A >;<Z, B>;<Z, C>;
         */
        i = 0;
        k = 0;
        n = 0;
        for (i = 0; i < msm_data_count; i++) {
            for (j = 0; j < board_data_count; j++) {
                if (dtb_ver == DEV_TREE_VERSION_V3 && pmic_prop) {
                    for (n = 0; n < pmic_data_count; n++) {
                        dt_entry_array[k].platform_id = platform_data[i].platform_id;
                        dt_entry_array[k].soc_rev = platform_data[i].soc_rev;
                        dt_entry_array[k].variant_id = board_data[j].variant_id;
                        dt_entry_array[k].board_hw_subtype = board_data[j].platform_subtype;
                        dt_entry_array[k].pmic_rev[0]= pmic_data[n].pmic_version[0];
                        dt_entry_array[k].pmic_rev[1]= pmic_data[n].pmic_version[1];
                        dt_entry_array[k].pmic_rev[2]= pmic_data[n].pmic_version[2];
                        dt_entry_array[k].pmic_rev[3]= pmic_data[n].pmic_version[3];
                        dt_entry_array[k].offset = (boot_uint32_t)dtb;
                        dt_entry_array[k].size = dtb_size;
                        k++;
                    }

                } else {
                    dt_entry_array[k].platform_id = platform_data[i].platform_id;
                    dt_entry_array[k].soc_rev = platform_data[i].soc_rev;
                    dt_entry_array[k].variant_id = board_data[j].variant_id;
                    dt_entry_array[k].board_hw_subtype = board_data[j].platform_subtype;
                    dt_entry_array[k].pmic_rev[0]= libboot_qcdt_pmic_target(0);
                    dt_entry_array[k].pmic_rev[1]= libboot_qcdt_pmic_target(1);
                    dt_entry_array[k].pmic_rev[2]= libboot_qcdt_pmic_target(2);
                    dt_entry_array[k].pmic_rev[3]= libboot_qcdt_pmic_target(3);
                    dt_entry_array[k].offset = (boot_uint32_t)dtb;
                    dt_entry_array[k].size = dtb_size;
                    k++;
                }
            }
        }

        for (i=0 ; i < num_entries; i++) {
            LOGV("Found an appended flattened device tree (%s - %u %u %u 0x%x)\n",
                 *model ? model : "unknown",
                 dt_entry_array[i].platform_id, dt_entry_array[i].variant_id, dt_entry_array[i].board_hw_subtype, dt_entry_array[i].soc_rev);

            if (devtree_entry_is_excact_match(&(dt_entry_array[i]), dtb_list)) {
                LOGV("Device tree exact match the board: <%u %u %u 0x%x> == <%u %u %u 0x%x>\n",
                     dt_entry_array[i].platform_id,
                     dt_entry_array[i].variant_id,
                     dt_entry_array[i].soc_rev,
                     dt_entry_array[i].board_hw_subtype,
                     libboot_qcdt_platform_id(),
                     libboot_qcdt_hardware_id(),
                     libboot_qcdt_hardware_subtype(),
                     libboot_qcdt_soc_version());

            } else {
                LOGV("Device tree's msm_id doesn't match the board: <%u %u %u 0x%x> != <%u %u %u 0x%x>\n",
                     dt_entry_array[i].platform_id,
                     dt_entry_array[i].variant_id,
                     dt_entry_array[i].soc_rev,
                     dt_entry_array[i].board_hw_subtype,
                     libboot_qcdt_platform_id(),
                     libboot_qcdt_hardware_id(),
                     libboot_qcdt_hardware_subtype(),
                     libboot_qcdt_soc_version());
            }
        }

        libboot_free(board_data);
        libboot_free(platform_data);
        if (pmic_data)
            libboot_free(pmic_data);
        libboot_free(dt_entry_array);
    }
    if (model)
        libboot_free(model);
    return 1;
}

#if 0
/*
 * Will relocate the DTB to the tags addr if the device tree is found and return
 * its address
 *
 * Arguments:    kernel - Start address of the kernel loaded in RAM
 *               tags - Start address of the tags loaded in RAM
 *               kernel_size - Size of the kernel in bytes
 *
 * Return Value: DTB address : If appended device tree is found
 *               'NULL'         : Otherwise
 */
void *libboot_qcdt_appended(void *kernel, boot_uint32_t kernel_size, boot_uint32_t dtb_offset, void *tags)
{
    void *kernel_end = kernel + kernel_size;
    boot_uint32_t app_dtb_offset = 0;
    void *dtb = NULL;
    void *bestmatch_tag = NULL;
    dt_entry_t *best_match_dt_entry = NULL;
    boot_uint32_t bestmatch_tag_size;
    dt_entry_node_t *dt_entry_queue = NULL;
    dt_entry_node_t *dt_node_tmp1 = NULL;
    dt_entry_node_t *dt_node_tmp2 = NULL;


    /* Initialize the dtb entry node*/
    dt_entry_queue = (dt_entry_node_t *)
                     libboot_alloc(sizeof(dt_entry_node_t));

    if (!dt_entry_queue) {
        LOGE("Out of memory\n");
        return NULL;
    }
    libboot_list_initialize(&dt_entry_queue->node);

    if (dtb_offset)
        app_dtb_offset = dtb_offset;
    else
        libboot_platform_memmove((void *) &app_dtb_offset, (void *) (kernel + DTB_OFFSET), sizeof(boot_uint32_t));

    if (((uintptr_t)kernel + (uintptr_t)app_dtb_offset) < (uintptr_t)kernel) {
        return NULL;
    }
    dtb = kernel + app_dtb_offset;
    while (((uintptr_t)dtb + sizeof(fdt_header_t)) < (uintptr_t)kernel_end) {
        fdt_header_t dtb_hdr;
        boot_uint32_t dtb_size;

        /* the DTB could be unaligned, so extract the header,
         * and operate on it separately */
        libboot_platform_memmove(&dtb_hdr, dtb, sizeof(fdt_header_t));
        if (fdt_check_header((const void *)&dtb_hdr) != 0 ||
                ((uintptr_t)dtb + (uintptr_t)fdt_totalsize((const void *)&dtb_hdr) < (uintptr_t)dtb) ||
                ((uintptr_t)dtb + (uintptr_t)fdt_totalsize((const void *)&dtb_hdr) > (uintptr_t)kernel_end))
            break;
        dtb_size = fdt_totalsize(&dtb_hdr);

        if (check_aboot_addr_range_overlap((boot_uint32_t)tags, dtb_size)) {
            LOGE("Tags addresses overlap with aboot addresses.\n");
            return NULL;
        }

        devtree_add_compatible_entries(dtb, dtb_size, dt_entry_queue);

        /* goto the next device tree if any */
        dtb += dtb_size;
    }

    best_match_dt_entry = devtree_get_best_entry(dt_entry_queue);
    if (best_match_dt_entry) {
        bestmatch_tag = (void *)best_match_dt_entry->offset;
        bestmatch_tag_size = best_match_dt_entry->size;
        LOGI("Best match DTB tags %u/%08x/0x%08x/%x/%x/%x/%x/%x/%x/%x\n",
             best_match_dt_entry->platform_id, best_match_dt_entry->variant_id,
             best_match_dt_entry->board_hw_subtype, best_match_dt_entry->soc_rev,
             best_match_dt_entry->pmic_rev[0], best_match_dt_entry->pmic_rev[1],
             best_match_dt_entry->pmic_rev[2], best_match_dt_entry->pmic_rev[3],
             best_match_dt_entry->offset, best_match_dt_entry->size);
        LOGI("Using pmic info 0x%0x/0x%x/0x%x/0x%0x for device 0x%0x/0x%x/0x%x/0x%0x\n",
             best_match_dt_entry->pmic_rev[0], best_match_dt_entry->pmic_rev[1],
             best_match_dt_entry->pmic_rev[2], best_match_dt_entry->pmic_rev[3],
             libboot_qcdt_pmic_target(0), libboot_qcdt_pmic_target(1),
             libboot_qcdt_pmic_target(2), libboot_qcdt_pmic_target(3));
    }
    /* libboot_free queue's memory */
    libboot_list_for_every_entry(&dt_entry_queue->node, dt_node_tmp1, dt_entry_node_t, node) {
        dt_node_tmp2 = (dt_entry_node_t *) dt_node_tmp1->node.prev;
        dt_entry_list_delete(dt_node_tmp1);
        dt_node_tmp1 = dt_node_tmp2;
    }

    if (bestmatch_tag) {
        libboot_platform_memmove(tags, bestmatch_tag, bestmatch_tag_size);
        /* clear out the old DTB magic so kernel doesn't find it */
        *((boot_uint32_t *)(kernel + app_dtb_offset)) = 0;
        return tags;
    }

    LOGE("DTB offset is incorrect, kernel image does not have appended DTB\n");
    LOGE("No DTB found for the board: <%u %u 0x%x>, 0x%0x/0x%x/0x%x/0x%0x\n",
         libboot_qcdt_platform_id(),
         libboot_qcdt_hardware_id(),
         libboot_qcdt_soc_version(),
         libboot_qcdt_pmic_target(0), libboot_qcdt_pmic_target(1),
         libboot_qcdt_pmic_target(2), libboot_qcdt_pmic_target(3));

    return NULL;
}
#endif

/* Returns 0 if the device tree is valid. */
int libboot_qcdt_validate(dt_table_t *table, boot_uint32_t *dt_hdr_size)
{
    int dt_entry_size;
    boot_uint64_t hdr_size;

    /* Validate the device tree table header */
    if (table->magic != DEV_TREE_MAGIC) {
        LOGE("ERROR: Bad magic in device tree table \n");
        return -1;
    }

    if (table->version == DEV_TREE_VERSION_V1) {
        dt_entry_size = sizeof(dt_entry_v1_t);
    } else if (table->version == DEV_TREE_VERSION_V2) {
        dt_entry_size = sizeof(dt_entry_v2_t);
    } else if (table->version == DEV_TREE_VERSION_V3) {
        dt_entry_size = sizeof(dt_entry_t);
    } else {
        LOGE("ERROR: Unsupported version (%d) in DT table \n",
             table->version);
        return -1;
    }

    hdr_size = (boot_uint64_t)table->num_entries * dt_entry_size + DEV_TREE_HEADER_SIZE;

    if (hdr_size > UINT_MAX)
        return -1;
    else
        *dt_hdr_size = hdr_size & UINT_MAX;

    return 0;
}

static int devtree_entry_is_excact_match(dt_entry_t *cur_dt_entry, dt_entry_node_t *dt_list)
{
    boot_uint32_t cur_dt_hlos_ddr;
    boot_uint32_t cur_dt_hw_platform;
    boot_uint32_t cur_dt_hw_subtype;
    boot_uint32_t cur_dt_msm_id;
    dt_entry_node_t *dt_node_tmp = NULL;

    /* Platform-id
    * bit no |31     24|23  16|15   0|
    *        |reserved|foundry-id|msm-id|
    */
    cur_dt_msm_id = (cur_dt_entry->platform_id & 0x0000ffff);
    cur_dt_hw_platform = (cur_dt_entry->variant_id & 0x000000ff);
    cur_dt_hw_subtype = (cur_dt_entry->board_hw_subtype & 0xff);

    /* Determine the bits 10:8 to check the DT with the DDR Size */
    cur_dt_hlos_ddr = (cur_dt_entry->board_hw_subtype & 0x700);

    /* 1. must match the msm_id, platform_hw_id, platform_subtype and DDR size
    *  soc, board major/minor, pmic major/minor must less than board info
    *  2. find the matched DTB then return 1
    *  3. otherwise return 0
    */
    if ((cur_dt_msm_id == (libboot_qcdt_platform_id() & 0x0000ffff)) &&
            (cur_dt_hw_platform == libboot_qcdt_hardware_id()) &&
            (cur_dt_hw_subtype == libboot_qcdt_hardware_subtype()) &&
            (cur_dt_hlos_ddr == (libboot_qcdt_get_hlos_subtype() & 0x700)) &&
            (cur_dt_entry->soc_rev <= libboot_qcdt_soc_version()) &&
            ((cur_dt_entry->variant_id & 0x00ffff00) <= (libboot_qcdt_target_id() & 0x00ffff00)) &&
            ((cur_dt_entry->pmic_rev[0] & 0x00ffff00) <= (libboot_qcdt_pmic_target(0) & 0x00ffff00)) &&
            ((cur_dt_entry->pmic_rev[1] & 0x00ffff00) <= (libboot_qcdt_pmic_target(1) & 0x00ffff00)) &&
            ((cur_dt_entry->pmic_rev[2] & 0x00ffff00) <= (libboot_qcdt_pmic_target(2) & 0x00ffff00)) &&
            ((cur_dt_entry->pmic_rev[3] & 0x00ffff00) <= (libboot_qcdt_pmic_target(3) & 0x00ffff00))) {

        dt_node_tmp = dt_entry_list_init();
        libboot_platform_memmove((char *)dt_node_tmp->dt_entry_m,(char *)cur_dt_entry, sizeof(dt_entry_t));

        LOGV("Add DTB entry %u/%08x/0x%08x/%x/%x/%x/%x/%x/%x/%x\n",
             dt_node_tmp->dt_entry_m->platform_id, dt_node_tmp->dt_entry_m->variant_id,
             dt_node_tmp->dt_entry_m->board_hw_subtype, dt_node_tmp->dt_entry_m->soc_rev,
             dt_node_tmp->dt_entry_m->pmic_rev[0], dt_node_tmp->dt_entry_m->pmic_rev[1],
             dt_node_tmp->dt_entry_m->pmic_rev[2], dt_node_tmp->dt_entry_m->pmic_rev[3],
             dt_node_tmp->dt_entry_m->offset, dt_node_tmp->dt_entry_m->size);

        insert_dt_entry_in_queue(dt_list, dt_node_tmp);
        return 1;
    }
    return 0;
}

static int devtree_delete_incompatible_entries(dt_entry_node_t *dt_list, boot_uint32_t dtb_info)
{
    dt_entry_node_t *dt_node_tmp1 = NULL;
    dt_entry_node_t *dt_node_tmp2 = NULL;
    boot_uint32_t current_info = 0;
    boot_uint32_t board_info = 0;
    boot_uint32_t best_info = 0;
    boot_uint32_t current_pmic_model[4] = {0, 0, 0, 0};
    boot_uint32_t board_pmic_model[4] = {0, 0, 0, 0};
    boot_uint32_t best_pmic_model[4] = {0, 0, 0, 0};
    boot_uint32_t delete_current_dt = 0;
    boot_uint32_t i;

    /* start to select the exact entry
    * default to exact match 0, if find current DTB entry info is the same as board info,
    * then exact match board info.
    */
    libboot_list_for_every_entry(&dt_list->node, dt_node_tmp1, dt_entry_node_t, node) {
        if (!dt_node_tmp1) {
            LOGV("Current node is the end\n");
            break;
        }
        switch (dtb_info) {
            case DTB_FOUNDRY:
                current_info = ((dt_node_tmp1->dt_entry_m->platform_id) & 0x00ff0000);
                board_info = libboot_qcdt_foundry_id() << 16;
                break;
            case DTB_PMIC_MODEL:
                for (i = 0; i < 4; i++) {
                    current_pmic_model[i] = (dt_node_tmp1->dt_entry_m->pmic_rev[i] & 0xff);
                    board_pmic_model[i] = (libboot_qcdt_pmic_target(i) & 0xff);
                }
                break;
            case DTB_PANEL_TYPE:
                current_info = ((dt_node_tmp1->dt_entry_m->board_hw_subtype) & 0x1800);
                board_info = (libboot_qcdt_get_hlos_subtype() & 0x1800);
                break;
            case DTB_BOOT_DEVICE:
                current_info = ((dt_node_tmp1->dt_entry_m->board_hw_subtype) & 0xf0000);
                board_info = (libboot_qcdt_get_hlos_subtype() & 0xf0000);
                break;
            default:
                LOGE("ERROR: Unsupported version (%d) in dt node check \n",
                     dtb_info);
                return 0;
        }

        if (dtb_info == DTB_PMIC_MODEL) {
            if ((current_pmic_model[0] == board_pmic_model[0]) &&
                    (current_pmic_model[1] == board_pmic_model[1]) &&
                    (current_pmic_model[2] == board_pmic_model[2]) &&
                    (current_pmic_model[3] == board_pmic_model[3])) {

                for (i = 0; i < 4; i++) {
                    best_pmic_model[i] = current_pmic_model[i];
                }
                break;
            }
        } else {
            if (current_info == board_info) {
                best_info = current_info;
                break;
            }
        }
    }

    libboot_list_for_every_entry(&dt_list->node, dt_node_tmp1, dt_entry_node_t, node) {
        if (!dt_node_tmp1) {
            LOGV("Current node is the end\n");
            break;
        }
        switch (dtb_info) {
            case DTB_FOUNDRY:
                current_info = ((dt_node_tmp1->dt_entry_m->platform_id) & 0x00ff0000);
                break;
            case DTB_PMIC_MODEL:
                for (i = 0; i < 4; i++) {
                    current_pmic_model[i] = (dt_node_tmp1->dt_entry_m->pmic_rev[i] & 0xff);
                }
                break;
            case DTB_PANEL_TYPE:
                current_info = ((dt_node_tmp1->dt_entry_m->board_hw_subtype) & 0x1800);
                break;
            case DTB_BOOT_DEVICE:
                current_info = ((dt_node_tmp1->dt_entry_m->board_hw_subtype) & 0xf0000);
                break;
            default:
                LOGE("ERROR: Unsupported version (%d) in dt node check \n",
                     dtb_info);
                return 0;
        }

        if (dtb_info == DTB_PMIC_MODEL) {
            if ((current_pmic_model[0] != best_pmic_model[0]) ||
                    (current_pmic_model[1] != best_pmic_model[1]) ||
                    (current_pmic_model[2] != best_pmic_model[2]) ||
                    (current_pmic_model[3] != best_pmic_model[3])) {

                delete_current_dt = 1;
            }
        } else {
            if (current_info != best_info) {
                delete_current_dt = 1;
            }
        }

        if (delete_current_dt) {
            LOGV("Delete don't fit DTB entry %u/%08x/0x%08x/%x/%x/%x/%x/%x/%x/%x\n",
                 dt_node_tmp1->dt_entry_m->platform_id, dt_node_tmp1->dt_entry_m->variant_id,
                 dt_node_tmp1->dt_entry_m->board_hw_subtype, dt_node_tmp1->dt_entry_m->soc_rev,
                 dt_node_tmp1->dt_entry_m->pmic_rev[0], dt_node_tmp1->dt_entry_m->pmic_rev[1],
                 dt_node_tmp1->dt_entry_m->pmic_rev[2], dt_node_tmp1->dt_entry_m->pmic_rev[3],
                 dt_node_tmp1->dt_entry_m->offset, dt_node_tmp1->dt_entry_m->size);

            dt_node_tmp2 = (dt_entry_node_t *) dt_node_tmp1->node.prev;
            dt_entry_list_delete(dt_node_tmp1);
            dt_node_tmp1 = dt_node_tmp2;
            delete_current_dt = 0;
        }
    }

    return 1;
}

static int devtree_delete_incompatible_entries2(dt_entry_node_t *dt_list, boot_uint32_t dtb_info)
{
    dt_entry_node_t *dt_node_tmp1 = NULL;
    dt_entry_node_t *dt_node_tmp2 = NULL;
    boot_uint32_t current_info = 0;
    boot_uint32_t board_info = 0;
    boot_uint32_t best_info = 0;

    /* start to select the best entry*/
    libboot_list_for_every_entry(&dt_list->node, dt_node_tmp1, dt_entry_node_t, node) {
        if (!dt_node_tmp1) {
            LOGV("Current node is the end\n");
            break;
        }
        switch (dtb_info) {
            case DTB_SOC:
                current_info = dt_node_tmp1->dt_entry_m->soc_rev;
                board_info = libboot_qcdt_soc_version();
                break;
            case DTB_MAJOR_MINOR:
                current_info = ((dt_node_tmp1->dt_entry_m->variant_id) & 0x00ffff00);
                board_info = (libboot_qcdt_target_id() & 0x00ffff00);
                break;
            case DTB_PMIC0:
                current_info = ((dt_node_tmp1->dt_entry_m->pmic_rev[0]) & 0x00ffff00);
                board_info = (libboot_qcdt_pmic_target(0) & 0x00ffff00);
                break;
            case DTB_PMIC1:
                current_info = ((dt_node_tmp1->dt_entry_m->pmic_rev[1]) & 0x00ffff00);
                board_info = (libboot_qcdt_pmic_target(1) & 0x00ffff00);
                break;
            case DTB_PMIC2:
                current_info = ((dt_node_tmp1->dt_entry_m->pmic_rev[2]) & 0x00ffff00);
                board_info = (libboot_qcdt_pmic_target(2) & 0x00ffff00);
                break;
            case DTB_PMIC3:
                current_info = ((dt_node_tmp1->dt_entry_m->pmic_rev[3]) & 0x00ffff00);
                board_info = (libboot_qcdt_pmic_target(3) & 0x00ffff00);
                break;
            default:
                LOGE("ERROR: Unsupported version (%d) in dt node check \n",
                     dtb_info);
                return 0;
        }

        if (current_info == board_info) {
            best_info = current_info;
            break;
        }
        if ((current_info < board_info) && (current_info > best_info)) {
            best_info = current_info;
        }
        if (current_info < best_info) {
            LOGV("Delete don't fit DTB entry %u/%08x/0x%08x/%x/%x/%x/%x/%x/%x/%x\n",
                 dt_node_tmp1->dt_entry_m->platform_id, dt_node_tmp1->dt_entry_m->variant_id,
                 dt_node_tmp1->dt_entry_m->board_hw_subtype, dt_node_tmp1->dt_entry_m->soc_rev,
                 dt_node_tmp1->dt_entry_m->pmic_rev[0], dt_node_tmp1->dt_entry_m->pmic_rev[1],
                 dt_node_tmp1->dt_entry_m->pmic_rev[2], dt_node_tmp1->dt_entry_m->pmic_rev[3],
                 dt_node_tmp1->dt_entry_m->offset, dt_node_tmp1->dt_entry_m->size);

            dt_node_tmp2 = (dt_entry_node_t *) dt_node_tmp1->node.prev;
            dt_entry_list_delete(dt_node_tmp1);
            dt_node_tmp1 = dt_node_tmp2;
        }
    }

    libboot_list_for_every_entry(&dt_list->node, dt_node_tmp1, dt_entry_node_t, node) {
        if (!dt_node_tmp1) {
            LOGV("Current node is the end\n");
            break;
        }
        switch (dtb_info) {
            case DTB_SOC:
                current_info = dt_node_tmp1->dt_entry_m->soc_rev;
                break;
            case DTB_MAJOR_MINOR:
                current_info = ((dt_node_tmp1->dt_entry_m->variant_id) & 0x00ffff00);
                break;
            case DTB_PMIC0:
                current_info = ((dt_node_tmp1->dt_entry_m->pmic_rev[0]) & 0x00ffff00);
                break;
            case DTB_PMIC1:
                current_info = ((dt_node_tmp1->dt_entry_m->pmic_rev[1]) & 0x00ffff00);
                break;
            case DTB_PMIC2:
                current_info = ((dt_node_tmp1->dt_entry_m->pmic_rev[2]) & 0x00ffff00);
                break;
            case DTB_PMIC3:
                current_info = ((dt_node_tmp1->dt_entry_m->pmic_rev[3]) & 0x00ffff00);
                break;
            default:
                LOGE("ERROR: Unsupported version (%d) in dt node check \n",
                     dtb_info);
                return 0;
        }

        if (current_info != best_info) {
            LOGV("Delete don't fit DTB entry %u/%08x/0x%08x/%x/%x/%x/%x/%x/%x/%x\n",
                 dt_node_tmp1->dt_entry_m->platform_id, dt_node_tmp1->dt_entry_m->variant_id,
                 dt_node_tmp1->dt_entry_m->board_hw_subtype, dt_node_tmp1->dt_entry_m->soc_rev,
                 dt_node_tmp1->dt_entry_m->pmic_rev[0], dt_node_tmp1->dt_entry_m->pmic_rev[1],
                 dt_node_tmp1->dt_entry_m->pmic_rev[2], dt_node_tmp1->dt_entry_m->pmic_rev[3],
                 dt_node_tmp1->dt_entry_m->offset, dt_node_tmp1->dt_entry_m->size);

            dt_node_tmp2 = (dt_entry_node_t *) dt_node_tmp1->node.prev;
            dt_entry_list_delete(dt_node_tmp1);
            dt_node_tmp1 = dt_node_tmp2;
        }
    }
    return 1;
}

static dt_entry_t *devtree_get_best_entry(dt_entry_node_t *dt_list)
{
    dt_entry_node_t *dt_node_tmp1 = NULL;

    /* check Foundry id
    * the foundry id must exact match board founddry id, this is compatibility check,
    * if couldn't find the exact match from DTB, will exact match 0x0.
    */
    if (!devtree_delete_incompatible_entries(dt_list, DTB_FOUNDRY))
        return NULL;

    /* check PMIC model
    * the PMIC model must exact match board PMIC model, this is compatibility check,
    * if couldn't find the exact match from DTB, will exact match 0x0.
    */
    if (!devtree_delete_incompatible_entries(dt_list, DTB_PMIC_MODEL))
        return NULL;

    /* check panel type
    * the panel  type must exact match board panel type, this is compatibility check,
    * if couldn't find the exact match from DTB, will exact match 0x0.
    */
    if (!devtree_delete_incompatible_entries(dt_list, DTB_PANEL_TYPE))
        return NULL;

    /* check boot device subtype
    * the boot device subtype must exact match board boot device subtype, this is compatibility check,
    * if couldn't find the exact match from DTB, will exact match 0x0.
    */
    if (!devtree_delete_incompatible_entries(dt_list, DTB_BOOT_DEVICE))
        return NULL;

    /* check soc version
    * the suitable soc version must less than or equal to board soc version
    */
    if (!devtree_delete_incompatible_entries2(dt_list, DTB_SOC))
        return NULL;

    /*check major and minor version
    * the suitable major&minor version must less than or equal to board major&minor version
    */
    if (!devtree_delete_incompatible_entries2(dt_list, DTB_MAJOR_MINOR))
        return NULL;

    /*check pmic info
    * the suitable pmic major&minor info must less than or equal to board pmic major&minor version
    */
    if (!devtree_delete_incompatible_entries2(dt_list, DTB_PMIC0))
        return NULL;
    if (!devtree_delete_incompatible_entries2(dt_list, DTB_PMIC1))
        return NULL;
    if (!devtree_delete_incompatible_entries2(dt_list, DTB_PMIC2))
        return NULL;
    if (!devtree_delete_incompatible_entries2(dt_list, DTB_PMIC3))
        return NULL;

    libboot_list_for_every_entry(&dt_list->node, dt_node_tmp1, dt_entry_node_t, node) {
        if (!dt_node_tmp1) {
            LOGE("ERROR: Couldn't find the suitable DTB!\n");
            return NULL;
        }
        if (dt_node_tmp1->dt_entry_m)
            return dt_node_tmp1->dt_entry_m;
    }

    return NULL;
}

/* Function to obtain the index information for the correct device tree
 *  based on the platform data.
 *  If a matching device tree is found, the information is returned in the
 *  "dt_entry_info" out parameter and a function value of 0 is returned, otherwise
 *  a non-zero function value is returned.
 */
int libboot_qcdt_get_entry_info(dt_table_t *table, dt_entry_t *dt_entry_info)
{
    boot_uint32_t i;
    unsigned char *table_ptr = NULL;
    dt_entry_t dt_entry_buf_1;
    dt_entry_t *cur_dt_entry = NULL;
    dt_entry_t *best_match_dt_entry = NULL;
    dt_entry_v1_t *dt_entry_v1 = NULL;
    dt_entry_v2_t *dt_entry_v2 = NULL;
    dt_entry_node_t *dt_entry_queue = NULL;
    dt_entry_node_t *dt_node_tmp1 = NULL;
    dt_entry_node_t *dt_node_tmp2 = NULL;
    boot_uint32_t found = 0;

    if (!dt_entry_info) {
        LOGE("ERROR: Bad parameter passed to %s \n",
             __func__);
        return -1;
    }

    table_ptr = (unsigned char *)table + DEV_TREE_HEADER_SIZE;
    cur_dt_entry = &dt_entry_buf_1;
    best_match_dt_entry = NULL;
    dt_entry_queue = (dt_entry_node_t *) libboot_alloc(sizeof(dt_entry_node_t));

    if (!dt_entry_queue) {
        LOGE("Out of memory\n");
        return -1;
    }

    libboot_list_initialize(&dt_entry_queue->node);
    LOGI("DTB Total entry: %d, DTB version: %d\n", table->num_entries, table->version);
    for (i = 0; found == 0 && i < table->num_entries; i++) {
        libboot_platform_memset(cur_dt_entry, 0, sizeof(dt_entry_t));
        switch (table->version) {
            case DEV_TREE_VERSION_V1:
                dt_entry_v1 = (dt_entry_v1_t *)table_ptr;
                cur_dt_entry->platform_id = dt_entry_v1->platform_id;
                cur_dt_entry->variant_id = dt_entry_v1->variant_id;
                cur_dt_entry->soc_rev = dt_entry_v1->soc_rev;
                cur_dt_entry->board_hw_subtype = (dt_entry_v1->variant_id >> 0x18);
                cur_dt_entry->pmic_rev[0] = libboot_qcdt_pmic_target(0);
                cur_dt_entry->pmic_rev[1] = libboot_qcdt_pmic_target(1);
                cur_dt_entry->pmic_rev[2] = libboot_qcdt_pmic_target(2);
                cur_dt_entry->pmic_rev[3] = libboot_qcdt_pmic_target(3);
                cur_dt_entry->offset = dt_entry_v1->offset;
                cur_dt_entry->size = dt_entry_v1->size;
                table_ptr += sizeof(dt_entry_v1_t);
                break;
            case DEV_TREE_VERSION_V2:
                dt_entry_v2 = (dt_entry_v2_t *)table_ptr;
                cur_dt_entry->platform_id = dt_entry_v2->platform_id;
                cur_dt_entry->variant_id = dt_entry_v2->variant_id;
                cur_dt_entry->soc_rev = dt_entry_v2->soc_rev;
                /* For V2 version of DTBs we have platform version field as part
                 * of variant ID, in such case the subtype will be mentioned as 0x0
                 * As the qcom, board-id = <0xSSPMPmPH, 0x0>
                 * SS -- Subtype
                 * PM -- Platform major version
                 * Pm -- Platform minor version
                 * PH -- Platform hardware CDP/MTP
                 * In such case to make it compatible with LK algorithm move the subtype
                 * from variant_id to subtype field
                 */
                if (dt_entry_v2->board_hw_subtype == 0)
                    cur_dt_entry->board_hw_subtype = (cur_dt_entry->variant_id >> 0x18);
                else
                    cur_dt_entry->board_hw_subtype = dt_entry_v2->board_hw_subtype;
                cur_dt_entry->pmic_rev[0] = libboot_qcdt_pmic_target(0);
                cur_dt_entry->pmic_rev[1] = libboot_qcdt_pmic_target(1);
                cur_dt_entry->pmic_rev[2] = libboot_qcdt_pmic_target(2);
                cur_dt_entry->pmic_rev[3] = libboot_qcdt_pmic_target(3);
                cur_dt_entry->offset = dt_entry_v2->offset;
                cur_dt_entry->size = dt_entry_v2->size;
                table_ptr += sizeof(dt_entry_v2_t);
                break;
            case DEV_TREE_VERSION_V3:
                libboot_platform_memmove(cur_dt_entry, (dt_entry_t *)table_ptr,
                                         sizeof(dt_entry_t));
                /* For V3 version of DTBs we have platform version field as part
                 * of variant ID, in such case the subtype will be mentioned as 0x0
                 * As the qcom, board-id = <0xSSPMPmPH, 0x0>
                 * SS -- Subtype
                 * PM -- Platform major version
                 * Pm -- Platform minor version
                 * PH -- Platform hardware CDP/MTP
                 * In such case to make it compatible with LK algorithm move the subtype
                 * from variant_id to subtype field
                 */
                if (cur_dt_entry->board_hw_subtype == 0)
                    cur_dt_entry->board_hw_subtype = (cur_dt_entry->variant_id >> 0x18);

                table_ptr += sizeof(dt_entry_t);
                break;
            default:
                LOGE("ERROR: Unsupported version (%d) in DT table \n",
                     table->version);
                libboot_free(dt_entry_queue);
                return -1;
        }

        /* DTBs must match the platform_id, platform_hw_id, platform_subtype and DDR size.
        * The satisfactory DTBs are stored in dt_entry_queue
        */
        devtree_entry_is_excact_match(cur_dt_entry, dt_entry_queue);

    }
    best_match_dt_entry = devtree_get_best_entry(dt_entry_queue);
    if (best_match_dt_entry) {
        *dt_entry_info = *best_match_dt_entry;
        found = 1;
    }

    if (found != 0) {
        LOGI("Using DTB entry 0x%08x/%08x/0x%08x/%u for device 0x%08x/%08x/0x%08x/%u\n",
             dt_entry_info->platform_id, dt_entry_info->soc_rev,
             dt_entry_info->variant_id, dt_entry_info->board_hw_subtype,
             libboot_qcdt_platform_id(), libboot_qcdt_soc_version(),
             libboot_qcdt_target_id(), libboot_qcdt_hardware_subtype());
        if (dt_entry_info->pmic_rev[0] == 0 && dt_entry_info->pmic_rev[0] == 0 &&
                dt_entry_info->pmic_rev[0] == 0 && dt_entry_info->pmic_rev[0] == 0) {
            LOGV("No maintain pmic info in DTB, device pmic info is 0x%0x/0x%x/0x%x/0x%0x\n",
                 libboot_qcdt_pmic_target(0), libboot_qcdt_pmic_target(1),
                 libboot_qcdt_pmic_target(2), libboot_qcdt_pmic_target(3));
        } else {
            LOGI("Using pmic info 0x%0x/0x%x/0x%x/0x%0x for device 0x%0x/0x%x/0x%x/0x%0x\n",
                 dt_entry_info->pmic_rev[0], dt_entry_info->pmic_rev[1],
                 dt_entry_info->pmic_rev[2], dt_entry_info->pmic_rev[3],
                 libboot_qcdt_pmic_target(0), libboot_qcdt_pmic_target(1),
                 libboot_qcdt_pmic_target(2), libboot_qcdt_pmic_target(3));
        }
        return 0;
    }

    LOGE("ERROR: Unable to find suitable device tree for device (%u/0x%08x/0x%08x/%u)\n",
         libboot_qcdt_platform_id(), libboot_qcdt_soc_version(),
         libboot_qcdt_target_id(), libboot_qcdt_hardware_subtype());

    libboot_list_for_every_entry(&dt_entry_queue->node, dt_node_tmp1, dt_entry_node_t, node) {
        /* libboot_free node memory */
        dt_node_tmp2 = (dt_entry_node_t *) dt_node_tmp1->node.prev;
        dt_entry_list_delete(dt_node_tmp1);
        dt_node_tmp1 = dt_node_tmp2;
    }
    libboot_free(dt_entry_queue);
    return -1;
}
