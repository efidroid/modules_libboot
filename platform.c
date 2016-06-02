#include <lib/boot.h>
#include <lib/boot/internal/boot_internal.h>

#include <string.h>
#include <malloc.h>
#include <stdarg.h>
#include <board.h>
#include <atagparse.h>
#include <target.h>

boot_uint32_t libboot_qcdt_pmic_target(boot_uint8_t num_ent) {
    return board_pmic_target(num_ent);
}

boot_uint32_t libboot_qcdt_platform_id(void) {
    if(lkargs_has_board_info())
        return lkargs_get_platform_id();
    else
        return board_platform_id();
}

boot_uint32_t libboot_qcdt_hardware_id(void) {
    if(lkargs_has_board_info())
        return lkargs_get_variant_id();
    else
        return board_hardware_id();
}

boot_uint32_t libboot_qcdt_hardware_subtype(void) {
    return board_hardware_subtype();
}

boot_uint32_t libboot_qcdt_soc_version(void) {
    if(lkargs_has_board_info())
        return lkargs_get_soc_rev();
    else
        return board_soc_version();
}

boot_uint32_t libboot_qcdt_target_id(void) {
    return board_target_id();
}

boot_uint32_t libboot_qcdt_foundry_id(void) {
    return board_foundry_id();
}

boot_uint32_t libboot_qcdt_get_hlos_subtype(void) {
    return target_get_hlos_subtype();
}

void libboot_platform_memmove(void* dst, const void* src, boot_uintn_t num) {
    memmove(dst, src, num);
}

int libboot_platform_memcmp(const void *s1, const void *s2, boot_uintn_t n) {
    return memcmp(s1, s2, n);
}

void *libboot_platform_memset(void *s, int c, boot_uintn_t n) {
    return memset(s, c, n);
}

void* libboot_platform_alloc(boot_uintn_t size) {
    void* mem = malloc(size);
    if(!mem)
        libboot_format_error(LIBBOOT_ERROR_GROUP_COMMON, LIBBOOT_ERROR_COMMON_OUT_OF_MEMORY);
    return mem;
}

void libboot_platform_free(void *ptr) {
    free(ptr);
}

void libboot_platform_format_string(char* buf, boot_uintn_t sz, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sz, fmt, args);
    va_end (args);
}

char* libboot_platform_strdup(const char *s) {
    return strdup(s);
}

char* libboot_platform_strtok_r(char *str, const char *delim, char **saveptr) {
    return strtok_r(str, delim, saveptr);
}

char* libboot_platform_strchr(const char *s, int c) {
    return strchr(s, c);
}

int libboot_platform_strcmp(const char* str1, const char* str2) {
    return strcmp(str1, str2);
}

boot_uintn_t libboot_platform_strlen(const char* str) {
    return strlen(str);
}
