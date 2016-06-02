#ifndef LIB_BOOT_PLATFORM_H
#define LIB_BOOT_PLATFORM_H

#include <stdint.h>
#include <limits.h>
#include <assert.h>
#include <stdio.h>

#define LIBBOOT_FMT_UINTN "%u"
#define LIBBOOT_FMT_UINT32 "%u"
#define LIBBOOT_FMT_ADDR "%x"
#define LIBBOOT_FMT_INT "%d"

#define LIBBOOT_ASSERT assert

#define LOGV(fmt, ...) dprintf(SPEW, fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) dprintf(CRITICAL, fmt, ##__VA_ARGS__)
#define LOGI(fmt, ...) dprintf(INFO, fmt, ##__VA_ARGS__)

typedef uintptr_t boot_uintn_t;
typedef intptr_t  boot_intn_t;
typedef uint8_t   boot_uint8_t;
typedef uint16_t  boot_uint16_t;
typedef uint32_t  boot_uint32_t;
typedef uint64_t  boot_uint64_t;

boot_uint32_t libboot_qcdt_pmic_target(boot_uint8_t num_ent);
boot_uint32_t libboot_qcdt_platform_id(void);
boot_uint32_t libboot_qcdt_hardware_id(void);
boot_uint32_t libboot_qcdt_hardware_subtype(void);
boot_uint32_t libboot_qcdt_soc_version(void);
boot_uint32_t libboot_qcdt_target_id(void);
boot_uint32_t libboot_qcdt_foundry_id(void);
boot_uint32_t libboot_qcdt_get_hlos_subtype(void);

void  libboot_platform_memmove(void* dst, const void* src, boot_uintn_t num);
int   libboot_platform_memcmp(const void *s1, const void *s2, boot_uintn_t n);
void* libboot_platform_memset(void *s, int c, boot_uintn_t n);
void* libboot_platform_alloc(boot_uintn_t size);
void  libboot_platform_free(void *ptr);
void  libboot_platform_format_string(char* buf, boot_uintn_t sz, const char* fmt, ...);
char* libboot_platform_strdup(const char *s);
char* libboot_platform_strtok_r(char *str, const char *delim, char **saveptr);
char* libboot_platform_strchr(const char *s, int c);
int   libboot_platform_strcmp(const char* str1, const char* str2);
boot_uintn_t libboot_platform_strlen(const char* str);

#endif // LIB_BOOT_PLATFORM_H
