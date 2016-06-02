LOCAL_DIR := $(GET_LOCAL_DIR)

INCLUDES += -I$(LOCAL_DIR)/include
INCLUDES += -I$(LOCAL_DIR)/include_private

OBJS += \
	$(LOCAL_DIR)/boot.o \
	$(LOCAL_DIR)/cmdline.o \
	$(LOCAL_DIR)/qcdt.o \
	$(LOCAL_DIR)/platform.o \
    \
	$(LOCAL_DIR)/loaders/android.o \
	$(LOCAL_DIR)/loaders/efi.o \
	$(LOCAL_DIR)/loaders/elf.o \
	$(LOCAL_DIR)/loaders/gzip.o \
	$(LOCAL_DIR)/loaders/qcmbn.o \
	$(LOCAL_DIR)/loaders/zimage.o \
    \
	$(LOCAL_DIR)/tagloaders/atags.o \
	$(LOCAL_DIR)/tagloaders/fdt.o \
	$(LOCAL_DIR)/tagloaders/qcdt.o \

