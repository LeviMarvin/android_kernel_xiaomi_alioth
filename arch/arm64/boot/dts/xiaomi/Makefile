ifeq ($(CONFIG_BUILD_ARM64_DT_OVERLAY),y)
dtbo-$(CONFIG_BOARD_XIAOMI) += \
	kona-alioth-overlay.dtbo \
	kona-apollo-overlay.dtbo \
	kona-lmi-overlay.dtbo \
	kona-munch-overlay.dtbo

kona-alioth-overlay.dtbo-base := qcom-base/kona-v2.dtb
kona-apollo-overlay.dtbo-base := qcom-base/kona-v2.dtb
kona-lmi-overlay.dtbo-base := qcom-base/kona-v2.dtb
kona-munch-overlay.dtbo-base := qcom-base/kona-v2.dtb
endif

always          := $(dtb-y)
subdir-y        := $(dts-dirs)
clean-files     := *.dtb
