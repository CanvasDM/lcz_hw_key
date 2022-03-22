#
# Copyright (c) 2022 Laird Connectivity LLC
#
# SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
#
if(CONFIG_LCZ_HW_KEY)

zephyr_include_directories(include)

zephyr_sources(src/lcz_hw_key.c)

endif()
