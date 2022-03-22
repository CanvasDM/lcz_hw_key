#
# Copyright (c) 2022 Laird Connectivity
#
# SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
#

# Building TFM requires Cmake 3.15.
cmake_minimum_required(VERSION 3.15)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(lcz_hw_key)

target_sources(app PRIVATE src/main.c)
