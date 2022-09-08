/*
 * Copyright (c) 2022 Laird Connectivity LLC
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(main, LOG_LEVEL_DBG);

#include <zephyr.h>

#include "lcz_hw_key.h"

#define PLAIN_TEXT_MAX_SIZE (100)
#define AUTH_DATA "My AUTH data"

static uint8_t plain_text[PLAIN_TEXT_MAX_SIZE] = {
	"This is an example string that will be encrypted and decrypted."
};
static uint8_t encrypted_text[PLAIN_TEXT_MAX_SIZE + LCZ_HW_KEY_MAC_LEN];
static uint8_t decrypted_text[PLAIN_TEXT_MAX_SIZE];

void main(void)
{
	uint32_t encrypted_data_size;
	uint32_t decrypted_data_size;
	uint8_t iv[LCZ_HW_KEY_IV_LEN];

	lcz_hw_key_generate_iv(iv, LCZ_HW_KEY_IV_LEN);

	lcz_hw_key_encrypt_data((const uint8_t *)iv, LCZ_HW_KEY_IV_LEN, AUTH_DATA,
				sizeof(AUTH_DATA), (const uint8_t *)plain_text, strlen(plain_text),
				encrypted_text, sizeof(encrypted_text), &encrypted_data_size);

	LOG_HEXDUMP_INF(encrypted_text, encrypted_data_size, "Encrypted data:");

	lcz_hw_key_decrypt_data((const uint8_t *)iv, LCZ_HW_KEY_IV_LEN, AUTH_DATA,
				sizeof(AUTH_DATA), (const uint8_t *)encrypted_text,
				encrypted_data_size, decrypted_text, sizeof(decrypted_text),
				&decrypted_data_size);

	LOG_INF("Decrypted data: %s", decrypted_text);
}
