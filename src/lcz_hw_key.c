/**
 * @file lcz_hw_key.c
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(lcz_hw_key, CONFIG_LCZ_HW_KEY_LOG_LEVEL);

/******************************************************************************/
/* Includes                                                                   */
/******************************************************************************/
#include <zephyr.h>
#include <string.h>
#include <errno.h>
#include <init.h>
#include <hw_unique_key.h>
#include <psa/crypto.h>
#ifdef CONFIG_BUILD_WITH_TFM
#include <tfm_crypto_defs.h>
#else
#include <nrf_cc3xx_platform.h>
#endif
#if !defined(HUK_HAS_KMU)
#include <sys/reboot.h>
#endif

#include "lcz_hw_key.h"

/******************************************************************************/
/* Local Constant, Macro and Type Definitions                                 */
/******************************************************************************/
#ifdef HUK_HAS_CC310
#define ENCRYPT_ALG PSA_ALG_CCM
#else
#define ENCRYPT_ALG PSA_ALG_GCM
#endif

#ifdef HUK_HAS_KMU
#define KEYSLOT HUK_KEYSLOT_MKEK
#else
#define KEYSLOT HUK_KEYSLOT_KDR
#endif

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/
static psa_key_id_t id;

static const uint8_t key_label[] = "HUK";

/**************************************************************************************************/
/* Local Function Prototypes                                                                      */
/**************************************************************************************************/
static int lcz_hw_key_generate_and_init(const struct device *device);
static psa_key_id_t derive_key(psa_key_attributes_t *attributes, uint8_t *key_label,
			       uint32_t label_size);

/**************************************************************************************************/
/* Global Function Definitions                                                                    */
/**************************************************************************************************/
int lcz_hw_key_generate_iv(uint8_t *iv_buf, size_t iv_buf_size)
{
	int ret;
	psa_status_t s;

	ret = 0;

	s = psa_generate_random(iv_buf, iv_buf_size);
	if (s != PSA_SUCCESS) {
		LOG_ERR("Could not generate IV [%d]", s);
		ret = -EIO;
	}

	return ret;
}

int lcz_hw_key_encrypt_data(const uint8_t *iv_buf, size_t iv_buf_size, const uint8_t *ad,
			    size_t ad_len, const uint8_t *data, size_t data_size,
			    uint8_t *encrypted_data_buf, size_t encrypted_data_buf_size,
			    uint32_t *encrypted_data_out_size)
{
	int ret;
	psa_status_t s;

	ret = 0;

	s = psa_aead_encrypt(id, ENCRYPT_ALG, iv_buf, iv_buf_size, ad, ad_len, data, data_size,
			     encrypted_data_buf, encrypted_data_buf_size, encrypted_data_out_size);
	if (s != PSA_SUCCESS) {
		LOG_ERR("Could not encrypt data [%d]", s);
		ret = s;
		goto done;
	}

	if (*encrypted_data_out_size != data_size + LCZ_HW_KEY_MAC_LEN) {
		LOG_ERR("encrypted data length is unexpected: %d", *encrypted_data_out_size);
		ret = -EINVAL;
		goto done;
	}

done:
	return ret;
}

int lcz_hw_key_decrypt_data(const uint8_t *iv_buf, size_t iv_buf_size, const uint8_t *ad,
			    size_t ad_len, const uint8_t *encrypted_data,
			    size_t encrypted_data_length, uint8_t *data, size_t data_size,
			    uint32_t *data_out_size)
{
	int ret;
	psa_status_t s;

	ret = 0;

	s = psa_aead_decrypt(id, ENCRYPT_ALG, iv_buf, iv_buf_size, ad, ad_len, encrypted_data,
			     encrypted_data_length, data, data_size, data_out_size);

	if (s != PSA_SUCCESS) {
		LOG_ERR("Could not decrypt data [%d]", s);
		ret = s;
		goto done;
	}

done:
	return ret;
}

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
#if defined(CONFIG_BUILD_WITH_TFM)
psa_key_id_t derive_key(psa_key_attributes_t *attributes, uint8_t *key_label, uint32_t label_size)
{
	psa_key_id_t kid;
	psa_status_t s;
	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;

	kid = 0;

	s = psa_key_derivation_setup(&op, TFM_CRYPTO_ALG_HUK_DERIVATION);
	if (s != PSA_SUCCESS) {
		LOG_ERR("Could not setup derivation [%d]", s);
		goto done;
	}

	s = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_LABEL, key_label,
					   label_size);
	if (s != PSA_SUCCESS) {
		LOG_ERR("Could input key label [%d]", s);
		goto done;
	}

	s = psa_key_derivation_output_key(attributes, &op, &kid);
	if (s != PSA_SUCCESS) {
		LOG_ERR("Could derive key [%d]", s);
		kid = 0;
		goto done;
	}

	s = psa_key_derivation_abort(&op);
	if (s != PSA_SUCCESS) {
		LOG_ERR("Could finish key derivation [%d]", s);
		kid = 0;
		goto done;
	}
done:
	return kid;
}
#else
psa_key_id_t derive_key(psa_key_attributes_t *attributes, uint8_t *key_label, uint32_t label_size)
{
	uint8_t key[HUK_SIZE_BYTES];
	psa_key_id_t kid;
	psa_status_t s;
	int ret;

	kid = 0;

	ret = hw_unique_key_derive_key(KEYSLOT, NULL, 0, key_label, label_size, key, sizeof(key));
	if (ret != 0) {
		LOG_ERR("could not derive key [%d]", ret);
		goto done;
	}

	s = psa_import_key(attributes, key, sizeof(key), &kid);
	if (s != PSA_SUCCESS) {
		LOG_ERR("could not import key [%d]", s);
		kid = 0;
		goto done;
	}

done:
	return kid;
}
#endif

/**************************************************************************************************/
/* SYS INIT                                                                                       */
/**************************************************************************************************/
SYS_INIT(lcz_hw_key_generate_and_init, APPLICATION, CONFIG_LCZ_HW_KEY_INIT_PRIORITY);
static int lcz_hw_key_generate_and_init(const struct device *device)
{
	int ret;
	psa_status_t s;
	psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;

#if !defined(CONFIG_BUILD_WITH_TFM)
	ret = nrf_cc3xx_platform_init();
	if (ret != NRF_CC3XX_PLATFORM_SUCCESS) {
		LOG_ERR("could not init cc3xx [%d]", ret);
		ret = -EIO;
		goto done;
	}

	if (!hw_unique_key_are_any_written()) {
		LOG_INF("HUK does not exist, generate it");
		hw_unique_key_write_random();
		LOG_INF("HUK generated!");

#if !defined(HUK_HAS_KMU)
		LOG_WRN("Rebooting in %d seconds to store HUK securely",
			CONFIG_LCZ_HW_KEY_REBOOT_DELAY_SECONDS);
		k_sleep(K_SECONDS(CONFIG_LCZ_HW_KEY_REBOOT_DELAY_SECONDS));
		/* Reboot to allow the bootloader to load the key into CryptoCell. */
		sys_reboot(0);
#endif
	}
#endif

	s = psa_crypto_init();
	if (s != PSA_SUCCESS) {
		LOG_ERR("Could not init PSA crypto [%d]", s);
		ret = -EIO;
		goto done;
	}

	psa_set_key_usage_flags(&key_attr, (PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT));
	psa_set_key_algorithm(&key_attr, ENCRYPT_ALG);
	psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&key_attr, PSA_BYTES_TO_BITS(HUK_SIZE_BYTES));

	id = derive_key(&key_attr, (uint8_t *)key_label, strlen(key_label));
	if (id == 0) {
		ret = -EIO;
		goto done;
	}

	psa_reset_key_attributes(&key_attr);

done:
	return ret;
}
