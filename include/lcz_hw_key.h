/**
 * @file lcz_hw_key.h
 * @brief
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */
#ifndef __LCZ_HW_KEY_H__
#define __LCZ_HW_KEY_H__

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <zephyr/types.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**************************************************************************************************/
/* Global Constants, Macros and Type Definitions                                                  */
/**************************************************************************************************/

#define LCZ_HW_KEY_IV_LEN 12
#define LCZ_HW_KEY_MAC_LEN 16

/**************************************************************************************************/
/* Global Function Prototypes                                                                     */
/**************************************************************************************************/

/**
 * @brief Generate a random initialization vector (nonce)
 *
 * @param iv_buf buffer to store the IV
 * @param iv_buf_size size of the IV buffer
 * @return int 0 on success, < 0 on error
 */
int lcz_hw_key_generate_iv(uint8_t *iv_buf, size_t iv_buf_size);

/**
 * @brief Encrypt data using the unique hardware key of the device
 *
 * @param iv_buf IV data
 * @param iv_buf_size length of the IV
 * @param ad Pointer to authenticated data
 * @param ad_len Length of authenticated data
 * @param data Data to be encrypted
 * @param data_size Length of the data to encrypt
 * @param encrypted_data_buf Data buffer to hold the encrypted data
 * @param encrypted_data_buf_size Size of the encrypted data buffer
 * @param encrypted_data_out_size Length of the encrypted data
 * @return int 0 on success, < 0 on error
 */
int lcz_hw_key_encrypt_data(const uint8_t *iv_buf, size_t iv_buf_size, const uint8_t *ad,
			    size_t ad_len, const uint8_t *data, size_t data_size,
			    uint8_t *encrypted_data_buf, size_t encrypted_data_buf_size,
			    uint32_t *encrypted_data_out_size);

/**
 * @brief Decrypt data using the unique hardware key of the device
 *
 * @param iv_buf IV data
 * @param iv_buf_size length of the IV
 * @param ad Pointer to authenticated data
 * @param ad_len Length of authenticated data
 * @param encrypted_data Encrypted data
 * @param encrypted_data_length Length of the encrypted data
 * @param data Buffer to hold the decrypted data
 * @param data_size Size of the decrypted data buffer
 * @param data_out_size Length of the decrypted data
 * @return int 0 on success, < 0 on error
 */
int lcz_hw_key_decrypt_data(const uint8_t *iv_buf, size_t iv_buf_size, const uint8_t *ad,
			    size_t ad_len, const uint8_t *encrypted_data,
			    size_t encrypted_data_length, uint8_t *data, size_t data_size,
			    uint32_t *data_out_size);

#ifdef __cplusplus
}
#endif

#endif /* __LCZ_HW_KEY_H__ */
