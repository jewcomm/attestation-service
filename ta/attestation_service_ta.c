/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <pta_attestation.h>

#include <attestation_service_ta.h>

#include <string.h> // need for memcpy()

#include <mbedtls/x509.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net.h>

#define ATT_MAX_KEYSZ 4096
#define TEE_SHA256_HASH_SIZE 32

const unsigned char cert_pem[] = "-----BEGIN CERTIFICATE-----\n\
MIIDDzCCAfcCFGnHpUKakLk0J0PLZ/L2IRTe2JRpMA0GCSqGSIb3DQEBCwUAMEQx\n\
CzAJBgNVBAYTAlNBMQ8wDQYDVQQIDAZSaXlhZGgxDzANBgNVBAcMBlJpeWFkaDET\n\
MBEGA1UECgwKQmFyYWthdCBDQTAeFw0yMzA0MDgxMDEzMDRaFw0zMzA0MDUxMDEz\n\
MDRaMEQxCzAJBgNVBAYTAlNBMQ8wDQYDVQQIDAZSaXlhZGgxDzANBgNVBAcMBlJp\n\
eWFkaDETMBEGA1UECgwKQmFyYWthdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEP\n\
ADCCAQoCggEBAJYc9kdknFZfo9XiLnpFJOmKS9dajgm0U5+NCwi2P7JnMMkWnJ/P\n\
Jl/czSNe2M1Td8HtfA9vyYrNXyBvmGHe+Jv8KtJwak1Nv7rujhD9Auyoem/8xYlm\n\
KI6oqSpzZMiokWEMvC+qn7cd9aomrcIweB8uMRw7ROUz2Ebi036gTJ+xigA6x/3/\n\
sR6cs+ylyooPCxoCASuKyg9LWluDsd0TeoBzom+pIiu1yeF2p7Q5khJ1OKHPaDKc\n\
nPbJzYDKnYkZErwtxRGQCmm1BP2suaOLn3lxu9Kl8uIu18onRwGE1IpFcchp8Yh0\n\
bfyFslEbYw8me+mCrsTDEAprOKraGg0G3OcCAwEAATANBgkqhkiG9w0BAQsFAAOC\n\
AQEAbbHvCMNf9INcWKIVTs/U24ICUtQ7LTIC6XZKj1jaL4tyk2UUhMndxpwE3uSE\n\
sGYhzffS03vEzAEifr2slvdQILXAkDjzKwvk5SR+A6/Fo/SctmtjB+0195YWzrXK\n\
FZVxo1vxM/WC5tXe0VHTuxPpim95tr2jte0ZIocWa4x9Yj9FxRPeRQx00loP8NqC\n\
/s14+l9N/0+JbOKQGufO8Anp3bz9ZDW9eMD/p09RXO/SfF3W3QNUfVYsWXLjAYLg\n\
HpnMBiS7xj4WxcO23nSSSjqsNNqJaQJgF27+TY5IRHq4nO+u8jx4x8sC4o40cyFk\n\
L1RC/fgDgVXZ1txACd9VDuCd/Q==\n\
-----END CERTIFICATE-----\n";

TEE_UUID pta_attestation_uuid = PTA_ATTESTATION_UUID;

void error_to_IMSG(TEE_Result error){
	switch (error)
	{
	case TEE_ERROR_BAD_PARAMETERS:
		IMSG("TEE_ERROR_BAD_PARAMETERS");
		return ;

	case TEE_ERROR_SHORT_BUFFER:
		IMSG("TEE_ERROR_SHORT_BUFFER");
		return ;

	default:
		IMSG("UNDEFINED ERROR");
		return ;
	}
}

void print_buffer_hex(uint8_t * msg, size_t msg_size){
	while(msg_size){
		IMSG("%x", *msg);
		msg++;
		msg_size--;
	}
}

// void mbed_test(){
// 	static const char host[] = "127.0.0.1";
//   	static const char port[] = "1234";

// 	int status;

// 	/**
// 	 * Trust chain config; 
// 	*/
// 	mbedtls_x509_crt x509_certificate;
// 	mbedtls_x509_crt_init(&x509_certificate);

// 	if((status = mbedtls_x509_crt_parse(&x509_certificate, cert_pem, sizeof(cert_pem))) != 0){
// 		IMSG("ERROR failed to parse CA certificate: %X", status);
// 		goto quite_x509_certificate;
// 	}


// 	/**
// 	 * Entropy / randomness source and pseudorandom number generator (prng) configuration
// 	*/
// 	mbedtls_entropy_context entropy_context;
// 	mbedtls_entropy_init(&entropy_context);

// 	mbedtls_ctr_drbg_context drbg_context;
// 	mbedtls_ctr_drbg_init(&drbg_context);

// 	if((status = mbedtls_ctr_drbg_seed(&drbg_context, mbedtls_entropy_func, &entropy_context, NULL, 0)) != 0){
// 		IMSG("ERROR failed seed: %x", status);
// 		goto quite_entropy;
// 	}

// 	/**
// 	 * TLS configuration
// 	*/
// 	mbedtls_ssl_config ssl_config;
// 	mbedtls_ssl_config_init(&ssl_config);

// 	if((status = mbedtls_ssl_config_defaults(&ssl_config, MBEDTLS_SSL_IS_CLIENT, 
// 						MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0){
// 		IMSG("ERROR create config: %x", status);
// 		goto quite_ssl_config;
// 	}

// 	// Only use TLS 1.2
// 	mbedtls_ssl_conf_max_version(&ssl_config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
// 	mbedtls_ssl_conf_min_version(&ssl_config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
// 	// Only use this cipher suite
// 	static const int tls_cipher_suites[2] = {MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0};
// 	mbedtls_ssl_conf_ciphersuites(&ssl_config, tls_cipher_suites);

// 	// By limiting ourselves to TLS v1.2 and the previous cipher suites, we can compile mbedTLS without the unused ciphers
// 	// and reduce its size

// 	// Load CA certificate
// 	mbedtls_ssl_conf_ca_chain(&ssl_config, &x509_certificate, NULL);
// 	// Strictly ensure that certificates are signed by the CA
// 	mbedtls_ssl_conf_authmode(&ssl_config, MBEDTLS_SSL_VERIFY_REQUIRED);
// 	mbedtls_ssl_conf_rng(&ssl_config, mbedtls_ctr_drbg_random, &drbg_context);

// 	// TLS CONTEXT
// 	mbedtls_ssl_context ssl_context;
// 	mbedtls_ssl_init(&ssl_context);

// 	if ((status = mbedtls_ssl_setup(&ssl_context, &ssl_config)) != 0){
// 		DMSG("ERROR tls context: %s", -status);
// 		goto quite_ssl_context;
// 	}

// 	// ESTABLISH SECURE TLS CONNECTION
// 	mbedtls_net_context net_context;
// 	mbedtls_net_init(&net_context);

// 	mbedtls_ssl_set_bio(&ssl_context, &net_context, mbedtls_net_send, mbedtls_net_recv, NULL);

// 	if ((status = mbedtls_net_connect(&net_context, host, port, MBEDTLS_NET_PROTO_TCP)) != 0)
// 	{
// 		DMSG("ERROR tls connect: %s", -status);
// 		goto quite_net_context;
// 	}

// 	  // Verify that that certificate actually belongs to the host
// 	if ((status = mbedtls_ssl_set_hostname(&ssl_context, host)) != 0)
// 	{
// 		DMSG("ERROR tls set hostname: %s", -status);
// 		goto quite_close_context;
// 	}

// 	while ((status = mbedtls_ssl_handshake(&ssl_context)) != 0)
// 	{
// 		if (status != MBEDTLS_ERR_SSL_WANT_READ && status != MBEDTLS_ERR_SSL_WANT_WRITE)
// 		{
// 		DMSG("ERROR tls handshake: %s", -status);
// 		goto quite_close_context;
// 		}
// 	}

// 	if ((status = mbedtls_ssl_get_verify_result(&ssl_context)) != 0)
// 	{
// 		DMSG("ERROR tls get verifu result: %s", -status);
// 		goto quite_close_context;
// 	}

// 	// EXCHANGE SOME MESSAGES

// 	static const unsigned char write_buffer[] = "Hello world!\n";
// 	static const size_t write_buffer_length = sizeof(write_buffer) - 1; // last byte is the null terminator

// 	do
// 	{
// 		status = mbedtls_ssl_write(&ssl_context, write_buffer + status, write_buffer_length - status);

// 		if (status == 0)
// 		{
// 		break;
// 		}

// 		if (status < 0)
// 		{
// 		switch (status)
// 		{
// 		case MBEDTLS_ERR_SSL_WANT_READ:
// 		case MBEDTLS_ERR_SSL_WANT_WRITE:
// 		case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
// 		case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
// 			{
// 			continue;
// 			}
// 		default:
// 			{
// 				IMSG("ERROR ssl write: %x", status);
// 				goto quite_close_context;
// 			}
// 		}
// 		}
// 		IMSG("%d bytes sent to server", status);
// 	}
// 	while (true);

// 	do
// 	{
// 		unsigned char read_buffer[64];
// 		static const size_t read_buffer_length = sizeof(read_buffer);

// 		memset(read_buffer, 0, sizeof(read_buffer));

// 		status = mbedtls_ssl_read(&ssl_context, read_buffer, read_buffer_length);

// 		if (status == 0)
// 		{
// 		break;
// 		}

// 		if (status < 0)
// 		{
// 		switch (status)
// 		{
// 		case MBEDTLS_ERR_SSL_WANT_READ:
// 		case MBEDTLS_ERR_SSL_WANT_WRITE:
// 		case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
// 		case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
// 			{
// 			continue;
// 			}
// 		default:
// 			{
// 				IMSG("SSL read %x", status);
// 				goto quite_close_context;
// 			}
// 		}
// 		}

// 		auto line_terminator_received = false;

// 		for (auto i = 0; i < status; ++i)
// 		{
// 		if (read_buffer[i] == '\n')
// 		{
// 			line_terminator_received = true;
// 			break;
// 		}
// 		}

// 		if (line_terminator_received)
// 		{
// 		if (status > 1)
// 		{
// 			IMSG("Receive chunk '%.%s'", status -1, read_buffer);
// 		}
// 		break;
// 		}
// 		IMSG("Receive chunk '%.%s'", status -1, read_buffer);
// 	}
// 	while (true);

// 	quite_close_context:

// 	// In our protocol, the connection will be closed by the server first
// #if 0
// 	if ((status = mbedtls_ssl_close_notify(&ssl_context)) != 0)
// 	{
// 		std::fprintf(stderr, "[!] mbedtls_ssl_close_notify (-0x%X)\n", -status);
// 	}
// #endif

// 	quite_net_context:
//   		mbedtls_net_free(&net_context);

// 	quite_ssl_context:
// 		mbedtls_ssl_free(&ssl_context);

// 	quite_ssl_config:
// 		mbedtls_ssl_config_free(&ssl_config);

// 	quite_entropy:
// 		mbedtls_ctr_drbg_free(&drbg_context);
// 		mbedtls_entropy_free(&entropy_context);

// 	quite_x509_certificate:
// 		mbedtls_x509_crt_free(&x509_certificate);
// }

/**
 * @brief Return a signed hash of the TEE OS (kernel) memory and running user space TA,
 * which caller this PTA
 * 
 * @details More info in attestation.h
 * 
 * @param hash_tee	 		value PTA_ATTESTATION_HASH_TEE_MEMORY 
 * @param hash_tee_size		number of first bytes copied from the hash_tee
 * @param hash_ta	 		value PTA_ATTESTATION_HASH_TA_MEMORY 
 * @param hash_ta_size		number of first bytes copied from the hash_ta
 * 
 * @return TEE_SUCCESS      value received successfully
 * @return TEE_Result       Something failed.
 */
TEE_Result attestation_tee_ta(uint8_t * hash_tee, size_t hash_tee_size,
							uint8_t * hash_ta, size_t hash_ta_size){
	uint8_t measurement[TEE_SHA256_HASH_SIZE + ATT_MAX_KEYSZ / 8] = { };
	uint8_t nonce[4] = { 0x12, 0x34, 0x56, 0x78 };

	uint32_t param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
										TEE_PARAM_TYPE_MEMREF_OUTPUT,
										TEE_PARAM_TYPE_NONE,
										TEE_PARAM_TYPE_NONE);
	
	TEE_Param params[TEE_NUM_PARAMS];
	params[0].memref.buffer = nonce;
	params[0].memref.size = sizeof(nonce);
	params[1].memref.buffer = measurement;
	params[1].memref.size = sizeof(measurement);

	TEE_TASessionHandle pta_attestation_tee_session;
	uint32_t ret_orig = 0;

	TEE_Result res = TEE_ERROR_GENERIC;

	res = TEE_OpenTASession(&pta_attestation_uuid, 			TEE_TIMEOUT_INFINITE, 
							param_type, 					params, 
							&pta_attestation_tee_session, 	&ret_orig);

	if(res != TEE_SUCCESS){
		IMSG("Cannot open session for check tee");
		IMSG("ERROR:");
		error_to_IMSG(res);
		return res;
	}

	res = TEE_InvokeTACommand(pta_attestation_tee_session, 		TEE_TIMEOUT_INFINITE, 
							PTA_ATTESTATION_HASH_TEE_MEMORY, 	param_type, 
							params, 							&ret_orig);

	if(res != TEE_SUCCESS){
		IMSG("Cannot get tee attestation value");
		IMSG("ERROR:");
		error_to_IMSG(res);
		return res;
	}

	memcpy(hash_tee, measurement, hash_tee_size);

	res = TEE_InvokeTACommand(pta_attestation_tee_session, 	TEE_TIMEOUT_INFINITE,
							PTA_ATTESTATION_HASH_TA_MEMORY, param_type, 
							params, 						&ret_orig);

	if(res != TEE_SUCCESS){
		IMSG("Cannot get ta attestation value");
		IMSG("ERROR:");
		error_to_IMSG(res);
		return res;
	}

	memcpy(hash_ta, measurement, hash_ta_size);

	TEE_CloseTASession(pta_attestation_tee_session);

	return res;
}

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Hello World!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}

/**
 * NEED function for mbedtls_ctr_drbg_seed
 * mbedtls_entropy_func - return -0x64
 * solution from https://github.com/Mbed-TLS/mbedtls/issues/5352
*/
int f_entropy(void *data, unsigned char *output, size_t size) {
    ((void) data);
    TEE_GenerateRandom(output, size);
    return 0;
}

static TEE_Result cmd_get_timestamp(uint32_t param_types,
				TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);


	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

    int ret = 1, len;
    mbedtls_net_context server_fd;
    uint32_t flags;
    unsigned char buf[1024];
    const char *pers = "ssl_client1";

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;

	int status;

	mbedtls_x509_crt x509_certificate;
	mbedtls_x509_crt_init(&x509_certificate);

	if((status = mbedtls_x509_crt_parse(&x509_certificate, cert_pem, sizeof(cert_pem))) != 0){
		IMSG("ERROR failed to parse CA certificate: %X", -status);
		goto quite_x509_certificate;
	}

	mbedtls_entropy_context entropy_context;
	mbedtls_entropy_init(&entropy_context);

	mbedtls_ctr_drbg_context drbg_context;
	mbedtls_ctr_drbg_init(&drbg_context);

	if((status = mbedtls_ctr_drbg_seed(&drbg_context, f_entropy, &entropy_context, NULL, 0)) != 0){
		IMSG("ERROR failed seed: %x", -status);
		goto quite_entropy;
	}

	mbedtls_ssl_config ssl_config;
	// mbedtls_ssl_config_init(&ssl_config);

	// if((status = mbedtls_ssl_config_defaults(&ssl_config, MBEDTLS_SSL_IS_CLIENT, 
	// 					MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0){
	// 	IMSG("ERROR create config: %x", status);
	// 	goto quite_ssl_config;
	// }

	quite_ssl_config:
		// mbedtls_ssl_config_free(&ssl_config);

	quite_entropy:
		mbedtls_ctr_drbg_free(&drbg_context);
		mbedtls_entropy_free(&entropy_context);

	quite_x509_certificate:
 		mbedtls_x509_crt_free(&x509_certificate);

	return TEE_SUCCESS;
}

/**
 * Need enable CFG_ATTESTATION_PTA in config.mk
 * 
*/
static TEE_Result checker(void __maybe_unused *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	uint8_t hash_tee[TEE_SHA256_HASH_SIZE ] = { };
	uint8_t hash_ta[TEE_SHA256_HASH_SIZE] = { };

	TEE_Result att_tee = attestation_tee_ta(hash_tee, sizeof(hash_tee), hash_ta, sizeof(hash_ta));

	// may be unccorected printing, but this enough to understand
	IMSG("hash TEE mem = ");
	print_buffer_hex(hash_tee, sizeof(hash_tee));

	IMSG("hash TA mem = ");
	print_buffer_hex(hash_ta, sizeof(hash_ta));

	if(att_tee != TEE_SUCCESS){
		return att_tee;
	}

	return TEE_SUCCESS;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	//(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_DEVICE_CHECK_VALUE:
		return checker(sess_ctx, param_types, params);
	case TA_DEVICE_TEST_TLS:
		return cmd_get_timestamp(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
