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

#define ATT_MAX_KEYSZ 4096
#define TEE_SHA256_HASH_SIZE 32

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
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
