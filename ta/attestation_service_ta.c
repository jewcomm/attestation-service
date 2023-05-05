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

#include <tee_isocket.h>
#include <tee_tcpsocket.h>

#include <attestation_service_ta.h>

#include <string.h> // need for memcpy()

#define ATT_MAX_KEYSZ 4096
#define TEE_SHA256_HASH_SIZE 32

#define MAX_MEAS 6

#define PTA_SYS_CALL_GETTER 2

#define PAGE_SIZE 4096

TEE_UUID pta_attestation_uuid = PTA_ATTESTATION_UUID;

#define MY_PTA_UUID { 0x2a38dd39, 0x3414, 0x4b58, \
		{ 0xa3, 0xbd, 0x73, 0x91, 0x8a, 0xe6, 0x2e, 0x68 } }

TEE_UUID my_pta_uuid = MY_PTA_UUID;

typedef struct{
	uint32_t measId;
	uint8_t measResult[32];
} measurment;


typedef struct{
	uint64_t IMEI;
	size_t measLen;
	measurment meas[MAX_MEAS];
} packet;


void error_to_DMSG(TEE_Result error, uint32_t extError){
	switch (error)
	{
	case TEE_ERROR_BAD_PARAMETERS:
		DMSG("TEE_ERROR_BAD_PARAMETERS");
		break; 
	case TEE_ERROR_SHORT_BUFFER:
		DMSG("TEE_ERROR_SHORT_BUFFER");
		break ;
	case TEE_ERROR_COMMUNICATION:
		DMSG("TEE_ERROR_COMMUNICATION");
		break;
	case TEE_ISOCKET_ERROR_TIMEOUT:
		DMSG("TEE_ISOCKET_ERROR_TIMEOUT");
		break;
	default:
		DMSG("Another return: %i", error);
		break;
	}

	switch (error)
	{
	case 0:
		return;
	case TEE_ISOCKET_ERROR_PROTOCOL:
		DMSG("TEE_ISOCKET_ERROR_PROTOCOL");
		return;
	case TEE_ISOCKET_ERROR_REMOTE_CLOSED:
		DMSG("TEE_ISOCKET_ERROR_REMOTE_CLOSED");
		return;
	case TEE_ISOCKET_ERROR_TIMEOUT:
		DMSG("TEE_ISOCKET_ERROR_TIMEOUT");
		return;
	case TEE_ISOCKET_ERROR_OUT_OF_RESOURCES:
		DMSG("TEE_ISOCKET_ERROR_OUT_OF_RESOURCES");
		return;		
	case TEE_ISOCKET_ERROR_LARGE_BUFFER:
		DMSG("TEE_ISOCKET_ERROR_LARGE_BUFFER");
		return;	
	case TEE_ISOCKET_WARNING_PROTOCOL:
		DMSG("TEE_ISOCKET_WARNING_PROTOCOL");
		return;
	case TEE_ISOCKET_ERROR_HOSTNAME:
		DMSG("TEE_ISOCKET_ERROR_HOSTNAME");
		return;
	default:
		DMSG("Another return: %i", error);
		return;
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
		error_to_DMSG(res, 0);
		return res;
	}

	res = TEE_InvokeTACommand(pta_attestation_tee_session, 		TEE_TIMEOUT_INFINITE, 
							PTA_ATTESTATION_HASH_TEE_MEMORY, 	param_type, 
							params, 							&ret_orig);

	if(res != TEE_SUCCESS){
		IMSG("Cannot get tee attestation value");
		IMSG("ERROR:");
		error_to_DMSG(res, 0);
		return res;
	}

	memcpy(hash_tee, measurement, hash_tee_size);

	res = TEE_InvokeTACommand(pta_attestation_tee_session, 	TEE_TIMEOUT_INFINITE,
							PTA_ATTESTATION_HASH_TA_MEMORY, param_type, 
							params, 						&ret_orig);

	if(res != TEE_SUCCESS){
		IMSG("Cannot get ta attestation value");
		IMSG("ERROR:");
		error_to_DMSG(res, 0);
		return res;
	}

	memcpy(hash_ta, measurement, hash_ta_size);

	TEE_CloseTASession(pta_attestation_tee_session);

	return res;
}

TEE_Result get_syscall(){

	uint32_t param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
										TEE_PARAM_TYPE_NONE,
										TEE_PARAM_TYPE_NONE,
										TEE_PARAM_TYPE_NONE);		

	TEE_Param params[TEE_NUM_PARAMS];

	TEE_TASessionHandle my_pta_tee_session;
	uint32_t ret_orig = 0;	

	TEE_Result res = TEE_ERROR_GENERIC;

	res = TEE_OpenTASession(&my_pta_uuid, 			TEE_TIMEOUT_INFINITE, 
							param_type, 					params, 
							&my_pta_tee_session, 	&ret_orig);

	if(res != TEE_SUCCESS){
		IMSG("Cannot open session for check tee");
		IMSG("ERROR:");
		error_to_DMSG(res, 0);
		return res;
	}				

	res = TEE_InvokeTACommand(my_pta_tee_session, 		TEE_TIMEOUT_INFINITE, 
							PTA_SYS_CALL_GETTER, 		param_type, 
							params, 					&ret_orig);

	if(res != TEE_SUCCESS){
		IMSG("Cannot get tee attestation value");
		IMSG("ERROR:");
		error_to_DMSG(res, 0);
		return res;
	}

	// IMSG("SYSCALL_COUNT: %ld", params[0].value.b);
	// IMSG("SYSCALL_PHYS_ADDR: %lx", params[0].value.a);

	// paddr_t	pa = (paddr_t)(params[0].value.a);
	// uint32_t size_syscall_table = params[0].value.b;

	// register_phys_mem(MEM_AREA_RAM_NSEC, pa, PAGE_SIZE);
	// unsigned long * compat_syscal_ptr = phys_to_virt(pa, MEM_AREA_RAM_NSEC, sizeof(unsigned long) * size_syscall_table);

	// IMSG("SYSCALL_ADDR_VA: %ld", compat_syscal_ptr);

	TEE_CloseTASession(my_pta_tee_session);

	return res;
}

TEE_Result attestation_send_recv(uint8_t * hash_tee, uint8_t * hash_ta){
	DMSG("Called send_recv func");

	TEE_Result res = TEE_ERROR_GENERIC;

	TEE_iSocketHandle ctx;
	TEE_tcpSocket_Setup setup;
	
	setup.ipVersion = TEE_IP_VERSION_4;
	setup.server_port = 3000;
	char * addr = "192.168.1.70";
	setup.server_addr = addr;

	uint32_t protocolError;

	measurment ta;
	ta.measId = 1;
	memcpy(ta.measResult, hash_ta, 32);

	measurment tee;
	tee.measId = 2;
	memcpy(tee.measResult, hash_tee, 32);

	packet msg;
	msg.IMEI = 1234567890123456;
	msg.measLen = 2;
	memcpy(&(msg.meas[0]), &ta, sizeof(ta));
	memcpy(&(msg.meas[1]), &tee, sizeof(tee));
	size_t sizeMsg = sizeof(msg);

	// char msg[] = "Hello World!\0";
	// uint32_t sizeMsg = sizeof(msg);	
	uint32_t rs = 32;
	char receive[32];

	res = TEE_tcpSocket->open(&ctx, &setup, &protocolError);
	if(res != TEE_SUCCESS){
		DMSG("Dont open tcp. Return:");
		error_to_DMSG(res, protocolError);
		return res;
	}

	res = TEE_tcpSocket->send(ctx, &msg, &sizeMsg, 0);
	if(res != TEE_SUCCESS){
		DMSG("Dont send tcp. Return");
		error_to_DMSG(res, 0);
		return res;
	}

	res = TEE_tcpSocket->recv(ctx, receive, &rs, 100);
	if(res != TEE_SUCCESS){
		DMSG("Dont receiver tcp. Return");
		error_to_DMSG(res, 0);
		return res;
	}

	DMSG("Receive: :%s", receive);

	res = TEE_tcpSocket->close(ctx);
	if(res != TEE_SUCCESS){
		DMSG("Dont close tcp. Return");
		error_to_DMSG(res, 0);
		return res;
	}
	return TEE_SUCCESS;
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

	get_syscall();
	return TEE_SUCCESS;

	uint8_t hash_tee[TEE_SHA256_HASH_SIZE ] = { };
	uint8_t hash_ta[TEE_SHA256_HASH_SIZE] = { };

	TEE_Result att_tee = attestation_tee_ta(hash_tee, sizeof(hash_tee), hash_ta, sizeof(hash_ta));

	// may be unccorected printing, but this enough to understand
	IMSG("hash TA mem = ");
	print_buffer_hex(hash_ta, sizeof(hash_ta));

	IMSG("hash TEE mem = ");
	print_buffer_hex(hash_tee, sizeof(hash_tee));

	if(att_tee != TEE_SUCCESS){
		return att_tee;
	}

	att_tee = attestation_send_recv(hash_tee, hash_ta);
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

	IMSG("command entry point to Att SERVICE");
	switch (cmd_id) {
	case TA_DEVICE_CHECK_VALUE:
		return checker(sess_ctx, param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
