#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <pta_attestation.h>
#include <utee_defines.h> // #define TEE_SHA256_HASH_SIZE 32

#include <tee_isocket.h>
#include <tee_tcpsocket.h>
#include <inttypes.h>

#include <attestation_service_ta.h>
#include <attestation_service_ta_private.h>

#include <string.h> // need for memcpy()

TEE_UUID pta_attestation_uuid = PTA_ATTESTATION_UUID;
TEE_UUID my_pta_uuid = MY_PTA_UUID;

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
		IMSG("%x (\'%c\')", *msg, *msg);
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
 * @param pack	 		AS_Packet with definite meas_length and `meas_id's`
 * 
 * @return TEE_SUCCESS      value received successfully
 * @return TEE_Result       Something failed.
 */
TEE_Result attestation_tee_ta(AS_Packet *pack){
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

	int counter;

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

	for(counter = 0; counter < pack->meas_length; counter++){
		switch (pack->meas[counter].meas_id)
		{
		case AS_GET_TA:
			res = TEE_InvokeTACommand(pta_attestation_tee_session, 		TEE_TIMEOUT_INFINITE, 
							PTA_ATTESTATION_HASH_TEE_MEMORY, 	param_type, 
							params, 							&ret_orig);

			if(res != TEE_SUCCESS){
				IMSG("Cannot get tee attestation value");
				IMSG("ERROR:");
				error_to_DMSG(res, 0);
				/** 
				 * if error. trying get other values and leave the buffer empty
				*/
				break;
			}

			memcpy(pack->meas[counter].digest, measurement, TEE_SHA256_HASH_SIZE);
			break;
		
		case AS_GET_TEE:
			res = TEE_InvokeTACommand(pta_attestation_tee_session, 	TEE_TIMEOUT_INFINITE,
							PTA_ATTESTATION_HASH_TA_MEMORY, param_type, 
							params, 						&ret_orig);

			if(res != TEE_SUCCESS){
				IMSG("Cannot get ta attestation value");
				IMSG("ERROR:");
				error_to_DMSG(res, 0);
				/** 
				 * if error. trying get other values and leave the buffer empty
				*/
				break;
			}

			memcpy(pack->meas[counter].digest, measurement, TEE_SHA256_HASH_SIZE);
			break;

		default:
			break;
		}
	}

	TEE_CloseTASession(pta_attestation_tee_session);

	return res;
}


/**
 * @brief Return hash of the Linux system call table
 * 
 * @details Hash calculate witout KASLR offset
 * 			This get equals digest after reboot device(if syscall not corrupted)
 * 
 * @param hash_syscall	 	buffer for saving hash. Buffer size should be TEE_SHA256_HASH_SIZE
 * 
 * @return TEE_SUCCESS      value received successfully
 * @return TEE_Result       Something failed.
 */
TEE_Result get_syscall(uint8_t *hash_syscall){
	uint32_t param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
										TEE_PARAM_TYPE_NONE,
										TEE_PARAM_TYPE_NONE,
										TEE_PARAM_TYPE_NONE);		

	TEE_Param params[TEE_NUM_PARAMS];

	params[0].memref.buffer = hash_syscall;
	params[0].memref.size = TEE_SHA256_HASH_SIZE;

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

	TEE_CloseTASession(my_pta_tee_session);

	return res;
}


/**
 * @brief Sends hash's to the server, and receiv results remote attestation
 *  
 * @param pack	 	data to send to the server. IMEI is filled from data
 * @param data		server and IMEI settings
 * 
 * @return TEE_SUCCESS      		attestation successfully
 * @return AS_ATTESTATION_FAILED	attestation failed
 * @return TEE_Result       		Something failed.
 */
TEE_Result attestation_send_recv(AS_Packet * pack, AS_TS_Conn_param * data){
	DMSG("Called send_recv func");

	TEE_Result res = TEE_ERROR_GENERIC;

	TEE_iSocketHandle ctx;
	TEE_tcpSocket_Setup setup;

	TEE_MemMove(&(pack->IMEI), &(data->IMEI), sizeof(data->IMEI));
	
	setup.ipVersion = TEE_IP_VERSION_4;
	setup.server_port = data->port;
	setup.server_addr = data->address;

	uint32_t protocolError;
	size_t sizeMsg;

	sizeMsg = sizeof(*pack);

	uint32_t rs = SERVER_RES_LENGTH;
	char receive[SERVER_RES_LENGTH + 1];

	memset(receive, 0, SERVER_RES_LENGTH + 1);

	res = TEE_tcpSocket->open(&ctx, &setup, &protocolError);
	if(res != TEE_SUCCESS){
		DMSG("Dont open tcp. Return:");
#ifdef AS_PRINT_SERVER_ERROR
		error_to_DMSG(res, protocolError);
#endif
		return res;
	}

	res = TEE_tcpSocket->send(ctx, pack, &sizeMsg, 0);
	if(res != TEE_SUCCESS){
		DMSG("Dont send tcp. Return");
#ifdef AS_PRINT_SERVER_ERROR
		error_to_DMSG(res, 0);
#endif
		return res;
	}

	res = TEE_tcpSocket->recv(ctx, receive, &rs, 100);
	if(res != TEE_SUCCESS){
		DMSG("Dont receiver tcp. Return");
#ifdef AS_PRINT_SERVER_ERROR
		error_to_DMSG(res, 0);
#endif
		return res;
	}

	DMSG("Receive: :%s", receive);

	res = TEE_tcpSocket->close(ctx);
	if(res != TEE_SUCCESS){
		DMSG("Dont close tcp. Return");
#ifdef AS_PRINT_SERVER_ERROR
		error_to_DMSG(res, 0);
#endif
		return res;
	}

	return TEE_ERROR_CANCEL;
}

/**
 * @brief Set params for attestation, call attestation functions and call send_recv_funstions
 *  
 * @param type_of_message	 	Type of attestation(init ot usual)
 * @param data					server and IMEI settings
 * 
 * @return TEE_SUCCESS      		attestation successfully
 * @return AS_ATTESTATION_FAILED	attestation failed
 * @return TEE_Result       		Something failed.
 */
static TEE_Result checker(char type_of_message, AS_TS_Conn_param data){
	AS_Packet check_result;
	memset(&check_result, 0, sizeof(check_result));

	TEE_Result res;

	check_result.IMEI = data.IMEI;
	check_result.meas_length = 3;
	check_result.meas[0].meas_id = AS_GET_TEE;
	check_result.meas[1].meas_id = AS_GET_TA;
	check_result.meas[2].meas_id = AS_GET_SYSCALL;

	res = attestation_tee_ta(&check_result);
	if(res != TEE_SUCCESS){
		IMSG("ERROR ATTESTATION TEE TA");
		/* dont return function, trying get syscall */
	}

	res = get_syscall(check_result.meas[2].digest);
		if(res != TEE_SUCCESS){
		IMSG("ERROR ATTESTATION SYSCALL");
		/* dont return function, sending zero-buffer to server */
	}

#ifdef AS_PRINT_HASH_RESULT
	// may be unccorected printing, but this enough to understand
	IMSG("hash TA mem = ");
	print_buffer_hex(check_result.meas[1].digest, TEE_SHA256_HASH_SIZE);

	IMSG("hash TEE mem = ");
	print_buffer_hex(check_result.meas[0].digest, TEE_SHA256_HASH_SIZE);

	IMSG("hash SYSCALL = ");
	print_buffer_hex(check_result.meas[2].digest, TEE_SHA256_HASH_SIZE);
#endif

	return attestation_send_recv(&check_result, &data);
}

/**
 * Need enable CFG_ATTESTATION_PTA in config.mk
*/
static TEE_Result usualy_checker(void __maybe_unused *sess_ctx, uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called usualy_checker");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	AS_TS_Conn_param data;
	data.IMEI = DEFINE_IMEI;
	data.port = DEFINE_PORT;
	char * addr = DEFINE_ADDRESS;
	TEE_MemMove(data.address, addr, strlen(addr) + 1);

	IMSG("IMEI: %llu", data.IMEI);
	IMSG("ADDR: %s", data.address);
	IMSG("PORT: %lu", data.port);

	return checker(TA_DEVICE_CHECK_VALUE, data);
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
	IMSG("Attestation service!\n");

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
	IMSG("Exit!\n");
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

	IMSG("command entry point to attestation service");
	switch (cmd_id) {
	case TA_DEVICE_CHECK_VALUE:
		return usualy_checker(sess_ctx, param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
