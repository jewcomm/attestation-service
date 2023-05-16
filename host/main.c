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

// test init -i 1234567890123456 -a 12.54.34.54 -p 123

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <attestation_service_ta.h>

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = ATTESTATION_SERVICE_UUID;
	uint32_t err_origin;
	uint32_t commanId;

	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));

	if(argc == 1){
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
								TEEC_NONE, TEEC_NONE);
		commanId = TA_DEVICE_CHECK_VALUE;

	} else if(argc == 7){
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, // imei
									TEEC_VALUE_INPUT,	// port
									TEEC_MEMREF_TEMP_INPUT, // address
									TEEC_NONE);

		uint64_t imei;
		char addr[ADDRESS_BUFFER_MAX_SIZE] = "";
		uint32_t port = 0;

		commanId = TA_DEVICE_INIT_VALUE;

		for(int c = 1; c < argc; c++){
			// set imei
			if(!strcmp(argv[c], "-i")){
				imei = strtoull(argv[++c], NULL, 10);
			}
			// set addr
			if(!strcmp(argv[c], "-a")){
				strcpy(addr, argv[++c]);
			}
			// set port
			if(!strcmp(argv[c], "-p")){
				port = strtoul(argv[++c], NULL, 10);
			}
		}
		printf("IMEI: %llu\n", imei);
		printf("ADDR: %s\n", addr);
		printf("PORT: %lu\n", port);

		if(!imei || !port || !strcmp(addr, "")){
			printf("ERROR PARAMETERS\n");
			return 0;
		}

		op.params[0].value.a = (uint32_t)imei;
		op.params[0].value.b = (uint32_t)(imei >> 32);

		printf("IMEI(a): %lx\n", op.params[0].value.a);
		printf("IMEI(b): %lx\n", op.params[0].value.b);

		op.params[1].value.a = port;

		op.params[2].tmpref.buffer = addr;
		op.params[2].tmpref.size = ADDRESS_BUFFER_MAX_SIZE;
	} else return 0;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/*
	 * Open a session to the "hello world" TA, the TA will print "hello
	 * world!" in the log when the session is created.
	 */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	/*
	 * Execute a function in the TA by invoking it, in this case
	 * we're incrementing a number.
	 *
	 * The value of command ID part and how the parameters are
	 * interpreted is part of the interface provided by the TA.
	 */

	/*
	 * TA_HELLO_WORLD_CMD_INC_VALUE is the actual function in the TA to be
	 * called.
	 */
	res = TEEC_InvokeCommand(&sess, commanId, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 *
	 * The TA will print "Goodbye!" in the log when the
	 * session is closed.
	 */

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
