#ifndef TA_ATTESTATION_SERVICE_PRIVATE_H
#define TA_ATTESTATION_SERVICE_PRIVATE_H

/* define's printing params */
#define AS_PRINT_HASH_RESULT
#define AS_PRINT_SERVER_ERROR

/* types of hash, sending on server */
#define AS_GET_TEE 		0
#define AS_GET_TA		1
#define AS_GET_SYSCALL	2

#define ATT_MAX_KEYSZ 4096

/* command for pta */
#define PTA_SYS_CALL_GETTER 2

#define MY_PTA_UUID { 0x2a38dd39, 0x3414, 0x4b58, \
		{ 0xa3, 0xbd, 0x73, 0x91, 0x8a, 0xe6, 0x2e, 0x68 } }

/* object id for trusted storage */
const char obj_id[] = "AS_Params";

/* Set if run on QEMU */
#define QEMU_RUN 

/* in QEMU after reboot dont saved data in trusted storage */
#ifdef QEMU_RUN
#define DEFINE_ADDRESS "192.168.1.70\0"
#define DEFINE_PORT 3000
#define DEFINE_IMEI 1234567890123456LLU
#endif

/* return value in normal world */
#define AS_ATTESTATION_FAILED 0xFEFEFEFE

/* defined server response */
#define SERVER_RES_FAILED 0xFFFF
#define SERVER_RES_SUCCES 0x1111
#define SERVER_RES_LENGTH 0x2

/* maximum number of measurements transmitted to the server */
#define MAX_MEAS 6

/* one measurement */
typedef struct{
	uint32_t meas_id;
	uint8_t digest[TEE_SHA256_HASH_SIZE];
} AS_Measurement;

typedef struct{
	uint64_t IMEI;

	// for simplicity equals cmd_id in TA_InvokeCommandEntryPoint
	char type_of_message; 
	
	size_t meas_length;
	AS_Measurement meas[MAX_MEAS];
} AS_Packet;

typedef struct{
	uint64_t IMEI;
	uint16_t port;
	char address[ADDRESS_BUFFER_MAX_SIZE];
} AS_TS_Conn_param;

#endif /*TA_ATTESTATION_SERVICE_PRIVATE_H*/