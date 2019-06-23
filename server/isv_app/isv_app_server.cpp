/*
 *   Copyright(C) 2011-2018 Intel Corporation All Rights Reserved.
 *
 *   The source code, information  and  material ("Material") contained herein is
 *   owned  by Intel Corporation or its suppliers or licensors, and title to such
 *   Material remains  with Intel Corporation  or its suppliers or licensors. The
 *   Material  contains proprietary information  of  Intel or  its  suppliers and
 *   licensors. The  Material is protected by worldwide copyright laws and treaty
 *   provisions. No  part  of  the  Material  may  be  used,  copied, reproduced,
 *   modified, published, uploaded, posted, transmitted, distributed or disclosed
 *   in any way  without Intel's  prior  express written  permission. No  license
 *   under  any patent, copyright  or  other intellectual property rights  in the
 *   Material  is  granted  to  or  conferred  upon  you,  either  expressly,  by
 *   implication, inducement,  estoppel or  otherwise.  Any  license  under  such
 *   intellectual  property  rights must  be express  and  approved  by  Intel in
 *   writing.
 *
 *   *Third Party trademarks are the property of their respective owners.
 *
 *   Unless otherwise  agreed  by Intel  in writing, you may not remove  or alter
 *   this  notice or  any other notice embedded  in Materials by Intel or Intel's
 *   suppliers or licensors in any way.
 *
 */

// This sample is confined to the communication between a SGX client platform
// and an ISV Application Server.  Refer to Intel IAS documentation for
// communication between the ISV Application Server and Intel's IAS (Intel
// Attestation Server).


#include <stdio.h>
#include <limits.h>
// Needed for definition of remote attestation messages.
#include "remote_attestation_result.h"

#include "isv_enclave_u.h"

// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"

// Needed to get service provider's information, in your real project, you will
// need to talk to real server.
#include "network_ra.h"

// Needed to create enclave and do ecall.
#include "sgx_urts.h"

// Needed to query extended epid group id.
#include "sgx_uae_service.h"

#include "service_provider.h"

//add by dxl for share memory
#include <windows.h>  


#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

// In addition to generating and sending messages, this application
// can use pre-generated messages to verify the generation of
// messages and the information flow.
#include "sample_messages.h"


#ifdef _MSC_VER
#define ENCLAVE_PATH "isv_enclave.signed.dll"
#else
#define ENCLAVE_PATH "isv_enclave.signed.so"
#endif

uint8_t* msg1_samples[] = { msg1_sample1, msg1_sample2 };
uint8_t* msg2_samples[] = { msg2_sample1, msg2_sample2 };
uint8_t* msg3_samples[] = { msg3_sample1, msg3_sample2 };
uint8_t* attestation_msg_samples[] =
    { attestation_msg_sample1, attestation_msg_sample2};

// Some utility functions to output some of the data structures passed between
// the ISV app and the remote attestation service provider.
void PRINT_BYTE_ARRAY(
    FILE *file, void *mem, uint32_t len)
{
    if(!mem || !len)
    {
        fprintf(file, "\n( null )\n");
        return;
    }
    uint8_t *array = (uint8_t *)mem;
    fprintf(file, "%u bytes:\n{\n", len);
    uint32_t i = 0;
    for(i = 0; i < len - 1; i++)
    {
        fprintf(file, "0x%x, ", array[i]);
        if(i % 8 == 7) fprintf(file, "\n");
    }
    fprintf(file, "0x%x ", array[i]);
    fprintf(file, "\n}\n");
}


void PRINT_ATTESTATION_SERVICE_RESPONSE(
    FILE *file,
    ra_samp_response_header_t *response)
{
    if(!response)
    {
        fprintf(file, "\t\n( null )\n");
        return;
    }

    fprintf(file, "RESPONSE TYPE:   0x%x\n", response->type);
    fprintf(file, "RESPONSE STATUS: 0x%x 0x%x\n", response->status[0],
            response->status[1]);
    fprintf(file, "RESPONSE BODY SIZE: %u\n", response->size);

    if(response->type == TYPE_RA_MSG2)
    {
        sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)(response->body);

        fprintf(file, "MSG2 gb - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->g_b), sizeof(p_msg2_body->g_b));

        fprintf(file, "MSG2 spid - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->spid), sizeof(p_msg2_body->spid));

        fprintf(file, "MSG2 quote_type : %hx\n", p_msg2_body->quote_type);

        fprintf(file, "MSG2 kdf_id : %hx\n", p_msg2_body->kdf_id);

        fprintf(file, "MSG2 sign_gb_ga - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sign_gb_ga),
                         sizeof(p_msg2_body->sign_gb_ga));

        fprintf(file, "MSG2 mac - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->mac), sizeof(p_msg2_body->mac));

        fprintf(file, "MSG2 sig_rl - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sig_rl),
                         p_msg2_body->sig_rl_size);
    }
    else if(response->type == TYPE_RA_ATT_RESULT)
    {
        sample_ra_att_result_msg_t *p_att_result =
            (sample_ra_att_result_msg_t *)(response->body);
        fprintf(file, "ATTESTATION RESULT MSG platform_info_blob - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->platform_info_blob),
                         sizeof(p_att_result->platform_info_blob));

        fprintf(file, "ATTESTATION RESULT MSG mac - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->mac), sizeof(p_att_result->mac));

        fprintf(file, "ATTESTATION RESULT MSG secret.payload_tag - %u bytes\n",
                p_att_result->secret.payload_size);

        fprintf(file, "ATTESTATION RESULT MSG secret.payload - ");
        PRINT_BYTE_ARRAY(file, p_att_result->secret.payload,
                p_att_result->secret.payload_size);
    }
    else
    {
        fprintf(file, "\nERROR in printing out the response. "
                       "Response of type not supported %d\n", response->type);
    }
}

// This sample code doesn't have any recovery/retry mechanisms for the remote
// attestation. Since the enclave can be lost due S3 transitions, apps
// susceptible to S3 transitions should have logic to restart attestation in
// these scenarios.
#include <TCHAR.H>
//add by dxl
HANDLE lhShareMemory;
HANDLE controlMemory;
LPVOID buff;
LPVOID controlbuff;//0 server 1client

void share_init()
{
	lhShareMemory = OpenFileMapping(FILE_MAP_ALL_ACCESS, false, _T("TestFileMap")); //打开共享文件
	controlMemory = OpenFileMapping(FILE_MAP_ALL_ACCESS, false, _T("controlTestFileMap")); //打开共享文件
	if (NULL == lhShareMemory)
	{
		lhShareMemory = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, _T("TestFileMap"));
		controlMemory = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 1024, _T("controlTestFileMap")); //打开共享文件
	}
	buff = MapViewOfFile(lhShareMemory, FILE_MAP_WRITE, 0, 0, 0); // 获取映射对象地址  
	controlbuff = MapViewOfFile(controlMemory, FILE_MAP_WRITE, 0, 0, 0); // 获取映射对象地址  
	char str[2] = "1";
	CopyMemory((PVOID)controlbuff, str, 1024);
}

void share_send(char * send)
{
	char * str = (char *)controlbuff;
	if (str[0] == '1') {
		//error
		exit(1);
	}
	CopyMemory((PVOID)buff, send, 4096); // 写入数据 
	char str1[2]  = "1";
	strcpy((char*)controlbuff, str1);
}

void share_receive()
{
	char * str = (char *)controlbuff;
	while (str[0] == '1') {
		Sleep(1000);
		printf("\nwait for client!!!\n");
	}
	printf("\nmessage received\n");
}

void share_destory()
{
	UnmapViewOfFile((PVOID)buff);
	UnmapViewOfFile((PVOID)controlbuff);
	CloseHandle(lhShareMemory);
	CloseHandle(controlMemory);
}

#ifdef _MSC_VER
#include <TCHAR.H>
int _tmain(int argc, _TCHAR *argv[])
#else
#define _T(x) x
int main(int argc, char* argv[])
#endif
{
    int ret = 0;
    ra_samp_request_header_t *p_msg0_full = NULL;
    ra_samp_response_header_t *p_msg0_resp_full = NULL;
    ra_samp_request_header_t *p_msg1_full = NULL;
    ra_samp_response_header_t *p_msg2_full = NULL;
    sgx_ra_msg3_t *p_msg3 = NULL;
    ra_samp_response_header_t* p_att_result_msg_full = NULL;
    sgx_enclave_id_t enclave_id = 0;
    int enclave_lost_retry_time = 1;
//    int busy_retry_time = 4;
    sgx_ra_context_t context = INT_MAX;
    sgx_status_t status = SGX_SUCCESS;
    ra_samp_request_header_t* p_msg3_full = NULL;

    int32_t verify_index = -1;
    int32_t verification_samples = sizeof(msg1_samples)/sizeof(msg1_samples[0]);

    FILE* OUTPUT = stdout;

#define VERIFICATION_INDEX_IS_VALID() (verify_index > 0 && \
                                       verify_index <= verification_samples)
#define GET_VERIFICATION_ARRAY_INDEX() (verify_index-1)

    if(argc > 1)
    {

#ifdef _MSC_VER
        verify_index = _ttoi(argv[1]);
#else
        verify_index = atoi(argv[1]);
#endif

        if( VERIFICATION_INDEX_IS_VALID())
        {
            fprintf(OUTPUT, "\nVerifying precomputed attestation messages "
                            "using precomputed values# %d\n", verify_index);
        }
        else
        {
            fprintf(OUTPUT, "\nValid invocations are:\n");
            fprintf(OUTPUT, "\n\tisv_app\n");
            fprintf(OUTPUT, "\n\tisv_app <verification index>\n");
            fprintf(OUTPUT, "\nValid indices are [1 - %d]\n",
                    verification_samples);
            fprintf(OUTPUT, "\nUsing a verification index uses precomputed "
                    "messages to assist debugging the remote attestation "
                    "service provider.\n");
            return -1;
        }
    }
	

	// Preparation for receive msg0
	share_init();
	share_receive();
	p_msg0_full = (ra_samp_request_header_t *)buff;
	p_msg0_resp_full = (ra_samp_response_header_t*)
		malloc(sizeof(ra_samp_response_header_t)
			+ sizeof(uint32_t));

	fprintf(OUTPUT, "\n\n*********************receive MSG0******************************\n\n");

	PRINT_BYTE_ARRAY(OUTPUT, p_msg0_full,
		(uint32_t)sizeof(ra_samp_request_header_t)
		+ p_msg0_full->size);
	fprintf(OUTPUT, "\n\n*********************receive MSG0 end**************************\n\n");


	ret = ra_network_send_receive("http://SampleServiceProvider.intel.com/",
		p_msg0_full,
		&p_msg0_resp_full);

	share_send((char *)p_msg0_resp_full);
	
	printf("\nsend msg0 response\n");
	

    // Remote attestation will be initiated the ISV server challenges the ISV
    // app or if the ISV app detects it doesn't have the credentials
    // (shared secret) from a previous attestation required for secure
    // communication with the server.
    {
        // ISV application creates the ISV enclave.
		share_receive();
		p_msg1_full = (ra_samp_request_header_t *)buff;
		p_msg2_full = (ra_samp_response_header_t*)
			malloc(sizeof(ra_samp_response_header_t)
				+ sizeof(uint32_t));

		fprintf(OUTPUT, "\n\n*********************receive MSG1******************************\n\n");

		PRINT_BYTE_ARRAY(OUTPUT, p_msg1_full,
			(uint32_t)sizeof(ra_samp_request_header_t)
			+ p_msg1_full->size);
		fprintf(OUTPUT, "\n\n*********************receive MSG1 end**************************\n\n");




        ret = ra_network_send_receive("http://SampleServiceProvider.intel.com/",
                                      p_msg1_full,
                                      &p_msg2_full);
		share_send((char *)p_msg2_full);

		{ // creates the cryptserver enclave.
			uint32_t extended_epid_group_id = 0;
			ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);

			if (SGX_SUCCESS != ret)
			{
				ret = -1;
				fprintf(OUTPUT, "\nError, call sgx_get_extended_epid_group_id fail [%s].",
					__FUNCTION__);
				return ret;
			}
			fprintf(OUTPUT, "\nCall sgx_get_extended_epid_group_id success.");

			int launch_token_update = 0;
			sgx_launch_token_t launch_token = { 0 };
			memset(&launch_token, 0, sizeof(sgx_launch_token_t));
			do
			{
				ret = sgx_create_enclave(_T(ENCLAVE_PATH),
					SGX_DEBUG_FLAG,
					&launch_token,
					&launch_token_update,
					&enclave_id, NULL);
				if (SGX_SUCCESS != ret)
				{
					ret = -1;
					fprintf(OUTPUT, "\nError, call sgx_create_enclave fail [%s].",
						__FUNCTION__);

				}
				fprintf(OUTPUT, "\nCall sgx_create_enclave success.");

				ret = enclave_init_ra(enclave_id,
					&status,
					false,
					&context);
				//Ideally, this check would be around the full attestation flow.
			} while (SGX_ERROR_ENCLAVE_LOST == ret && enclave_lost_retry_time--);

			if (SGX_SUCCESS != ret || status)
			{
				ret = -1;
				fprintf(OUTPUT, "\nError, call enclave_init_ra fail [%s].",
					__FUNCTION__);

			}
			fprintf(OUTPUT, "\nCall enclave_init_ra success.");
		}


		printf("\nsend msg2 (msg1 response)\n");


        // The ISV application sends msg3 to the SP to get the attestation
        // result message, attestation result message needs to be freed when
        // no longer needed. The ISV service provider decides whether to use
        // linkable or unlinkable signatures. The format of the attestation
        // result is up to the service provider. This format is used for
        // demonstration.  Note that the attestation result message makes use
        // of both the MK for the MAC and the SK for the secret. These keys are
        // established from the SIGMA secure channel binding.
		share_receive();
		p_msg3_full = (ra_samp_request_header_t *)buff;

		fprintf(OUTPUT, "\n\n*********************receive MSG3******************************\n\n");

		PRINT_BYTE_ARRAY(OUTPUT, p_msg3_full,
			(uint32_t)sizeof(ra_samp_request_header_t)
			+ p_msg3_full->size);
		fprintf(OUTPUT, "\n\n*********************receive MSG3 end**************************\n\n");


		p_att_result_msg_full = (ra_samp_response_header_t*)
			malloc(sizeof(ra_samp_response_header_t)
				+ sizeof(uint32_t));
		ret = ra_network_send_receive("http://SampleServiceProvider.intel.com/",
			p_msg3_full,
			&p_att_result_msg_full);
		share_send((char *)p_att_result_msg_full);
		printf("\nsend msg4 (msg3 response)\n");
       
    }
	{
		share_receive();
		sgx_rsa3072_public_key_t *pub_key;
	
		{

			pub_key = (sgx_rsa3072_public_key_t*)malloc(sizeof(sgx_rsa3072_public_key_t));
			ret = rsa_public_key_gen(enclave_id,
				&status,
				pub_key);
			/*for (int i = 0; i < 5; i++) {
				printf("0x%02x\n", *((uint8_t*)pub_key + i));
			}*/
			if ((SGX_SUCCESS != ret))
			{
				fprintf(OUTPUT, "\n11111Error, attestation result message secret "
					"using SK based AESGCM failed in [%s]. ret = "
					"0x%0x. status = 0x%0x", __FUNCTION__, ret,
					status);
				
			}
		}
		
		share_send((char *)pub_key);
		share_receive();
		

		
		sgx_rsa3072_signature_t *p_signature;
	
		{
			char data[12] = "hello world";
			p_signature = (sgx_rsa3072_signature_t*)malloc(sizeof(sgx_rsa3072_signature_t));
			ret = rsa_sign(enclave_id,
				&status,
				(uint8_t*)&data,
				sizeof(char) * 12,
				p_signature
			);
		/*	for (int i = 0; i < 384; i++) {
			printf("0x%02x\n", *((uint8_t*)p_signature + i));
			}*/

			if ((SGX_SUCCESS != ret))
			{
				fprintf(OUTPUT, "\n22222Error, attestation result message secret "
					"using SK based AESGCM failed in [%s]. ret = "
					"0x%0x. status = 0x%0x", __FUNCTION__, ret,
					status);
				
			}
		}

		share_send((char *)p_signature);


	}


    // Clean-up
    // Need to close the RA key state.
    if(INT_MAX != context)
    {
        int ret_save = ret;
        ret = enclave_ra_close(enclave_id, &status, context);
        if(SGX_SUCCESS != ret || status)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError, call enclave_ra_close fail [%s].",
                    __FUNCTION__);
        }
        else
        {
            // enclave_ra_close was successful, let's restore the value that
            // led us to this point in the code.
            ret = ret_save;
        }
        fprintf(OUTPUT, "\nCall enclave_ra_close success.");
    }

    sgx_destroy_enclave(enclave_id);


    ra_free_network_response_buffer(p_msg0_resp_full);
    ra_free_network_response_buffer(p_msg2_full);
    ra_free_network_response_buffer(p_att_result_msg_full);
	share_destory();
    // p_msg3 is malloc'd by the untrusted KE library. App needs to free.
    SAFE_FREE(p_msg3);
    /*SAFE_FREE(p_msg3_full);
    SAFE_FREE(p_msg1_full);
    SAFE_FREE(p_msg0_full);*/
    printf("\nEnter a character before exit ...\n");
    getchar();
    return ret;
}

