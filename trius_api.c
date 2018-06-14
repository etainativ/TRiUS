#include <stdlib.h>
#include <nanomsg/nn.h>
#include <nanomsg/reqrep.h>

#include "trius_api.h"
#include "tcpr.pb-c.h"

#define ADDRESS "tcp://localhost:54748"
#define MAX_BUFFER_SIZE 65536
int nanofd = -1;


int connect(void)
{
	if (nanofd >= 0)
		return 0;

	nanofd = nn_socket(AF_SP, NN_REP);
	if (nanofd < 0)
		return -1;

	if (nn_connect(nanofd, ADDRESS) < 0) {
		nn_close(nanofd);
		nanofd = -1;
		return nanofd;
	}

	return 0;
}

int get_init(
		struct four_tuple *four_tuple,
		struct get_init_response *response)
{
		TcprGetInit request = TCPR_GET_INIT__INIT;
		TcprGetInitResponse *resp;
		FourTuple connection = FOUR_TUPLE__INIT;	
		uint8_t resp_buf[MAX_BUFFER_SIZE];
		uint8_t *request_buf;
		size_t len;
		int res = -1;

		if (connect() < 0)
			goto finished;

		connection.local_ip = four_tuple->local_ip;
		connection.remote_ip = four_tuple->remote_ip;
		connection.local_port = four_tuple->local_port;
		connection.remote_port = four_tuple->remote_port; 
		request.connection = &connection;

		len = tcpr_get_init__get_packed_size(&request);
		request_buf = malloc(len);

		if (NULL == request_buf)
			goto finished;

		if (tcpr_get_init__pack(&request, request_buf) < 0)
			goto freerequest;
		
		if (nn_send(nanofd, request_buf, len, 0) < 0)
			goto freerequest;

		len = nn_recv(nanofd, &resp_buf, MAX_BUFFER_SIZE, 0);
		if (len < 0)
			goto freerequest;

		resp = tcpr_get_init_response__unpack(NULL, len, resp_buf);
		if (NULL == resp)
			goto freerequest;
			
		response->sack_enabled = resp->sack_enabled;
		response->max_segment_size = resp->max_segment_size;
		response->window_scaling = resp->window_scaling;
		res = 0;

freeresponse:
		tcpr_get_init_response__free_unpacked(resp, NULL);

freerequest:
		free(request_buf);

finished:
		return res;
}


int get_ack(
		struct four_tuple *four_tuple,
		uint32_t *ack)
{
		TcprGetAck request = TCPR_GET_ACK__INIT;
		TcprGetAckResponse *resp;
		FourTuple connection = FOUR_TUPLE__INIT;	
		uint8_t resp_buf[MAX_BUFFER_SIZE];
		uint8_t *request_buf;
		size_t len;
		int res = -1;

		if (connect() < 0)
			goto finished;

		connection.local_ip = four_tuple->local_ip;
		connection.remote_ip = four_tuple->remote_ip;
		connection.local_port = four_tuple->local_port;
		connection.remote_port = four_tuple->remote_port; 
		request.connection = &connection;

		len = tcpr_get_ack__get_packed_size(&request);
		request_buf = malloc(len);

		if (NULL == request_buf)
			goto finished;

		if (tcpr_get_ack__pack(&request, request_buf) < 0)
			goto freerequest;
		
		if (nn_send(nanofd, request_buf, len, 0) < 0)
			goto freerequest;

		len = nn_recv(nanofd, &resp_buf, MAX_BUFFER_SIZE, 0);
		if (len < 0)
			goto freerequest;

		resp = tcpr_get_ack_response__unpack(NULL, len, resp_buf);
		if (NULL == resp)
			goto freerequest;
			
		*ack = resp->current_ack;
		res = 0;

freeresponse:
		tcpr_get_ack_response__free_unpacked(resp, NULL);

freerequest:
		free(request_buf);

finished:
		return res;
}


int set_connection (
		struct set_connection *set_connection)
{
		TcprSet request = TCPR_SET__INIT;
		TcprSetResponse *resp;
		FourTuple connection = FOUR_TUPLE__INIT;	
		uint8_t resp_buf[MAX_BUFFER_SIZE];
		uint8_t *request_buf;
		size_t len;
		int res = -1;

		if (connect() < 0)
			goto finished;

		connection.local_ip = set_connection->connection.local_ip;
		connection.remote_ip = set_connection->connection.remote_ip;
		connection.local_port = set_connection->connection.local_port;
		connection.remote_port = set_connection->connection.remote_port; 
		request.connection = &connection;
		request.sack_enabled = set_connection->sack_enabled;
		request.max_segment_size = set_connection->max_segment_size;
		request.window_scaling = set_connection->window_scaling;

		len = tcpr_set__get_packed_size(&request);
		request_buf = malloc(len);

		if (NULL == request_buf)
			goto finished;

		if (tcpr_set__pack(&request, request_buf) < 0)
			goto freerequest;
		
		if (nn_send(nanofd, request_buf, len, 0) < 0)
			goto freerequest;

		len = nn_recv(nanofd, &resp_buf, MAX_BUFFER_SIZE, 0);
		if (len < 0)
			goto freerequest;

		resp = tcpr_set_response__unpack(NULL, len, resp_buf);
		if (NULL == resp)
			goto freerequest;
			
		if (resp->status == STATUS__SUCCESS) 
			res = 0;

freeresponse:
		tcpr_set_response__free_unpacked(resp, NULL);

freerequest:
		free(request_buf);

finished:
		return res;
}
