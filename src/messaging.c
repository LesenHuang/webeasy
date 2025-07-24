#include <kore/kore.h>
#include <kore/pgsql.h>
#include <kore/http.h>

#define WS_MESSAGE_ID	KORE_MSG_APP_BASE + 1

int	init(int);
int     websocket(struct http_request *req);
void	ws_message(struct kore_msg *, const void *);

int
init(int state)
{

	kore_pgsql_register("db", "hostaddr=172.0.0.2 dbname=webeasy user=webeasy password=root");
	if (state == KORE_MODULE_UNLOAD)
		return (KORE_RESULT_OK);

	kore_msg_register(WS_MESSAGE_ID, ws_message);
	return (KORE_RESULT_OK);
}

void
ws_message(struct kore_msg *msg, const void *data)
{

}

int
websocket(struct http_request *req)
{
	kore_websocket_handshake(req, "onconnect", "onmessage", "ondisconnect");
	return (KORE_RESULT_OK);
}
