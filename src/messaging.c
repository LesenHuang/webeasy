/*
 * Copyright (c) 2025 Lesen Huang <huanglesen at gmail dot com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

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
