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
#include <kore/http.h>
#include <jwt.h>

#include "jwt.h"
#include "assets.h"
#include "users.h"

int		page(struct http_request *);

int
page(struct http_request *req)
{

	struct kore_buf		buf;
	u_int8_t		*d;
	size_t			len;
	char			*user_name;
	long			user_id;

	kore_buf_init(&buf, asset_len_index_html);
	kore_buf_append(&buf, asset_index_html, asset_len_index_html);

	if (req->hdlr_extra != NULL) {
		user_name = ((struct kore_jwt *) req->hdlr_extra)->user_name;	//jwt_get_grant(req->hdlr_extra, "user_id");
		user_id   = ((struct kore_jwt *) req->hdlr_extra)->user_id;	//jwt_get_grant(req->hdlr_extra, "user_id");

		kore_log(LOG_INFO, "id:%ld, name:%s", user_id, user_name);
		kore_buf_replace_string(&buf, "$user_name$", user_name, strlen(user_name));
	}

	d = kore_buf_release(&buf, &len);

	http_response(req, 200, d, len);
	kore_free(d);

	return (KORE_RESULT_OK);

}
