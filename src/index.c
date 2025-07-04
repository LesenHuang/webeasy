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
