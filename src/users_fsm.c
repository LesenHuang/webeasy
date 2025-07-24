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
#include <kore/pgsql.h>
#include <kore/sha1.h>
#include <jwt.h>

#include "users.h"
#include "assets.h"
#include "utils.h"

int		regista(struct http_request *);
int		logina(struct http_request *);

int		v_tokenvalidate(struct http_request *, char *);
int		v_token_validatecheck(struct http_request *req, char *token);

struct  http_state	  tkvstates[] = {
	{ "REQ_STATE_INIT",		request_perform_init },
	{ "REQ_STATE_QUERY",		request_perform_query },
	{ "REQ_STATE_DB_WAIT",		request_db_wait },
	{ "REQ_STATE_DB_READ",		request_db_read },
	{ "REQ_STATE_ERROR",		request_error },
	{ "REQ_STATE_DONE",		request_done },
};

#define tkvstates_size		(sizeof(tkvstates) / sizeof(tkvstates[0]));


//int v_token_validatecheck(struct http_request *req, char *token)
//{
//	return (http_state_run(tkvstates, tkvstates_size, req));
//}

int
v_tokenvalidate(struct http_request *req, char *token)
{
	jwt_t *decoded_jwt;

	struct kore_pgsql	sql;
	struct kore_jwt		*jwt = kore_malloc(sizeof(struct kore_jwt));

	kore_pgsql_init(&sql);

	if (!kore_pgsql_setup(&sql, "db", KORE_PGSQL_SYNC)) {
		kore_pgsql_logerror(&sql);
		goto out;
	}

	kore_log(LOG_INFO, "token: %s", token);

	if (jwt_decode(&decoded_jwt, token, (unsigned char *)SECRET_KEY, strlen(SECRET_KEY))) {
		jwt_free(decoded_jwt);
		goto out;
	}

	kore_log(LOG_INFO, "1token: %s", token);
	jwt->user_id	= jwt_get_grant_int(decoded_jwt, "user_id");
	jwt->exp	= jwt_get_grant_int(decoded_jwt, "exp");
	jwt->user_name	= kore_strdup(jwt_get_grant(decoded_jwt, "user_name"));

	kore_log(LOG_INFO, "2token: %ld %ld", jwt->exp, time(NULL));
	if (!kore_pgsql_query_params(&sql,
			"select to_char(expires_at AT TIME ZONE 'UTC', "
				"'Dy, DD Mon YYYY HH24:MI:SS \"GMT\"') AS expires, id "
			"from users.jwt "
			"where token = $1", 0, 1,
		KORE_PGSQL_PARAM_TEXT(token))) {
		kore_pgsql_logerror(&sql);
		goto out;
	}

	kore_log(LOG_INFO, "nt: %d", kore_pgsql_ntuples(&sql));
	if (kore_pgsql_ntuples(&sql) != 1)
		goto out;

	char *jwt_id = kore_pgsql_getvalue(&sql, 0, 1);
	time_t expires_at = kore_date_to_time(kore_pgsql_getvalue(&sql, 0, 0));

	kore_log(LOG_INFO, "3token: %ld %ld %s", expires_at, time(NULL), jwt_id);
	kore_log(LOG_INFO, ":token: %ld", jwt->exp);

	struct http_cookie	*cookie;
	if (time(NULL) < expires_at && time(NULL) > jwt->exp) {
		kore_log(LOG_INFO, "5token: %ld", expires_at);

		if (jwt_del_grants(decoded_jwt, "exp")) {
			jwt_free(decoded_jwt);
			goto out;
		}

		jwt->exp = jwt_add_grant_int(decoded_jwt, "exp", time(NULL) + REFRESH_AT);

		if ((token = jwt_encode_str(decoded_jwt)) == NULL) {
			jwt_free(decoded_jwt);
			goto out;
		}

		kore_log(LOG_INFO, "::token: %s", token);
		if (!kore_pgsql_query_params(&sql,
				"update users.jwt set expires_at = $1, token = $2 where id = $3", 0, 3,
				KORE_PGSQL_PARAM_TEXT(kore_time_to_date(time(NULL) + EXPIRES_AT)),
				KORE_PGSQL_PARAM_TEXT(token),
			KORE_PGSQL_PARAM_TEXT(jwt_id))) {

			kore_pgsql_logerror(&sql);
			goto out;
		}

		http_response_cookie(req, "token", token, "/", 0, EXPIRES_AT, NULL);
		cookie->flags &= ~HTTP_COOKIE_SECURE;

	} else if (time(NULL) > expires_at) {

		kore_log(LOG_INFO, "6token: %ld", expires_at);
		if (!kore_pgsql_query_params(&sql,
				"delete from users.jwt where token = $1", 0, 1,
			KORE_PGSQL_PARAM_TEXT(token))) {
			kore_pgsql_logerror(&sql);
		}
		http_response_cookie(req, "token", "", "/", 1, 0, &cookie);
		cookie->flags &= ~HTTP_COOKIE_SECURE;

		goto out;
	}

	kore_log(LOG_INFO, "4token: %s", token);

	req->hdlr_extra = jwt;

	jwt_free(decoded_jwt);

	kore_pgsql_cleanup(&sql);
	return (KORE_RESULT_OK);
out:
	kore_pgsql_cleanup(&sql);
	return (KORE_RESULT_ERROR);
}

int
logina(struct http_request *req)
{
	size_t			len;
	u_int8_t		*d;
	char			*name, *pass, *base64;
	const char		*loc;
	struct kore_buf		buf;
	struct kore_pgsql	sql;
	struct http_cookie	*cookie;

	kore_pgsql_init(&sql);
	kore_buf_init(&buf, asset_len_login_html);
	kore_buf_append(&buf, asset_login_html, asset_len_login_html);

	char *url[4], path[64];
	if (http_request_header(req, "referer", &loc)) {
		kore_split_string(kore_strdup(loc), "/", url, 4);

		sprintf(path, "/%s", url[2]);
		kore_log(LOG_INFO, "%s %s", path, url[2]);
		kore_buf_replace_string(&buf, "$referer$", path, strlen(path));
	}

	d = kore_buf_release(&buf, &len);

	if (req->method == HTTP_METHOD_POST) {
		http_populate_post(req);

		if (!(http_argument_get_string(req, "username", &name) && http_argument_get_string(req, "password", &pass))) {
			http_response(req, 400, RESP_STR("username or password error"));
		};

		if (!kore_pgsql_setup(&sql, "db", KORE_PGSQL_SYNC)) {
			kore_pgsql_logerror(&sql);
			http_response(req, 500, NULL, 0);
			goto out;
		}

		string_tosha1base64(pass, &base64);

		if (!kore_pgsql_query_params(&sql, "select id, username, email from users.base where username=$1 and password_hash=$2", 0, 2,
			KORE_PGSQL_PARAM_TEXT(name),
			KORE_PGSQL_PARAM_TEXT(base64))) {

			kore_free(base64);
			kore_log(LOG_INFO, "!no");
			kore_pgsql_logerror(&sql);
			goto out;
		}

		kore_free(base64);

		if (!kore_pgsql_ntuples(&sql)) {
			kore_log(LOG_INFO, "user not exist or password error");
			kore_pgsql_logerror(&sql);
			http_response(req, 400, RESP_STR("user not exist or password error"));
			goto out;

		}

		jwt_t	*jwt;
		char	*token;

		jwt_new(&jwt);

		jwt_set_alg(jwt, JWT_ALG_HS256, (unsigned char *)SECRET_KEY, strlen(SECRET_KEY));

		int err;
		const char	*user_ids = kore_pgsql_getvalue(&sql, 0, 0);
		long		user_id = kore_strtonum(user_ids, 10, 0, LLONG_MAX, &err);
		char		*user_name = kore_pgsql_getvalue(&sql, 0, 1);

		kore_log(LOG_INFO, "user id: %ld", user_id);

		if (!err)
			goto out;

		jwt_add_grant_int(jwt, "user_id", user_id);
		jwt_add_grant(jwt, "user_name", user_name);
		jwt_add_grant_int(jwt, "exp", time(NULL) + REFRESH_AT);

		if ((token = jwt_encode_str(jwt)) == NULL) {
			jwt_free(jwt);
			goto out;
		}

		jwt_free(jwt);

		if (!kore_pgsql_query_params(&sql, "insert into users.jwt (user_id, token, expires_at) values ($1, $2, $3)", 0, 3,
			KORE_PGSQL_PARAM_TEXT(user_ids),
			KORE_PGSQL_PARAM_TEXT(token),
			KORE_PGSQL_PARAM_TEXT(kore_time_to_date(time(NULL) + EXPIRES_AT)))) {

			kore_log(LOG_INFO, "insert token error");
			kore_pgsql_logerror(&sql);
			goto out;
		}

		http_response_cookie(req, "token", token, "/", 0, EXPIRES_AT, &cookie);
		cookie->flags &= ~HTTP_COOKIE_SECURE;

		kore_log(LOG_INFO, "JWT Token: %s\n", token);

		http_response_header(req, "location", "/");

		if (http_argument_get_string(req, "referer", &loc) && strcmp(loc, "/register") && strcmp(loc, "/login")) {
			http_response_header(req, "location", loc);
			kore_log(LOG_INFO, "%s", loc);
		}

		http_response(req, HTTP_STATUS_MOVED_PERMANENTLY, RESP_STR("Redirecting to /"));
		goto out;
	}

	http_response(req, 200, d, len);
out:
	kore_pgsql_cleanup(&sql);

	return (KORE_RESULT_OK);
}

int
regista(struct http_request *req)
{
	u_int8_t		*d;
	size_t			len;
	char			*base64, *name, *pass, *email;
	struct kore_buf		buf;
	struct kore_pgsql	sql;

	kore_buf_init(&buf, asset_len_reg2_html);
	kore_pgsql_init(&sql);

	if (!kore_pgsql_setup(&sql, "db", KORE_PGSQL_SYNC)) {
		kore_pgsql_logerror(&sql);
		http_response(req, 500, NULL, 0);
		goto out;
	}

	if (req->method == HTTP_METHOD_POST) {

		http_populate_post(req);

		if (!(http_argument_get_string(req, "username", &name) &&
			http_argument_get_string(req, "password", &pass) &&
			http_argument_get_string(req, "email", &email))) {

			http_response(req, 400, RESP_STR("params error"));
			goto out;

		}

		kore_log(LOG_INFO, "%s %s %s", name, pass, email);

		string_tosha1base64(pass, &base64);

		if (!kore_pgsql_query_params(&sql, "INSERT INTO users.base (username, password_hash, email) values ($1, $2, $3)", 0, 3,
			KORE_PGSQL_PARAM_TEXT(name),
			KORE_PGSQL_PARAM_TEXT(base64),
			KORE_PGSQL_PARAM_TEXT(email))) {

			http_response(req, 400, RESP_STR("username or email exist"));
			kore_free(base64);
			kore_pgsql_logerror(&sql);
			goto out;
		}

		kore_buf_append(&buf, asset_reg2_html, asset_len_reg2_html);
		kore_buf_replace_string(&buf, "$username$", name, strlen(name));
		kore_free(base64);

		d = kore_buf_release(&buf, &len);

		http_response(req, 200, d, len);
		kore_free(d);
		goto out;

	}

	kore_buf_free(&buf);

	http_response_header(req, "content-type", "text/html");
	http_response(req, 200, asset_reg_html, asset_len_reg_html);

out:

	kore_pgsql_cleanup(&sql);
	return (KORE_RESULT_OK);
}
