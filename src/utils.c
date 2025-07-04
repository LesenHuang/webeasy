#include <kore/kore.h>
#include <kore/sha1.h>

#include "utils.h"

void
string_tosha1base64(const char *str, char **b64)
{
	struct kore_buf		buf;
	SHA1_CTX		sctx;
	u_int8_t		digest[SHA1_DIGEST_LENGTH];

	kore_buf_init(&buf, 64);
	kore_buf_appendf(&buf, "%s", str);

	SHA1Init(&sctx);
	SHA1Update(&sctx, buf.data, buf.offset);
	SHA1Final(digest, &sctx);

	kore_buf_free(&buf);
	kore_base64_encode(digest, sizeof(digest), b64);
}
