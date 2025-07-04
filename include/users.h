#ifndef __H_USERS_H
#define __H_USERS_H

#define         SECRET_KEY      "123"
#define         RESP_STR(x)     x, strlen(x)
#define         REFRESH_AT      10
#define         EXPIRES_AT      2*60

struct kore_jwt {
        long    user_id;
        char    *user_name;
        time_t  exp;
};

#endif
