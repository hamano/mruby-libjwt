/*
** mrb_jwt.c - JWT class
**
** Copyright (c) HAMANO Tsukasa 2017
**
** See Copyright Notice in LICENSE
*/
#include <stdlib.h>
#include <string.h>

#include "jwt.h"
#include "mruby.h"
#include "mruby/class.h"
#include "mruby/data.h"
#include "mruby/string.h"
#include "mruby/hash.h"
#include "mruby/array.h"
#include "mrb_jwt.h"

#define DONE mrb_gc_arena_restore(mrb, 0);

typedef struct {
	jwt_t *jwt;
} mrb_jwt;

static void mrb_jwt_free(mrb_state *mrb, void *ptr)
{
	mrb_jwt *data = ptr;
	if(data->jwt){
		jwt_free(data->jwt);
	}
	mrb_free(mrb, data);
}

static const struct mrb_data_type mrb_jwt_type = {
	"JWT", mrb_jwt_free,
};

static mrb_value mrb_jwt_init(mrb_state *mrb, mrb_value self)
{
	mrb_value arg = mrb_nil_value();
	mrb_jwt *data;
	int rc;

	data = (mrb_jwt *)DATA_PTR(self);
	if (data) {
		mrb_free(mrb, data);
	}

	mrb_get_args(mrb, "|H", &arg);
	data = (mrb_jwt *)mrb_malloc(mrb, sizeof(mrb_jwt));
	if (!data) {
		mrb_raise(mrb, E_RUNTIME_ERROR, "mrb_malloc() failed.");
	}
	data->jwt = NULL;
	DATA_TYPE(self) = &mrb_jwt_type;
	DATA_PTR(self) = data;
	rc = jwt_new(&data->jwt);
	if (rc) {
		mrb_raise(mrb, E_RUNTIME_ERROR, "jwt_new() failed.");
	}
	return self;
}

static mrb_value mrb_jwt_to_s(mrb_state *mrb, mrb_value self)
{
	mrb_jwt *data = DATA_PTR(self);
	char* str;
	mrb_value ret;
	str = jwt_dump_str(data->jwt, 0);
	ret = mrb_str_new(mrb, str, strlen(str));
	free(str);
	return ret;
}

static mrb_value mrb_jwt_dump(mrb_state *mrb, mrb_value self)
{
	mrb_jwt *data = DATA_PTR(self);
	char* str;
	mrb_value ret;
	str = jwt_dump_str(data->jwt, 0);
	ret = mrb_str_new(mrb, str, strlen(str));
	free(str);
	return ret;
}

static mrb_value mrb_jwt_add_grant(mrb_state *mrb, mrb_value self)
{
	mrb_jwt *data = DATA_PTR(self);
	char *key;
	mrb_value value;
	mrb_get_args(mrb, "zo", &key, &value);
	switch (mrb_type(value)) {
	case MRB_TT_STRING:
		jwt_add_grant(data->jwt, key, RSTRING_PTR(value));
		break;
	case MRB_TT_FIXNUM:
		jwt_add_grant_int(data->jwt, key, mrb_fixnum(value));
		break;
	default:
		/* TODO: boolean */
		mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
	}
	return self;
}

static mrb_value mrb_jwt_add_grants(mrb_state *mrb, mrb_value self)
{
	mrb_jwt *data = DATA_PTR(self);
	mrb_value arg;
	mrb_value hash_keys, hash_key;
	int hash_len;
	int i;

	mrb_get_args(mrb, "o", &arg);
	switch (mrb_type(arg)) {
	case MRB_TT_STRING:
		jwt_add_grants_json(data->jwt, RSTRING_PTR(arg));
		break;
	case MRB_TT_HASH:
		hash_keys = mrb_hash_keys(mrb, arg);
		hash_len = RARRAY_LEN(hash_keys);
		for (i = 0; i < hash_len; i++){
			hash_key = mrb_ary_ref(mrb, hash_keys, i);
			mrb_funcall(mrb, self, "add_grant", 2, hash_key,
				    mrb_hash_get(mrb, arg, hash_key));
		}
		break;
	default:
		mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
	}
	return self;
}

static mrb_value mrb_jwt_set_alg_array(mrb_state *mrb, mrb_value self)
{
	mrb_value args;
	mrb_get_args(mrb, "A", &args);
	if (RARRAY_LEN(args) != 2) {
		mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid argument");
	}
	return mrb_funcall(mrb, self, "set_alg", 2,
			   mrb_ary_ref(mrb, args, 0),
			   mrb_ary_ref(mrb, args, 1));
}

static mrb_value mrb_jwt_set_alg(mrb_state *mrb, mrb_value self)
{
	mrb_jwt *data = DATA_PTR(self);
	mrb_int alg;
	char *key;
	mrb_int len;
	mrb_get_args(mrb, "is", &alg, &key, &len);
	jwt_set_alg(data->jwt, alg, (unsigned char*)key, len);
	return self;
}

static mrb_value mrb_jwt_encode(mrb_state *mrb, mrb_value self)
{
	mrb_jwt *data = DATA_PTR(self);
	mrb_value ret;
	char* str;
	str = jwt_encode_str(data->jwt);
	ret = mrb_str_new(mrb, str, strlen(str));
	free(str);
	return ret;
}

void mrb_mruby_libjwt_gem_init(mrb_state *mrb)
{
	struct RClass *jwt;
	jwt = mrb_define_class(mrb, "JWT", mrb->object_class);
	MRB_SET_INSTANCE_TT(jwt, MRB_TT_DATA);
	mrb_define_method(mrb, jwt, "initialize", mrb_jwt_init, MRB_ARGS_OPT(1));
	mrb_define_method(mrb, jwt, "to_s", mrb_jwt_to_s, MRB_ARGS_NONE());
	mrb_define_method(mrb, jwt, "dump", mrb_jwt_dump, MRB_ARGS_REQ(1));
	mrb_define_method(mrb, jwt, "add_grant", mrb_jwt_add_grant, MRB_ARGS_REQ(2));
	mrb_define_method(mrb, jwt, "add_grants", mrb_jwt_add_grants, MRB_ARGS_REQ(1));
	mrb_define_method(mrb, jwt, "set_alg", mrb_jwt_set_alg, MRB_ARGS_REQ(2));
	mrb_define_method(mrb, jwt, "alg=", mrb_jwt_set_alg_array, MRB_ARGS_REQ(1));
	mrb_define_method(mrb, jwt, "encode", mrb_jwt_encode, MRB_ARGS_NONE());

	mrb_define_const(mrb, jwt, "ALG_NONE",
			 mrb_fixnum_value(JWT_ALG_NONE));
	mrb_define_const(mrb, jwt, "ALG_HS256",
			 mrb_fixnum_value(JWT_ALG_HS256));
	mrb_define_const(mrb, jwt, "ALG_HS384",
			 mrb_fixnum_value(JWT_ALG_HS384));
	mrb_define_const(mrb, jwt, "ALG_HS512",
			 mrb_fixnum_value(JWT_ALG_HS512));
	mrb_define_const(mrb, jwt, "ALG_RS256",
			 mrb_fixnum_value(JWT_ALG_RS256));
	mrb_define_const(mrb, jwt, "ALG_RS384",
			 mrb_fixnum_value(JWT_ALG_RS384));
	mrb_define_const(mrb, jwt, "ALG_RS512",
			 mrb_fixnum_value(JWT_ALG_RS512));
	mrb_define_const(mrb, jwt, "ALG_ES256",
			 mrb_fixnum_value(JWT_ALG_ES256));
	mrb_define_const(mrb, jwt, "ALG_ES384",
			 mrb_fixnum_value(JWT_ALG_ES384));
	mrb_define_const(mrb, jwt, "ALG_ES512",
			 mrb_fixnum_value(JWT_ALG_ES512));
	DONE;
}

void mrb_mruby_libjwt_gem_final(mrb_state *mrb)
{
}
