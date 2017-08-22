/*
Copyright (c) 2009-2014 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
Contributors:
   Roger Light - initial implementation and documentation.
*/

#include <config.h>

#ifndef WIN32
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#ifdef WITH_WRAP
#include <tcpd.h>
#endif

#ifdef __FreeBSD__
#  include <netinet/in.h>
#  include <sys/socket.h>
#endif

#ifdef __QNX__
#include <netinet/in.h>
#include <net/netbyte.h>
#include <sys/socket.h>
#endif

#include <mosquitto_broker.h>
#include <mqtt3_protocol.h>
#include <memory_mosq.h>
#include <net_mosq.h>
#include <util_mosq.h>

#ifdef WITH_TLS
#include "tls_mosq.h"
#include <openssl/err.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static int tls_ex_index_context = -1;
static int tls_ex_index_listener = -1;
#endif

#ifdef WITH_SYS_TREE
extern unsigned int g_socket_connections;
#endif


static void net__print_error(int log, const char *format_str)
{
#ifdef WIN32
	char *buf;

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
			NULL, WSAGetLastError(), LANG_NEUTRAL, &buf, 0, NULL);

	_mosquitto_log_printf(NULL, log, format_str, buf);
	LocalFree(buf);
#else
	char buf[256];

	strerror_r(errno, buf, 256);
	_mosquitto_log_printf(NULL, log, format_str, buf);
#endif
}


int mqtt3_socket_accept(struct mosquitto_db *db, mosq_sock_t listensock)
{
	int i;
	int j;
	mosq_sock_t new_sock = INVALID_SOCKET;
	struct mosquitto *new_context;
#ifdef WITH_TLS
	BIO *bio;
	int rc;
	char ebuf[256];
	unsigned long e;
#endif
#ifdef WITH_WRAP
	struct request_info wrap_req;
	char address[1024];
#endif

	new_sock = accept(listensock, NULL, 0);
	if(new_sock == INVALID_SOCKET) return -1;

#ifdef WITH_SYS_TREE
	g_socket_connections++;
#endif

	if(_mosquitto_socket_nonblock(new_sock)){
		return INVALID_SOCKET;
	}

#ifdef WITH_WRAP
	/* Use tcpd / libwrap to determine whether a connection is allowed. */
	request_init(&wrap_req, RQ_FILE, new_sock, RQ_DAEMON, "mosquitto", 0);
	fromhost(&wrap_req);
	if(!hosts_access(&wrap_req)){
		/* Access is denied */
		if(!_mosquitto_socket_get_address(new_sock, address, 1024)){
			_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE, "Client connection from %s denied access by tcpd.", address);
		}
		COMPAT_CLOSE(new_sock);
		return -1;
	}
#endif
	new_context = mqtt3_context_init(db, new_sock);
	if(!new_context){
		COMPAT_CLOSE(new_sock);
		return -1;
	}
	for(i=0; i<db->config->listener_count; i++){
		for(j=0; j<db->config->listeners[i].sock_count; j++){
			if(db->config->listeners[i].socks[j] == listensock){
				new_context->listener = &db->config->listeners[i];
				new_context->listener->client_count++;
				break;
			}
		}
	}
	if(!new_context->listener){
		mqtt3_context_cleanup(db, new_context, true);
		return -1;
	}

	if(new_context->listener->max_connections > 0 && new_context->listener->client_count > new_context->listener->max_connections){
		_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE, "Client connection from %s denied: max_connections exceeded.", new_context->address);
		mqtt3_context_cleanup(db, new_context, true);
		return -1;
	}

#ifdef WITH_TLS
	/* TLS init */
	for(i=0; i<db->config->listener_count; i++){
		for(j=0; j<db->config->listeners[i].sock_count; j++){
			if(db->config->listeners[i].socks[j] == listensock){
				if(db->config->listeners[i].ssl_ctx){
					new_context->ssl = SSL_new(db->config->listeners[i].ssl_ctx);
					if(!new_context->ssl){
						mqtt3_context_cleanup(db, new_context, true);
						return -1;
					}
					SSL_set_ex_data(new_context->ssl, tls_ex_index_context, new_context);
					SSL_set_ex_data(new_context->ssl, tls_ex_index_listener, &db->config->listeners[i]);
					new_context->want_write = true;
					bio = BIO_new_socket(new_sock, BIO_NOCLOSE);
					SSL_set_bio(new_context->ssl, bio, bio);
					ERR_clear_error();
					rc = SSL_accept(new_context->ssl);
					if(rc != 1){
						rc = SSL_get_error(new_context->ssl, rc);
						if(rc == SSL_ERROR_WANT_READ){
							/* We always want to read. */
						}else if(rc == SSL_ERROR_WANT_WRITE){
							new_context->want_write = true;
						}else{
							e = ERR_get_error();
							while(e){
								_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE,
										"Client connection from %s failed: %s.",
										new_context->address, ERR_error_string(e, ebuf));
								e = ERR_get_error();
							}
							mqtt3_context_cleanup(db, new_context, true);
							return -1;
						}
					}
				}
			}
		}
	}
#endif

	_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE, "New connection from %s on port %d.", new_context->address, new_context->listener->port);

	return new_sock;
}

#ifdef WITH_TLS
static int client_certificate_verify(int preverify_ok, X509_STORE_CTX *ctx)
{
	/* Preverify should check expiry, revocation.
	 */

	return preverify_ok;
}
#endif

#ifdef REAL_WITH_TLS_PSK
static unsigned int psk_server_callback(SSL *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len)
{
	struct mosquitto_db *db;
	struct mosquitto *context;
	struct _mqtt3_listener *listener;
	char *psk_key = NULL;
	int len;
	const char *psk_hint;

	if(!identity) return 0;

	db = _mosquitto_get_db();

	context = SSL_get_ex_data(ssl, tls_ex_index_context);
	if(!context) return 0;

	listener = SSL_get_ex_data(ssl, tls_ex_index_listener);
	if(!listener) return 0;

	psk_hint = listener->psk_hint;

	/* The hex to BN conversion results in the length halving, so we can pass
	 * max_psk_len*2 as the max hex key here. */
	psk_key = _mosquitto_calloc(1, max_psk_len*2 + 1);
	if(!psk_key) return 0;

	if(mosquitto_psk_key_get(db, psk_hint, identity, psk_key, max_psk_len*2) != MOSQ_ERR_SUCCESS){
		_mosquitto_free(psk_key);
		return 0;
	}

	len = _mosquitto_hex2bin(psk_key, psk, max_psk_len);
	if (len < 0){
		_mosquitto_free(psk_key);
		return 0;
	}

	if(listener->use_identity_as_username){
		context->username = _mosquitto_strdup(identity);
		if(!context->username){
			_mosquitto_free(psk_key);
			return 0;
		}
	}

	_mosquitto_free(psk_key);
	return len;
}
#endif

#ifdef WITH_TLS
static int _mosquitto_tls_server_ctx(struct _mqtt3_listener *listener)
{
	int ssl_options = 0;
	char buf[256];
	int rc;
#ifdef WITH_EC
#if OPENSSL_VERSION_NUMBER >= 0x10000000L && OPENSSL_VERSION_NUMBER < 0x10002000L
	EC_KEY *ecdh = NULL;
#endif
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10001000L
	if(listener->tls_version == NULL){
		listener->ssl_ctx = SSL_CTX_new(SSLv23_server_method());
	}else if(!strcmp(listener->tls_version, "tlsv1.2")){
		listener->ssl_ctx = SSL_CTX_new(TLSv1_2_server_method());
	}else if(!strcmp(listener->tls_version, "tlsv1.1")){
		listener->ssl_ctx = SSL_CTX_new(TLSv1_1_server_method());
	}else if(!strcmp(listener->tls_version, "tlsv1")){
		listener->ssl_ctx = SSL_CTX_new(TLSv1_server_method());
	}
#else
	listener->ssl_ctx = SSL_CTX_new(SSLv23_server_method());
#endif
	if(!listener->ssl_ctx){
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to create TLS context.");
		return 1;
	}

	/* Don't accept SSLv2 or SSLv3 */
	ssl_options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
#ifdef SSL_OP_NO_COMPRESSION
	/* Disable compression */
	ssl_options |= SSL_OP_NO_COMPRESSION;
#endif
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
	/* Server chooses cipher */
	ssl_options |= SSL_OP_CIPHER_SERVER_PREFERENCE;
#endif
	SSL_CTX_set_options(listener->ssl_ctx, ssl_options);

#ifdef SSL_MODE_RELEASE_BUFFERS
	/* Use even less memory per SSL connection. */
	SSL_CTX_set_mode(listener->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
#endif

#ifdef WITH_EC
#if OPENSSL_VERSION_NUMBER >= 0x10002000L && OPENSSL_VERSION_NUMBER < 0x10100000L
	SSL_CTX_set_ecdh_auto(listener->ssl_ctx, 1);
#elif OPENSSL_VERSION_NUMBER >= 0x10000000L && OPENSSL_VERSION_NUMBER < 0x10002000L
	ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if(!ecdh){
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to create TLS ECDH curve.");
		return 1;
	}
	SSL_CTX_set_tmp_ecdh(listener->ssl_ctx, ecdh);
	EC_KEY_free(ecdh);
#endif
#endif

	snprintf(buf, 256, "mosquitto-%d", listener->port);
	SSL_CTX_set_session_id_context(listener->ssl_ctx, (unsigned char *)buf, strlen(buf));

	if(listener->ciphers){
		rc = SSL_CTX_set_cipher_list(listener->ssl_ctx, listener->ciphers);
		if(rc == 0){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to set TLS ciphers. Check cipher list \"%s\".", listener->ciphers);
			return 1;
		}
	}else{
		rc = SSL_CTX_set_cipher_list(listener->ssl_ctx, "DEFAULT:!aNULL:!eNULL:!LOW:!EXPORT:!SSLv2:@STRENGTH");
		if(rc == 0){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to set TLS ciphers. Check cipher list \"%s\".", listener->ciphers);
			return 1;
		}
	}
	return MOSQ_ERR_SUCCESS;
}
#endif


#ifdef WITH_TLS
/* Yeah, the lazy way, just assume that OpenSSL is new enough if it is not, we
 * are screwed anyways ... */
#if OPENSSL_VERSION_NUMBER <= 0x00907000L
#error OpenSSL version is not supported
#endif

#define CRL_FILE_STAT_TIME (5*60) /* seconds */
#define MAX_NUM_CRLS 16

struct CRLAutoReloaderData {
	char        *filename;
	time_t       last_mtime;
	time_t       last_stat;
	X509_CRL    *crls[MAX_NUM_CRLS + 1];
};

static int crl_autoreloader_new(X509_LOOKUP *ctx)
{
	struct CRLAutoReloaderData *data = malloc(sizeof(struct CRLAutoReloaderData));
	ctx->method_data = (char*) data;
	if (!data)
		return 0;

	data->last_mtime = 0;
	data->last_stat = 0;
	data->filename = NULL;
	data->crls[0] = NULL;

	return 1;
}

static void crl_autoreloader_clear(X509_LOOKUP *ctx)
{
	struct CRLAutoReloaderData *data = (struct CRLAutoReloaderData*) ctx->method_data;
	X509_CRL **crl;

	for (crl = data->crls; *crl; crl++) {
		X509_CRL_free(*crl);
		*crl = NULL;
	}
}

static void crl_autoreloader_free(X509_LOOKUP *ctx)
{
	struct CRLAutoReloaderData *data = (struct CRLAutoReloaderData*) ctx->method_data;

	if (!data)
		return;

	crl_autoreloader_clear(ctx);

	if (data->filename)
		free(data->filename);

	free(data);
}

static int crl_autoreloader_reload(X509_LOOKUP *ctx)
{
	struct CRLAutoReloaderData *data = (struct CRLAutoReloaderData*) ctx->method_data;
	struct timespec now;
	struct stat buf;
	int count;
	BIO *bio;
	int ret;

	if (!data->filename) {
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "No CRL file set on lookup handler, cannot load CRL.");
		return 0;
	}

	clock_gettime(CLOCK_REALTIME, &now);
	ret = stat(data->filename, &buf);
	if (ret) {
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Could not stat CRL file %s! Aborting load.", data->filename);
		return 0;
	}

	data->last_stat = now.tv_sec;
	data->last_mtime = buf.st_mtime;

	bio = BIO_new_file(data->filename, "r");
	if (!bio) {
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Could not open CRL file %s! Aborting load.", data->filename);
		return 0;
	}

	/* The file was opened successfully. Load all CRLs into memory. */
	count = 0;
	while (count < MAX_NUM_CRLS) {
		X509_CRL *crl;
		crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);

		if (!crl)
			break;

		if (count == 0)
			crl_autoreloader_clear(ctx);

		data->crls[count] = crl;
		data->crls[count+1] = NULL;
		count += 1;
	}

	_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Loaded %i CRL(s) from %s.", count, data->filename);

	BIO_free(bio);
	return count > 0;
}

static void crl_autoreloader_check_reload(X509_LOOKUP *ctx)
{
	struct CRLAutoReloaderData *data = (struct CRLAutoReloaderData*) ctx->method_data;
	struct timespec now;
	struct stat buf;
	int ret;

	if (!data->filename)
		return;

	clock_gettime(CLOCK_REALTIME, &now);

	if (now.tv_sec < data->last_stat + CRL_FILE_STAT_TIME)
		return;

	_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Checking whether CRL file %s was modified.", data->filename);

	data->last_stat = now.tv_sec;

	ret = stat(data->filename, &buf);
	if (ret) {
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Could not stat CRL file %s! Will retry at next check time.", data->filename);
		return;
	}
	/* CRL file did not change. */
	if (buf.st_mtime == data->last_mtime)
		return;

	crl_autoreloader_reload(ctx);
}


static int crl_autoreloader_get_by_subject(X509_LOOKUP *ctx, int type, X509_NAME *name, X509_OBJECT *ret)
{
	struct CRLAutoReloaderData *data = (struct CRLAutoReloaderData*) ctx->method_data;
	X509_CRL **crl;
	char *buf;

	ret->type = X509_LU_FAIL;
	if (type != X509_LU_CRL)
		return 0;

	crl_autoreloader_check_reload(ctx);

	for (crl = data->crls; *crl; crl++) {
		if (X509_NAME_cmp((*crl)->crl->issuer, name) == 0) {
			ret->type = type;
			ret->data.crl = *crl;

			return 1;
		}
	}

	buf = X509_NAME_oneline(name, NULL, 0);
	free(buf);


	return 0;
}

static int crl_autoreloader_load_file(X509_LOOKUP *ctx, const char *filename)
{
	struct CRLAutoReloaderData *data = (struct CRLAutoReloaderData*) ctx->method_data;

	if (data->filename)
		free(data->filename);

	data->filename = strdup(filename);

	crl_autoreloader_clear(ctx);
	return crl_autoreloader_reload(ctx);
}

static int crl_autoreloader_ctrl(X509_LOOKUP *ctx, int cmd, const char *argp, long argl, char **ret)
{
	switch (cmd) {
		case X509_L_FILE_LOAD:
			return crl_autoreloader_load_file(ctx, argp);
		default:
			return 0;
	}

	return 0;
}

static X509_LOOKUP_METHOD x509_crl_autoreloader = {
	"CRL file auto reloader",
	crl_autoreloader_new,            /* new */
	crl_autoreloader_free,           /* free */
	NULL,                        /* init */
	NULL,                        /* shutdown */
	crl_autoreloader_ctrl,           /* ctrl */
	crl_autoreloader_get_by_subject, /* get_by_subject */
	NULL,                        /* get_by_issuer_serial */
	NULL,                        /* get_by_fingerprint */
	NULL                         /* get_by_alias */
};

static X509_LOOKUP_METHOD *X509_LOOKUP_crl_autoreloader(void)
{
	return (&x509_crl_autoreloader);
}


static STACK_OF(X509_CRL) *my_get1_crls_nocache(X509_STORE_CTX *ctx, X509_NAME *nm)
{
	int i, idx, cnt;
	STACK_OF(X509_CRL) *sk;
	X509_CRL *x;
	X509_OBJECT xobj;
	sk = sk_X509_CRL_new_null();

	if (!X509_STORE_get_by_subject(ctx, X509_LU_CRL, nm, &xobj)) {
		sk_X509_CRL_free(sk);
		return NULL;
	}

	x = xobj.data.crl;

	if (!sk_X509_CRL_push(sk, x)) {
		X509_CRL_free(x);
		sk_X509_CRL_pop_free(sk, X509_CRL_free);
		return NULL;
	}

	return sk;
}

#endif



/* Creates a socket and listens on port 'port'.
 * Returns 1 on failure
 * Returns 0 on success.
 */
int mqtt3_socket_listen(struct _mqtt3_listener *listener)
{
	mosq_sock_t sock = INVALID_SOCKET;
	struct addrinfo hints;
	struct addrinfo *ainfo, *rp;
	char service[10];
#ifndef WIN32
	int ss_opt = 1;
#else
	char ss_opt = 1;
#endif
#ifdef WITH_TLS
	int rc;
	X509_STORE *store;
	X509_LOOKUP *lookup;
#endif

	if(!listener) return MOSQ_ERR_INVAL;

	snprintf(service, 10, "%d", listener->port);
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = PF_UNSPEC;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = SOCK_STREAM;

	if(getaddrinfo(listener->host, service, &hints, &ainfo)) return INVALID_SOCKET;

	listener->sock_count = 0;
	listener->socks = NULL;

	for(rp = ainfo; rp; rp = rp->ai_next){
		if(rp->ai_family == AF_INET){
			_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Opening ipv4 listen socket on port %d.", ntohs(((struct sockaddr_in *)rp->ai_addr)->sin_port));
		}else if(rp->ai_family == AF_INET6){
			_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Opening ipv6 listen socket on port %d.", ntohs(((struct sockaddr_in6 *)rp->ai_addr)->sin6_port));
		}else{
			continue;
		}

		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(sock == INVALID_SOCKET){
			net__print_error(MOSQ_LOG_WARNING, "Warning: %s");
			continue;
		}
		listener->sock_count++;
		listener->socks = _mosquitto_realloc(listener->socks, sizeof(mosq_sock_t)*listener->sock_count);
		if(!listener->socks){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			return MOSQ_ERR_NOMEM;
		}
		listener->socks[listener->sock_count-1] = sock;

#ifndef WIN32
		ss_opt = 1;
		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &ss_opt, sizeof(ss_opt));
#endif
		ss_opt = 1;
		setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &ss_opt, sizeof(ss_opt));

		if(_mosquitto_socket_nonblock(sock)){
			return 1;
		}

		if(bind(sock, rp->ai_addr, rp->ai_addrlen) == -1){
			net__print_error(MOSQ_LOG_ERR, "Error: %s");
			COMPAT_CLOSE(sock);
			return 1;
		}

		if(listen(sock, 100) == -1){
			net__print_error(MOSQ_LOG_ERR, "Error: %s");
			COMPAT_CLOSE(sock);
			return 1;
		}
	}
	freeaddrinfo(ainfo);

	/* We need to have at least one working socket. */
	if(listener->sock_count > 0){
#ifdef WITH_TLS
		if((listener->cafile || listener->capath) && listener->certfile && listener->keyfile){
			if(_mosquitto_tls_server_ctx(listener)){
				COMPAT_CLOSE(sock);
				return 1;
			}

			rc = SSL_CTX_load_verify_locations(listener->ssl_ctx, listener->cafile, listener->capath);
			if(rc == 0){
				if(listener->cafile && listener->capath){
					_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load CA certificates. Check cafile \"%s\" and capath \"%s\".", listener->cafile, listener->capath);
				}else if(listener->cafile){
					_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load CA certificates. Check cafile \"%s\".", listener->cafile);
				}else{
					_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load CA certificates. Check capath \"%s\".", listener->capath);
				}
				COMPAT_CLOSE(sock);
				return 1;
			}
			/* FIXME user data? */
			if(listener->require_certificate){
				SSL_CTX_set_verify(listener->ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, client_certificate_verify);
			}else{
				SSL_CTX_set_verify(listener->ssl_ctx, SSL_VERIFY_NONE, client_certificate_verify);
			}
			rc = SSL_CTX_use_certificate_chain_file(listener->ssl_ctx, listener->certfile);
			if(rc != 1){
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load server certificate \"%s\". Check certfile.", listener->certfile);
				COMPAT_CLOSE(sock);
				return 1;
			}
			rc = SSL_CTX_use_PrivateKey_file(listener->ssl_ctx, listener->keyfile, SSL_FILETYPE_PEM);
			if(rc != 1){
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load server key file \"%s\". Check keyfile.", listener->keyfile);
				COMPAT_CLOSE(sock);
				return 1;
			}
			rc = SSL_CTX_check_private_key(listener->ssl_ctx);
			if(rc != 1){
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Server certificate/key are inconsistent.");
				COMPAT_CLOSE(sock);
				return 1;
			}

			/* Load CRLs if they exist. */
			if(listener->crlfile){
				store = SSL_CTX_get_cert_store(listener->ssl_ctx);
				if(!store){
					_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to obtain TLS store.");
					COMPAT_CLOSE(sock);
					return 1;
				}
				lookup = X509_STORE_add_lookup(store, X509_LOOKUP_crl_autoreloader());
				rc = crl_autoreloader_load_file(lookup, listener->crlfile);
				if(rc != 1){
					_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to load certificate revocation file \"%s\". Check crlfile.", listener->crlfile);
					COMPAT_CLOSE(sock);
					return 1;
				}
				store->lookup_crls = my_get1_crls_nocache;
				X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
			}

#  ifdef REAL_WITH_TLS_PSK
		}else if(listener->psk_hint){
			if(tls_ex_index_context == -1){
				tls_ex_index_context = SSL_get_ex_new_index(0, "client context", NULL, NULL, NULL);
			}
			if(tls_ex_index_listener == -1){
				tls_ex_index_listener = SSL_get_ex_new_index(0, "listener", NULL, NULL, NULL);
			}

			if(_mosquitto_tls_server_ctx(listener)){
				COMPAT_CLOSE(sock);
				return 1;
			}
			SSL_CTX_set_psk_server_callback(listener->ssl_ctx, psk_server_callback);
			if(listener->psk_hint){
				rc = SSL_CTX_use_psk_identity_hint(listener->ssl_ctx, listener->psk_hint);
				if(rc == 0){
					_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to set TLS PSK hint.");
					COMPAT_CLOSE(sock);
					return 1;
				}
			}
#  endif /* REAL_WITH_TLS_PSK */
		}
#endif /* WITH_TLS */
		return 0;
	}else{
		return 1;
	}
}

int _mosquitto_socket_get_address(mosq_sock_t sock, char *buf, int len)
{
	struct sockaddr_storage addr;
	socklen_t addrlen;

	addrlen = sizeof(addr);
	if(!getpeername(sock, (struct sockaddr *)&addr, &addrlen)){
		if(addr.ss_family == AF_INET){
			if(inet_ntop(AF_INET, &((struct sockaddr_in *)&addr)->sin_addr.s_addr, buf, len)){
				return 0;
			}
		}else if(addr.ss_family == AF_INET6){
			if(inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&addr)->sin6_addr.s6_addr, buf, len)){
				return 0;
			}
		}
	}
	return 1;
}
