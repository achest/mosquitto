
#ifndef AUDIT_H
#define AUDIT_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(WIN32) && !defined(WITH_BROKER)
#	ifdef libmosquitto_EXPORTS
#		define libmosq_EXPORT  __declspec(dllexport)
#	else
#		define libmosq_EXPORT  __declspec(dllimport)
#	endif
#else
#	define libmosq_EXPORT
#endif

#include <mosquitto_internal.h>
#include <mosquitto_broker.h>
#include <mosquitto.h>
#include <time_mosq.h>

struct mosquitto_audit{
	char *topic;
	int payloadlen;
	int count;
	struct mosquitto_audit *next;
};

struct mosquitto_audit *audit_db;

static time_t audit_last_update = 0;

int topic_truncate (const char * strin, int depth,char delimeter, char * strout );
int mosquitto_initAudit();

int mosquitto_cleanAuditDB();



int mosquitto_audit(const char * topic, int len, int topicdepth);

struct mosquitto_audit * mosquitto_getAuditTopic(const char * topic);



int mosquitto_sendAuditData(struct mosquitto_db *db,const char * treeprefix, int interval, time_t start_time);




#ifdef __cplusplus
}
#endif

#endif
