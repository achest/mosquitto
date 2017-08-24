#include <audit.h>

#include <memory_mosq.h>
#include <stdio.h>

#include <time_mosq.h>

#define BUFLEN 100

int mosquitto_initAudit() {

	audit_db = NULL;
	return 0;
}
int mosquitto_cleanAuditDB() {

	struct mosquitto_audit * ma = NULL;

	while (audit_db != NULL) {

		ma=	audit_db;
		audit_db = audit_db->next;
		_mosquitto_free(ma->topic);
		_mosquitto_free(ma);
	}
	return 0;
}

struct mosquitto_audit * mosquitto_getAuditTopic(const char * topic) {

	struct mosquitto_audit * ma = NULL;
	if (audit_db == NULL) {
		return NULL;
	}
	if (strcmp(audit_db->topic, topic) == 0) {
				return ma;
	}
	ma = audit_db;

	while (ma->next != NULL) {
		if (strcmp(ma->topic, topic) == 0) {
			return ma;
		}
		ma = ma->next;
	}

	return NULL;
}

int mosquitto_audit(const char * topic, int len) {

	struct mosquitto_audit * ma = mosquitto_getAuditTopic(topic);

	if (ma != NULL) {

		ma->count++;
		ma->payloadlen += len;
		return 1;
	}

	ma = (struct mosquitto_audit *) _mosquitto_calloc(1,
			sizeof(struct mosquitto_audit));

	ma->topic = (char *) _mosquitto_calloc(1,
			sizeof(char*) * (strlen(topic) + 2));
	snprintf(ma->topic, strlen(topic)+1, "%s", topic);
	ma->topic[strlen(topic)] = '\0';

	ma->count = 1;
	ma->payloadlen = len;

	if (audit_db == NULL) {
		audit_db = ma;
	} else {
		ma->next = audit_db;
		audit_db = ma;
	}

	return 0;
}

int mosquitto_sendAuditData(struct mosquitto_db *db,const char * treeprefix,int interval,
		time_t start_time) {

	struct mosquitto_audit * ma = audit_db;

	time_t now;
	now = mosquitto_time();
	if (interval && now - interval < audit_last_update) {
		//TODO check
		return -1;
	}
	audit_last_update = mosquitto_time();
	if (ma == NULL) {
		return 0;
	}

	while (ma->next != NULL) {

		char topiccount[BUFLEN];
		char topicsize[BUFLEN];
		snprintf(topiccount, BUFLEN, "%s/%s/%s", treeprefix, ma->topic, "COUNT");
		snprintf(topicsize, BUFLEN, "%s/%s/%s", treeprefix, ma->topic, "SIZE");
		char buf[BUFLEN];
		snprintf(buf, BUFLEN, "%d", ma->count);
		mqtt3_db_messages_easy_queue(db, NULL, topiccount, 2, strlen(buf), buf,	1);
		snprintf(buf, BUFLEN, "%d", ma->payloadlen);
		mqtt3_db_messages_easy_queue(db, NULL, topicsize, 2, strlen(buf), buf,1);
		ma = ma->next;

	}

	while (audit_db != NULL) {

		_mosquitto_free(audit_db->topic);
		_mosquitto_free(audit_db);
		audit_db = audit_db->next;
	}
	return 1;
}
