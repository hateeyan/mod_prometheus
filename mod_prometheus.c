#include <switch.h>
#include <microhttpd.h>

#define PROMETHEUS_FMT_CORE                                                                            \
	"# HELP freeswitch_uptime FreeSWITCH uptime in milliseconds.\n"                                    \
	"# TYPE freeswitch_uptime gauge\n"                                                                 \
	"freeswitch_uptime %lu\n"                                                                          \
	"# HELP freeswitch_version FreeSWITCH version.\n"                                                  \
	"# TYPE freeswitch_version gauge\n"                                                                \
	"freeswitch_version{major=\"%s\",minor=\"%s\",micro=\"%s\",version=\"%s\"} 1\n"                    \
	"# HELP freeswitch_info Information about the FreeSWITCH.\n"                                       \
	"# TYPE freeswitch_info gauge\n"                                                                   \
	"freeswitch_info{switchname=\"%s\",hostname=\"%s\",uuid=\"%s\",domain=\"%s\"} 1\n"

#define PROMETHEUS_FMT_SESSION                                                                         \
	"# HELP freeswitch_sessions_total Total sessions since startup.\n"                                 \
	"# TYPE freeswitch_sessions_total counter\n"                                                       \
	"freeswitch_sessions_total %lu\n"                                                                  \
	"# HELP freeswitch_sessions_active Number of active sessions.\n"                                   \
	"# TYPE freeswitch_sessions_active gauge\n"                                                        \
	"freeswitch_sessions_active %u\n"                                                                  \
	"# HELP freeswitch_sessions_peak Peak session count.\n"                                            \
	"# TYPE freeswitch_sessions_peak gauge\n"                                                          \
	"freeswitch_sessions_peak %u\n"                                                                    \
	"# HELP freeswitch_sessions_max Max sessions.\n"                                                   \
	"# TYPE freeswitch_sessions_max gauge\n"                                                           \
	"freeswitch_sessions_max %u\n"

#define PROMETHEUS_FMT_SOFIA_PROFILE_INFO_S                                                            \
	"# HELP freeswitch_sofia_profile_info Information about the sofia profile.\n"                      \
	"# TYPE freeswitch_sofia_profile_info gauge\n%s"

#define PROMETHEUS_FMT_SOFIA_PROFILE_INFO                                                              \
	"freeswitch_sofia_profile_info{profile=\"%s\",state=\"%s\"} 1\n"

#define PROMETHEUS_FMT_SOFIA_PROFILE_CALLS_TOTAL_S                                                     \
	"# HELP freeswitch_sofia_profile_calls_total Total number of profile calls.\n"                     \
	"# TYPE freeswitch_sofia_profile_calls_total counter\n%s"

#define PROMETHEUS_FMT_SOFIA_PROFILE_CALLS_TOTAL                                                       \
	"freeswitch_sofia_profile_calls_total{profile=\"%s\",type=\"%s\"} %s\n"

#define PROMETHEUS_FMT_SOFIA_PROFILE_REGISTRATIONS_S                                                   \
	"# HELP freeswitch_sofia_profile_registrations Current registrations.\n"                           \
	"# TYPE freeswitch_sofia_profile_registrations gauge\n%s"

#define PROMETHEUS_FMT_SOFIA_PROFILE_REGISTRATIONS                                                     \
	"freeswitch_sofia_profile_registrations{profile=\"%s\"} %s\n"

#define PROMETHEUS_FMT_SOFIA_PROFILE_GATEWAY_INFO_S                                                    \
	"# HELP freeswitch_sofia_profile_gateway_info Information about the sofia gateway.\n"              \
	"# TYPE freeswitch_sofia_profile_gateway_info gauge\n%s"

#define PROMETHEUS_FMT_SOFIA_PROFILE_GATEWAY_INFO                                                      \
	"freeswitch_sofia_profile_gateway_info{gateway=\"%s\",profile=\"%s\",state=\"%s\",status=\"%s\"} 1\n"

#define PROMETHEUS_FMT_SOFIA_PROFILE_GATEWAY_CALLS_TOTAL_S                                             \
	"# HELP freeswitch_sofia_profile_gateway_calls_total Total number of gateway calls.\n"             \
	"# TYPE freeswitch_sofia_profile_gateway_calls_total counter\n%s"

#define PROMETHEUS_FMT_SOFIA_PROFILE_GATEWAY_CALLS_TOTAL                                               \
	"freeswitch_sofia_profile_gateway_calls_total{gateway=\"%s\",profile=\"%s\",type=\"%s\"} %s\n"

#define PROMETHEUS_FMT_RTP_IN_BYTES_S                                                                  \
	"# HELP freeswitch_rtp_in_bytes Total number of incoming rtp size in bytes.\n"                     \
	"# TYPE freeswitch_rtp_in_bytes counter\n%s"

#define PROMETHEUS_FMT_RTP_IN_BYTES                                                                    \
	"freeswitch_rtp_in_bytes{profile=\"%s\"} %lld\n"

#define PROMETHEUS_FMT_RTP_OUT_BYTES_S                                                                 \
	"# HELP freeswitch_rtp_out_bytes Total number of outgoing rtp size in bytes.\n"                    \
	"# TYPE freeswitch_rtp_out_bytes counter\n%s"

#define PROMETHEUS_FMT_RTP_OUT_BYTES                                                                   \
	"freeswitch_rtp_out_bytes{profile=\"%s\"} %lld\n"


SWITCH_MODULE_LOAD_FUNCTION(mod_prometheus_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_prometheus_shutdown);
SWITCH_MODULE_DEFINITION(mod_prometheus, mod_prometheus_load, mod_prometheus_shutdown, NULL);

typedef struct prometheus_profile_s {
	const char *name;
	const char *direction;
	uint64_t rtp_in_bytes;
	uint64_t rtp_out_bytes;
	struct prometheus_profile_s *next;
} prometheus_profile_t;

static struct {
	struct MHD_Daemon *daemon;
	char *ip;
	uint16_t port;
	char *metrics_path;
	switch_memory_pool_t *pool;
	prometheus_profile_t *profiles;
} globals;

static prometheus_profile_t *prometheus_get_profile_ptr(const char *name)
{
	prometheus_profile_t *profile;

	for (profile = globals.profiles; profile; profile = profile->next) {
		if (!strcmp(profile->name, name)) {
			return profile;
		}
	}
	return NULL;
}

static void prometheus_profile_add(prometheus_profile_t **profiles, prometheus_profile_t *profile)
{
	prometheus_profile_t *p = *profiles;

	if (!p) {
		*profiles = profile;
		return;
	}

	while(p->next) p = p->next;
	p->next = profile;
}

static void prometheus_asprintf(char **buf, const char *fmt, ...)
{
	char *tmp;
	va_list ap;

	va_start(ap, fmt);
	switch_vasprintf(&tmp, fmt, ap);
	va_end(ap);

	if (*buf) {
		char *all;
		size_t size = strlen(*buf) + strlen(tmp) + 1;

		switch_zmalloc(all, size);

		strcat(all, *buf);
		strcat(all+strlen(all), tmp);

		switch_safe_free(tmp);
		free(*buf);
		*buf = all;
	} else {
		*buf = tmp;
	}
}

static void metric_core(char **buf)
{
	switch_time_t uptime;

	uptime = switch_core_uptime() / 1000;

	prometheus_asprintf(buf, PROMETHEUS_FMT_CORE,
						uptime,
						switch_version_major(), switch_version_minor(), switch_version_micro(), switch_version_full(),
						switch_core_get_switchname(), switch_core_get_hostname(), switch_core_get_uuid(), switch_core_get_domain(SWITCH_FALSE));
}

static void metric_sessions(char **buf)
{
	int sessions_peak = 0;

	switch_core_session_ctl(SCSC_SESSIONS_PEAK, &sessions_peak);
	prometheus_asprintf(buf, PROMETHEUS_FMT_SESSION,
						switch_core_session_id()-1,
						switch_core_session_count(),
						sessions_peak,
						switch_core_session_limit(0));
}

static void metric_sofia_gateway(char **buf)
{
	switch_xml_t xml = NULL, gateway, param;
	const char *err;
	char *buf_info = NULL, *buf_calls = NULL;
	switch_stream_handle_t stream;

	SWITCH_STANDARD_STREAM(stream);

	if (switch_api_execute("sofia", "xmlstatus gateway", NULL, &stream) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to execute sofia xmlstatus gateway: %s\n", (char *)stream.data);
		goto end;
	}

	xml = switch_xml_parse_str(stream.data, stream.data_len);
	err = switch_xml_error(xml);
	if (!switch_strlen_zero(err)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to parse sofia xmlstatus gateway: %s\n", err);
		goto end;
	}

	for (gateway = switch_xml_child(xml, "gateway"); gateway; gateway = gateway->next) {
		char *name = NULL, *profile = NULL, *state = NULL, *status = NULL;

		if ((param = switch_xml_child(gateway, "name"))) name = param->txt;
		if ((param = switch_xml_child(gateway, "profile"))) profile = param->txt;
		if ((param = switch_xml_child(gateway, "state"))) state = param->txt;
		if ((param = switch_xml_child(gateway, "status"))) status = param->txt;
		prometheus_asprintf(&buf_info, PROMETHEUS_FMT_SOFIA_PROFILE_GATEWAY_INFO, name, profile, state, status);

		if ((param = switch_xml_child(gateway, "calls-in"))) {
			prometheus_asprintf(&buf_calls, PROMETHEUS_FMT_SOFIA_PROFILE_GATEWAY_CALLS_TOTAL, name, profile, "calls-in", param->txt);
		}
		if ((param = switch_xml_child(gateway, "calls-out"))) {
			prometheus_asprintf(&buf_calls, PROMETHEUS_FMT_SOFIA_PROFILE_GATEWAY_CALLS_TOTAL, name, profile, "calls-out", param->txt);
		}
		if ((param = switch_xml_child(gateway, "failed-calls-in"))) {
			prometheus_asprintf(&buf_calls, PROMETHEUS_FMT_SOFIA_PROFILE_GATEWAY_CALLS_TOTAL, name, profile, "failed-calls-in", param->txt);
		}
		if ((param = switch_xml_child(gateway, "failed-calls-out"))) {
			prometheus_asprintf(&buf_calls, PROMETHEUS_FMT_SOFIA_PROFILE_GATEWAY_CALLS_TOTAL, name, profile, "failed-calls-out", param->txt);
		}
	}
	if (buf_info) prometheus_asprintf(buf, PROMETHEUS_FMT_SOFIA_PROFILE_GATEWAY_INFO_S, buf_info);
	if (buf_calls) prometheus_asprintf(buf, PROMETHEUS_FMT_SOFIA_PROFILE_GATEWAY_CALLS_TOTAL_S, buf_calls);

end:
	switch_safe_free(stream.data);
	switch_safe_free(buf_info);
	switch_safe_free(buf_calls);
	if (xml) switch_xml_free(xml);
}

static void metric_sofia_profile(char **buf_info, char **buf_calls, char **buf_reg,
								 const char *profile, const char *state)
{
	switch_xml_t xml = NULL, xml_info, param;
	const char *err;
	char *ext = NULL;
	switch_stream_handle_t stream;
	char arg[128] = {0};

	switch_snprintf(arg, sizeof(arg), "xmlstatus profile %s", profile);

	SWITCH_STANDARD_STREAM(stream);

	if (switch_api_execute("sofia", arg, NULL, &stream) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to execute sofia xmlstatus profile: %s\n", (char *)stream.data);
		goto end;
	}

	xml = switch_xml_parse_str(stream.data, stream.data_len);
	err = switch_xml_error(xml);
	if (!switch_strlen_zero(err)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to parse sofia xmlstatus profile: %s\n", err);
		goto end;
	}

	if (!(xml_info = switch_xml_child(xml, "profile-info"))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Can't find the profile-info tag.\n");
		goto end;
	}

	if (switch_xml_child(xml_info, "alias-of")) goto end;
	prometheus_asprintf(buf_info, PROMETHEUS_FMT_SOFIA_PROFILE_INFO, profile, state);

	if ((ext = strrchr(state, '('))) {
		if (!strcasecmp(ext, "(TLS)") || !strcasecmp(ext, "(WS)") || !strcasecmp(ext, "(WSS)")) return;
	}

	if ((param = switch_xml_child(xml_info, "calls-in"))) {
		prometheus_asprintf(buf_calls, PROMETHEUS_FMT_SOFIA_PROFILE_CALLS_TOTAL, profile, "calls-in", param->txt);
	}
	if ((param = switch_xml_child(xml_info, "calls-out"))) {
		prometheus_asprintf(buf_calls, PROMETHEUS_FMT_SOFIA_PROFILE_CALLS_TOTAL, profile, "calls-out", param->txt);
	}
	if ((param = switch_xml_child(xml_info, "failed-calls-in"))) {
		prometheus_asprintf(buf_calls, PROMETHEUS_FMT_SOFIA_PROFILE_CALLS_TOTAL, profile, "failed-calls-in", param->txt);
	}
	if ((param = switch_xml_child(xml_info, "failed-calls-out"))) {
		prometheus_asprintf(buf_calls, PROMETHEUS_FMT_SOFIA_PROFILE_CALLS_TOTAL, profile, "failed-calls-out", param->txt);
	}

	if ((param = switch_xml_child(xml_info, "registrations"))) {
		prometheus_asprintf(buf_reg, PROMETHEUS_FMT_SOFIA_PROFILE_REGISTRATIONS, profile, param->txt);
	}

end:
	switch_safe_free(stream.data);
	if (xml) switch_xml_free(xml);
}

static void metric_sofia(char **buf)
{
	switch_xml_t xml = NULL, profile, param;
	const char *err;
	const char *name = NULL, *state = NULL;
	char *buf_info = NULL, *buf_calls = NULL, *buf_reg = NULL;
	switch_stream_handle_t stream;

	SWITCH_STANDARD_STREAM(stream);

	if (switch_api_execute("sofia", "xmlstatus", NULL, &stream) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to execute sofia xmlstatus: %s\n", (char *)stream.data);
		goto end;
	}

	xml = switch_xml_parse_str(stream.data, stream.data_len);
	err = switch_xml_error(xml);
	if (!switch_strlen_zero(err)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to parse sofia xmlstatus: %s\n", err);
		goto end;
	}

	for (profile = switch_xml_child(xml, "profile"); profile; profile = profile->next) {
		if ((param = switch_xml_child(profile, "name"))) name = param->txt;
		if ((param = switch_xml_child(profile, "state"))) state = param->txt;

		metric_sofia_profile(&buf_info, &buf_calls, &buf_reg, name, state);
	}
	if (buf_info) prometheus_asprintf(buf, PROMETHEUS_FMT_SOFIA_PROFILE_INFO_S, buf_info);
	if (buf_calls) prometheus_asprintf(buf, PROMETHEUS_FMT_SOFIA_PROFILE_CALLS_TOTAL_S, buf_calls);
	if (buf_reg) prometheus_asprintf(buf, PROMETHEUS_FMT_SOFIA_PROFILE_REGISTRATIONS_S, buf_reg);

end:
	switch_safe_free(stream.data);
	switch_safe_free(buf_info);
	switch_safe_free(buf_calls);
	switch_safe_free(buf_reg);
	if (xml) switch_xml_free(xml);
}

static void metric_rtp(char **buf)
{
	prometheus_profile_t *p;
	char *buf_rtp_in = NULL, *buf_rtp_out = NULL;

	for (p = globals.profiles; p; p = p->next)
	{
		prometheus_asprintf(&buf_rtp_in, PROMETHEUS_FMT_RTP_IN_BYTES, p->name, p->rtp_in_bytes);
		prometheus_asprintf(&buf_rtp_out, PROMETHEUS_FMT_RTP_OUT_BYTES, p->name, p->rtp_out_bytes);
	}
	if (buf_rtp_in) prometheus_asprintf(buf, PROMETHEUS_FMT_RTP_IN_BYTES_S, buf_rtp_in);
	if (buf_rtp_out) prometheus_asprintf(buf, PROMETHEUS_FMT_RTP_OUT_BYTES_S, buf_rtp_out);

	switch_safe_free(buf_rtp_in);
	switch_safe_free(buf_rtp_out);
}

static int prometheus_handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method,
				   const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls)
{
	struct MHD_Response *response;
	int ret;
	char *body = NULL;

	if (strcmp(method, MHD_HTTP_METHOD_GET) != 0) { return MHD_NO; }
	if (strcmp(url, globals.metrics_path) != 0) { return MHD_NO; }

	metric_core(&body);
	metric_sessions(&body);
	metric_sofia(&body);
	metric_sofia_gateway(&body);
	metric_rtp(&body);

	response = MHD_create_response_from_buffer(strlen(body), (void *)body, MHD_RESPMEM_MUST_FREE);
	MHD_add_response_header(response, "Content-Type", "text/plain");
	ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
	MHD_destroy_response(response);

	return ret;
}

static void on_event_channel_hangup_complete(switch_event_t *event)
{
	switch_event_header_t * hp = NULL;
	prometheus_profile_t *profile = NULL;
	const char *profile_name = NULL;
	uint value;

	if ((hp = switch_event_get_header_ptr(event, "variable_sofia_profile_name"))) {
		profile_name = hp->value;
	}

	if (switch_strlen_zero(profile_name)) return;

	profile = prometheus_get_profile_ptr(profile_name);
	if (!profile) {
		profile = switch_core_alloc(globals.pool, sizeof(prometheus_profile_t));
		profile->name = switch_core_strdup(globals.pool, profile_name);

		prometheus_profile_add(&globals.profiles, profile);
	}

	if ((hp = switch_event_get_header_ptr(event, "variable_rtp_audio_in_raw_bytes"))) {
		value = switch_atoui(hp->value);
		profile->rtp_in_bytes += value;
	}

	if ((hp = switch_event_get_header_ptr(event, "variable_rtp_audio_out_raw_bytes"))) {
		value = switch_atoui(hp->value);
		profile->rtp_out_bytes += value;
	}
}

static switch_xml_config_item_t configs[] = {
	SWITCH_CONFIG_ITEM("listen-ip", SWITCH_CONFIG_STRING, CONFIG_REQUIRED, &globals.ip, "0.0.0.0", NULL, "ip address",
					   "ip address"),
	SWITCH_CONFIG_ITEM("listen-port", SWITCH_CONFIG_INT, CONFIG_REQUIRED, &globals.port, 8088, NULL, "listening port",
					   "listening port"),
	SWITCH_CONFIG_ITEM("metrics-path", SWITCH_CONFIG_STRING, CONFIG_RELOADABLE, &globals.metrics_path, "/metrics", NULL, "metrics path",
					   "Path under which to expose metrics"),
	SWITCH_CONFIG_ITEM_END()};

static switch_status_t do_config()
{
	if (switch_xml_config_parse_module_settings("prometheus.conf", SWITCH_FALSE, configs) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "No config file found\n");
		return SWITCH_STATUS_FALSE;
	}
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_prometheus_load)
{
	struct sockaddr_in addr;
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	if (do_config() != SWITCH_STATUS_SUCCESS) return SWITCH_STATUS_FALSE;

	globals.pool = pool;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(globals.port);
	addr.sin_addr.s_addr = inet_addr(globals.ip);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Starting HTTP server[%s:%d], path %s\n",
					  globals.ip, globals.port, globals.metrics_path);
	globals.daemon = MHD_start_daemon(MHD_USE_EPOLL_INTERNAL_THREAD, globals.port,
									  NULL, NULL,
									  (MHD_AccessHandlerCallback)&prometheus_handler, NULL,
									  MHD_OPTION_SOCK_ADDR, (struct sockaddr *)(&addr),
									  MHD_OPTION_END);
	if (globals.daemon == NULL) return SWITCH_STATUS_FALSE;

	switch_event_bind(modname, SWITCH_EVENT_CHANNEL_HANGUP_COMPLETE, SWITCH_EVENT_SUBCLASS_ANY, on_event_channel_hangup_complete, NULL);

	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_prometheus_shutdown) {
	switch_event_unbind_callback(on_event_channel_hangup_complete);
	if (globals.daemon)	MHD_stop_daemon(globals.daemon);
	return SWITCH_STATUS_SUCCESS;
}
