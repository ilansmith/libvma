/*
 * Copyright (c) 2001-2018 Mellanox Technologies, Ltd. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#include <stdlib.h>
#include <vlogger/vlogger.h>
#include "vma/event/event_handler_manager.h"
#include <vma/util/sys_vars.h>
#include "utils/rdtsc.h"
#include "vma/util/instrumentation.h"
#include "vma/util/utils.h"
#include "vma/dev/time_converter_ptp.h"
#include "vma/ib/base/verbs_extra.h"
#include "vma/sock/sock-redirect.h"
#include "src/utils/rdtsc.h"


#ifdef DEFINED_IBV_CLOCK_INFO

#define MODULE_NAME             "tc_ptp"

#define ibchtc_logerr __log_err
#define ibchtc_logwarn __log_warn
#define ibchtc_loginfo __log_info
#define ibchtc_logdbg __log_info_dbg
#define ibchtc_logfunc __log_info_func

#define UPDATE_HW_TIMER_PTP_PERIOD_MS 1

static clockid_t get_clockid(int fd)
{
#define CLOCKFD 3
#define FD_TO_CLOCKID(fd)   ((~(clockid_t) (fd) << 3) | CLOCKFD)
	return FD_TO_CLOCKID(fd);
}

time_converter_ptp::time_converter_ptp(struct ibv_context* ctx) :
		m_p_ibv_context(ctx), m_clock_values_id(0)
{
	ibchtc_logerr("time_converter_ptp");
	//ibv_get_phc(m_p_ibv_context, &m_phc_time.p_time_h, &m_phc_time.p_time_l);
	//g_p_timer_h = m_phc_time.p_time_h;
	//g_p_timer_l = m_phc_time.p_time_l;
	//ibchtc_logerr("time_h : %lu, time_l: %lu", ntohl(*m_phc_time.p_time_h), ntohl(*m_phc_time.p_time_l));
	for (size_t i=0; i < ARRAY_SIZE(m_clock_values); i++) {
		memset(&m_clock_values[i], 0, sizeof(m_clock_values[i]));
		if (vma_ibv_query_clock_info(m_p_ibv_context, &m_clock_values[i])) {
			ibchtc_logerr("vma_ibv_query_clock_info failure for clock_info, (ibv context %p)", m_p_ibv_context);
		}
	}

	m_timer_handle = g_p_event_handler_manager->register_timer_event(UPDATE_HW_TIMER_PTP_PERIOD_MS, this, PERIODIC_TIMER, 0);
	m_converter_status = TS_CONVERSION_MODE_PTP;

	m_sock = orig_os_api.socket(AF_INET, SOCK_DGRAM, 0);

	if (m_sock < 0) {
		ibchtc_logerr("Failed to open PHC socket!");
		return;
	}

	bzero((char *)&m_addr, sizeof(m_addr));
	m_addr.sin_family = AF_INET;
	m_addr.sin_addr.s_addr = inet_addr("224.1.2.3");
	m_addr.sin_port = htons(4000);
	m_addrlen = sizeof(m_addr);
	m_ptp_fd = open("/dev/ptp0", O_RDWR);

	if (m_ptp_fd < 0) {
		ibchtc_logerr("failed to open PTP device");
	}
	else {
		m_ptp_id = get_clockid(m_ptp_fd);
	}
	return;

	timespec start;
	timespec end;
	timespec os_ts;
	uint64_t vma_avg = 0;
	uint64_t verbs_avg = 0;
	uint64_t os_avg = 0;
	uint64_t count_start = 0;
	uint64_t count_end = 0;
	uint64_t delta = 0;
	//vma_ibv_clock_info clock_inf;
/*
	gettime(&start);
	for (int i = 0; i < 1000000; ++i) {
		rmax_get_ptp_time_ns();
	}
	gettime(&end);
	count_start = start.tv_sec * 1000000000 + start.tv_nsec;
	count_end= end.tv_sec * 1000000000 + end.tv_nsec;
	delta = count_end - count_start;
	vma_avg = delta / 1000000;
*/
	gettime(&start);
	for (int i = 0; i < 1000000; ++i) {
		vma_ibv_query_clock(m_p_ibv_context, &m_clock_values[0]);
	}
	gettime(&end);
	count_start = start.tv_sec * 1000000000 + start.tv_nsec;
	count_end= end.tv_sec * 1000000000 + end.tv_nsec;
	delta = count_end - count_start;
	verbs_avg = delta / 1000000;

	gettime(&start);
	for (int i = 0; i < 1000000; ++i) {
		clock_gettime(m_ptp_id, &os_ts);
	}
	gettime(&end);
	count_start = start.tv_sec * 1000000000 + start.tv_nsec;
	count_end= end.tv_sec * 1000000000 + end.tv_nsec;
	delta = count_end - count_start;
	os_avg = delta / 1000000;

	ibchtc_logerr("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^vma_avg: %llu verbs_avg: %llu os_avg: %llu", vma_avg, verbs_avg, os_avg);

}

unsigned char* time_converter_ptp::serialize_int(unsigned char *buffer, uint32_t value)
{
	/* Write big-endian int value into buffer; assumes 32-bit int and 8-bit char. */
	buffer[0] = value >> 24;
	buffer[1] = value >> 16;
	buffer[2] = value >> 8;
	buffer[3] = value;
	return buffer + 4;
}

unsigned char* time_converter_ptp::serialize_long(unsigned char *buffer, uint64_t value)
{
	/* Write big-endian int value into buffer; assumes 32-bit int and 8-bit char. */
	buffer[0] = value >> 56;
	buffer[1] = value >> 48;
	buffer[2] = value >> 40;
	buffer[3] = value >> 32;
	buffer[4] = value >> 24;
	buffer[5] = value >> 16;
	buffer[6] = value >> 8;
	buffer[7] = value;
	return buffer + 8;

}

int time_converter_ptp::mlx5_read_clock(uint64_t *cycles)
{
	uint32_t clockhi, clocklo, clockhi1;
	int i;

	/* Handle wraparound */
	for (i = 0; i < 2; i++) {
		clockhi = ntohl(*m_phc_time.p_time_h);
		clocklo = ntohl(*m_phc_time.p_time_l);
		clockhi1 = ntohl(*m_phc_time.p_time_h);
		if (clockhi == clockhi1)
			break;
	}

	*cycles = (uint64_t)(clockhi & 0x7fffffff) << 32 | (uint64_t)clocklo;

	return 0;
}

uint64_t time_converter_ptp::rmax_get_ptp_time_ns()
{
	int index = m_clock_values_id;
	uint64_t ts = 0;
	uint64_t cycles;


	mlx5_read_clock(&cycles);

	uint64_t delta;

	//delta = (ts & m_clock_values[index].clock_info.mask) - m_clock_values[index].clock_info.cycles;
	delta = (cycles - m_clock_values[index].clock_info.cycles) & m_clock_values[index].clock_info.mask ;
	ts = m_clock_values[index].clock_info.nsec;

	/*
	 * delta should be within half the mask range otherwise
	 * below formula isn't correct.
	 */
	if (delta > m_clock_values[index].clock_info.mask / 2) {
		delta = (m_clock_values[index].clock_info.cycles - cycles) & m_clock_values[index].clock_info.mask;
		ts -= ((delta * m_clock_values[index].clock_info.mult) - m_clock_values[index].clock_info.frac) >> m_clock_values[index].clock_info.shift;
	}
	else {
		ts += ((delta * m_clock_values[index].clock_info.mult) + m_clock_values[index].clock_info.frac) >> m_clock_values[index].clock_info.shift;
	}

	return ts;

}

void time_converter_ptp::handle_timer_expired(void* user_data) {

	//ibchtc_logerr("handle_timer_expired");
	NOT_IN_USE(user_data);

	unsigned char buff[128];
	unsigned char* curr = &buff[0];

	if (is_cleaned()) {
		return;
	}

	int ret = 0;
	ret = vma_ibv_query_clock_info(m_p_ibv_context, &m_clock_values[1 - m_clock_values_id]);
	if (ret)
		ibchtc_logerr("vma_ibv_query_clock_info failure for clock_info, (ibv context %p) (return value=%d)", m_p_ibv_context, ret);

	m_clock_values_id = 1 - m_clock_values_id;

	if (safe_mce_sys().send_phc) {
		curr = serialize_long(curr, m_clock_values[m_clock_values_id].clock_info.cycles);
		curr = serialize_long(curr, m_clock_values[m_clock_values_id].clock_info.nsec);
		curr = serialize_long(curr, m_clock_values[m_clock_values_id].clock_info.frac);
		curr = serialize_long(curr, m_clock_values[m_clock_values_id].clock_info.mask);
		curr = serialize_int(curr, m_clock_values[m_clock_values_id].clock_info.shift);
		curr = serialize_int(curr, m_clock_values[m_clock_values_id].clock_info.mult);
		ret = vma_ibv_query_clock(m_p_ibv_context, &m_clock_values[m_clock_values_id]);
		uint64_t verbs_ts = vma_ibv_convert_ts_to_ns(&m_clock_values[m_clock_values_id], m_clock_values[m_clock_values_id].hwclock);
		curr = serialize_long(curr, verbs_ts);
		curr = serialize_long(curr, m_clock_values[m_clock_values_id].hwclock);

		ret = orig_os_api.sendto(m_sock, (void*)&buff[0], 56, 0, (struct sockaddr *)&m_addr, m_addrlen);

		if (ret < 0) {
			ibchtc_logerr("Failed to send");
		}
		ibchtc_logerr("cycles: %llu nsec: %llu, frac: %llu, mask: %llu, shift: %u, mult: %u",
					m_clock_values[m_clock_values_id].clock_info.cycles,
					m_clock_values[m_clock_values_id].clock_info.nsec,
					m_clock_values[m_clock_values_id].clock_info.frac,
					m_clock_values[m_clock_values_id].clock_info.mask,
					m_clock_values[m_clock_values_id].clock_info.shift,
					m_clock_values[m_clock_values_id].clock_info.mult);

		ibchtc_logerr("HW cycles: %llu Time: %llu:", m_clock_values[m_clock_values_id].hwclock, verbs_ts);
	}

	return;
	uint64_t os_ts = 0;
	//uint64_t os_ts2 = 0;
	struct timespec systime;

	clock_gettime(m_ptp_id, &systime);
	uint64_t vma_ts = 0; //rmax_get_ptp_time_ns(); //m_clock_values[m_clock_values_id].hwclock;
	uint64_t verbs_ts = m_clock_values[m_clock_values_id].hwclock;
	//os_ts = rmax_get_ptp_time_ns(); //m_clock_values[m_clock_values_id].hwclock;
	//ret = vma_ibv_query_clock(m_p_ibv_context, &m_clock_values[m_clock_values_id]);
	ret = vma_ibv_query_clock(m_p_ibv_context, &m_clock_values[m_clock_values_id]);
	/*if (unlikely(clock_gettime(m_ptp_id, &systime))) {
        ibchtc_logerr("Failed to read ptp time");
    }
    else {
        os_ts = systime.tv_nsec + 1000000000LL * systime.tv_sec;
    }*/

	//if (ret)
	//    ibchtc_logerr("vma_ibv_query_clock_info failure for clock_info, (ibv context %p) (return value=%d)", m_p_ibv_context, ret);

	//vma_ts = vma_ibv_convert_ts_to_ns(&m_clock_values[m_clock_values_id], vma_ts);
	verbs_ts = vma_ibv_convert_ts_to_ns(&m_clock_values[m_clock_values_id], m_clock_values[m_clock_values_id].hwclock);
	os_ts = systime.tv_nsec + 1000000000LL * systime.tv_sec;

	ibchtc_logdbg("VMA ptp time is %llu Verbs PTP time: %llu OS time: %llu", vma_ts, verbs_ts, os_ts);

	if (ret < 0) {
		ibchtc_logerr("Failed to send!");
	}
}

void time_converter_ptp::convert_hw_time_to_system_time(uint64_t hwtime, struct timespec* systime) {
	uint64_t sync_hw_clock = vma_ibv_convert_ts_to_ns(&m_clock_values[m_clock_values_id], hwtime);
	systime->tv_sec = sync_hw_clock / NSEC_PER_SEC;
	systime->tv_nsec = sync_hw_clock % NSEC_PER_SEC;

	ibchtc_logerr("hwtime: 	%09ld", hwtime);
	ibchtc_logerr("systime:	%lld.%.9ld", systime->tv_sec, systime->tv_nsec);
}
#endif //DEFINED_IBV_CLOCK_INFO
