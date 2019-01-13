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


#ifndef TIME_CONVERTER_PTP_H
#define TIME_CONVERTER_PTP_H
extern "C" {
    #include <infiniband/verbs.h>
}
#include "vma/event/timer_handler.h"
#include <vma/util/sys_vars.h>
#include "time_converter.h"

#ifdef DEFINED_IBV_CLOCK_INFO

struct phc_time {
    uint32_t* p_time_h;
    uint32_t* p_time_l;
};

class time_converter_ptp : public time_converter
{
public:
	time_converter_ptp(struct ibv_context* ctx);
	virtual ~time_converter_ptp() {};

	inline void               convert_hw_time_to_system_time(uint64_t hwtime, struct timespec* systime);
	virtual void              handle_timer_expired(void* user_data);
	int                       mlx5_read_clock(uint64_t *cycles);
	uint64_t                  rmax_get_ptp_time_ns();

private:
	unsigned char* serialize_int(unsigned char *buffer, uint32_t value);
	unsigned char* serialize_long(unsigned char *buffer, uint64_t value);
	struct ibv_context*       m_p_ibv_context;

	vma_ibv_clock_info        m_clock_values[2];
	struct phc_time           m_phc_time;
	int                       m_clock_values_id;
	int                       m_sock;
    struct sockaddr_in        m_addr;
    int                       m_addrlen;
    int                       m_ptp_fd;
    clockid_t                 m_ptp_id;
};

#endif // DEFINED_IBV_CLOCK_INFO
#endif // TIME_CONVERTER_PTP_H
