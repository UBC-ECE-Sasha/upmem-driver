/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020 UPMEM. All rights reserved. */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM upmem

#if !defined(_TRACE_UPMEM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_UPMEM_H

#include <linux/tracepoint.h>

TRACE_EVENT(upmem_command_read,

	    TP_PROTO(struct dpu_rank *rank, int slice_id, uint64_t command),

	    TP_ARGS(rank, slice_id, command),

	    TP_STRUCT__entry(__field(struct dpu_rank *, rank)
				     __field(int, slice_id)
					     __field(uint64_t, command)),

	    TP_fast_assign(__entry->rank = rank; __entry->slice_id = slice_id;
			   __entry->command = command;),

	    TP_printk("dpu_region%hhu:dpu_rank%hhu:slice%d 0x%llx",
		      __entry->rank->region->id, __entry->rank->id_in_region,
		      __entry->slice_id, __entry->command));

TRACE_EVENT(upmem_command_write,

	    TP_PROTO(struct dpu_rank *rank, int slice_id, uint64_t command),

	    TP_ARGS(rank, slice_id, command),

	    TP_STRUCT__entry(__field(struct dpu_rank *, rank)
				     __field(int, slice_id)
					     __field(uint64_t, command)),

	    TP_fast_assign(__entry->rank = rank; __entry->slice_id = slice_id;
			   __entry->command = command;),

	    TP_printk("dpu_region%hhu:dpu_rank%hhu:slice%d 0x%llx",
		      __entry->rank->region->id, __entry->rank->id_in_region,
		      __entry->slice_id, __entry->command));

#endif /* _TRACE_UPMEM_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE dpu_rank_tracepoints
#include <trace/define_trace.h>
