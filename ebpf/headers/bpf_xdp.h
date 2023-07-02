// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

#ifndef __BPF_XDP_H_
#define __BPF_XDP_H_

#define VALIDATE_HEADER(hdr, ctx)                                              \
    do {                                                                       \
        if ((void *)(hdr + 1) > (void *)(__u64)(ctx->data_end))                \
            return XDP_PASS;                                                   \
    } while (0)

#endif // __BPF_XDP_H_