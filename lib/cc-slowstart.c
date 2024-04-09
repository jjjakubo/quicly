/*
 * TODO: Copyright
 */
#include "quicly/cc.h"
#include "quicly.h"

/**
 * slowstart callback functions
 */
static int basic_slowstart_on_acked(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t largest_acked, uint32_t inflight,
                                    int cc_limited, uint64_t next_pn, int64_t now, uint32_t max_udp_payload_size);
static int search_slowstart_on_acked(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t largest_acked, uint32_t inflight,
                                     int cc_limited, uint64_t next_pn, int64_t now, uint32_t max_udp_payload_size);

int quicly_cc_slowstart_on_ack(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t largest_acked, uint32_t inflight,
                               int cc_limited, uint64_t next_pn, int64_t now, uint32_t max_udp_payload_size)
{
    if( cc->flags.use_slowstart_search != 0 ) {
        return search_slowstart_on_acked(cc, loss, bytes, largest_acked,
                                         inflight, cc_limited, next_pn, now, max_udp_payload_size);
    }
    return basic_slowstart_on_acked(cc, loss, bytes, largest_acked,
                                    inflight, cc_limited, next_pn, now, max_udp_payload_size);
}

static int basic_slowstart_on_acked(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t largest_acked, uint32_t inflight,
                             int cc_limited, uint64_t next_pn, int64_t now, uint32_t max_udp_payload_size)
{
    if (cc->cwnd < cc->ssthresh) {
        if (cc_limited) {
            cc->cwnd += bytes;
            if (cc->cwnd_maximum < cc->cwnd)
                cc->cwnd_maximum = cc->cwnd;
        }
        return 1;
    }
    return 0;
}

static float search_calc_threshold(quicly_cc_t *cc)
{
    uint32_t sum_sent = 0U;
    uint32_t sum_delv = 0U;

    uint32_t index = cc->state.search.bin_index;

    for( uint32_t i=0; i<=index; i++ )
    {
        if( i != index )
            sum_delv += cc->state.search.delv[i];

        sum_sent += cc->state.search.sent[i];
    }

    if( sum_sent <= 0U )
        return 0U;

    return ( (float)sum_sent - (float)sum_delv ) / ((float)sum_sent);
}

static int search_slowstart_on_acked(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t largest_acked, uint32_t inflight,
                              int cc_limited, uint64_t next_pn, int64_t now, uint32_t max_udp_payload_size)
{
    assert(inflight >= bytes);
    if (cc->cwnd >= cc->ssthresh) {
        return 0;
    }

    if( cc->state.search.init == 0 ) {
        printf("%s@%d\n", __FILE__, __LINE__ );
        memset(cc->state.search.sent, 0U, sizeof(uint32_t) * CCSEARCH_NUMBINS );
        memset(cc->state.search.delv, 0U, sizeof(uint32_t) * CCSEARCH_NUMBINS );
        cc->state.search.bin_index = 0;
        cc->state.search.bin_end = now + CCSEARCH_BINTIME;
        cc->state.search.init = 1;
        printf("%s@%d\n", __FILE__, __LINE__ );
    }

    if( cc->state.search.bin_end == 0 )
        cc->state.search.bin_end = now; // after reset

    // update time bin
    uint32_t index = cc->state.search.bin_index;
    if( now > cc->state.search.bin_end )
    {
        cc->state.search.bin_end += CCSEARCH_BINTIME;
        index = (cc->state.search.bin_index+1) % CCSEARCH_NUMBINS;
        cc->state.search.bin_index = index;
        cc->state.search.sent[index] = 0U;
        cc->state.search.delv[index] = 0U;
    }

    cc->state.search.delv[index] += bytes;

    float threshold = search_calc_threshold(cc); // calc current threshold
    if( threshold > CCSEARCH_THRESH )
    {
        uint32_t newcc = cc->state.search.delv[index];
        cc->ssthresh = newcc;
        printf("CCA: %uld\n", cc->ssthresh);
    }
    return 1;
}
