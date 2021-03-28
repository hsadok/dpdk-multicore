/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <signal.h>
#include <getopt.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_vect.h>
#include <rte_jhash.h>

// uncomment to disable TX path
#define DISABLE_TX

#define RX_RING_SIZE 8192
#define TX_RING_SIZE 1024
#define MIN_NUM_MBUFS 8192
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 64
#define X_RX_RING_SIZE (4 * BURST_SIZE)
#define X_TX_RING_SIZE (4 * BURST_SIZE)

#define CMD_OPT_HELP "help"
#define CMD_OPT_BUSY_CYCLES "busy-cycles"
#define CMD_OPT_SOFT_LB "soft-lb"
#define CMD_OPT_SOFT_LB_HASH "hash"
#define CMD_OPT_Q_PER_CORE "q-per-core"
enum {
    /* long options mapped to short options: first long only option value must
    * be >= 256, so that it does not conflict with short options.
    */
    CMD_OPT_HELP_NUM = 256,
    CMD_OPT_BUSY_CYCLES_NUM,
    CMD_OPT_SOFT_LB_NUM,
    CMD_OPT_SOFT_LB_HASH_NUM,
    CMD_OPT_Q_PER_CORE_NUM
};

static void print_usage(const char* program_name) {
    printf("%s [EAL options] --"
        " [--help] |\n"
        " [--busy-cycles NUM_OF_BUSY_CYCLES]\n"
        " [--soft-lb]\n"
        " [--hash]\n"
        " [--q-per-core]\n\n"

        "  --help: Show this help and exit\n"
        "  --busy-cycles NUM_OF_BUSY_CYCLES: Busy CPU cycles for each packet\n"
        "  --soft-lb: Enable software load balancer\n"
        "  --hash: Use hash to load balance flows when using software LB\n"
        "  --q-per-core: Number of queues per core (only used with RSS)\n",
        program_name);
}

/* if we ever need short options, add to this string */
static const char short_options[] = "";

static const struct option long_options[] = {
    {CMD_OPT_HELP, no_argument, NULL, CMD_OPT_HELP_NUM},
    {CMD_OPT_BUSY_CYCLES, required_argument, NULL, CMD_OPT_BUSY_CYCLES_NUM},
    {CMD_OPT_SOFT_LB, no_argument, NULL, CMD_OPT_SOFT_LB_NUM},
    {CMD_OPT_SOFT_LB_HASH, no_argument, NULL, CMD_OPT_SOFT_LB_HASH_NUM},
    {CMD_OPT_Q_PER_CORE, required_argument, NULL, CMD_OPT_Q_PER_CORE_NUM},
    {0, 0, 0, 0}
};

struct parsed_args_t {
  uint32_t busy_cycles;
  bool soft_lb;
  bool hash;
  uint32_t q_per_core;
};

static int parse_args(int argc, char** argv, struct parsed_args_t* parsed_args)
{
    int opt;
    int long_index;

    parsed_args->busy_cycles = 0;
    parsed_args->soft_lb = false;
    parsed_args->hash = false;
    parsed_args->q_per_core = 1;

    while ((opt = getopt_long(argc, argv, short_options, long_options,
           &long_index)) != EOF) {
        switch (opt) {
          case CMD_OPT_HELP_NUM:
            return 1;
          case CMD_OPT_BUSY_CYCLES_NUM:
            parsed_args->busy_cycles = atoi(optarg);
            break;
          case CMD_OPT_SOFT_LB_NUM:
            parsed_args->soft_lb = true;
            break;
          case CMD_OPT_SOFT_LB_HASH_NUM:
            parsed_args->hash = true;
            break;
          case CMD_OPT_Q_PER_CORE_NUM:
            parsed_args->q_per_core = atoi(optarg);
            break;
          default:
            return -1;
        }
    }

    return 0;
}

/* Inspired by NetBricks options */
static const struct rte_eth_conf port_conf_default = {
    .link_speeds = ETH_LINK_SPEED_AUTONEG, /* auto negotiate speed */
    .lpbk_mode = 0,
    .rxmode =
        {
            .mq_mode = ETH_MQ_RX_RSS, /* Use none of CDB, RSS or VMDQ */
        },
    .txmode =
        {
            .mq_mode = ETH_MQ_TX_NONE, /* Disable DCB and VMDQ */
        },
    .intr_conf = /* No interrupt */
        {
            .lsc = 0,
            .rxq = 0,
            .rmv = 0,
        },
};

volatile bool quit;
static uint32_t busy_cycles;
static uint32_t q_per_core;

static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %i (%s) received, preparing to exit...\n", signum,
            strsignal(signum));
        quit = true;
    }
}

/* Check if the port is on the same NUMA node as the polling thread */
__rte_always_inline void
warn_if_not_same_numa(uint8_t port)
{
    if (rte_eth_dev_socket_id(port) > 0 &&
            rte_eth_dev_socket_id(port) != (int) rte_socket_id()) {
        printf("Port %"PRIu8 " is on remote NUMA node\n", port);
    }
}


union ipv4_5tuple_t {
    struct {
        uint8_t  pad0;
        uint8_t  proto;
        uint16_t pad1;
        uint32_t ip_src;
        uint32_t ip_dst;
        uint16_t port_src;
        uint16_t port_dst;
    };
    uint32_t u32[4];
    xmm_t xmm;
};

static rte_xmm_t ipv4_5tuple_mask = {
    .u32 = {
        0x0000ff00, /* protocol */
        0xffffffff, /* source IPv4 */
        0xffffffff, /* destination IPv4 */
        0xffffffff  /* src port and dest port */
    }
};

static __rte_always_inline uint32_t
five_tuple_jhash(const void *key, __attribute__((unused)) uint32_t length,
                 uint32_t initval)
{
    /* We know it is TCP; therefore we ignore the protocol for hashing. */
    const union ipv4_5tuple_t* five_tuple = (const union ipv4_5tuple_t*) key;
    return rte_jhash_3words(five_tuple->u32[1], five_tuple->u32[2],
                            five_tuple->u32[3], initval); 
}

static __rte_always_inline void
get_ipv4_5tuple(struct rte_mbuf *pkt, union ipv4_5tuple_t *key)
{
    __m128i tmpdata0 = _mm_loadu_si128(rte_pktmbuf_mtod_offset(
        pkt,
        __m128i *, 
        sizeof(struct rte_ether_hdr)
            + offsetof(struct rte_ipv4_hdr, time_to_live)
    ));
    key->xmm = _mm_and_si128(tmpdata0, ipv4_5tuple_mask.x);
}

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool, uint16_t rx_rings, 
          uint16_t tx_rings, bool disable_rss)
{
    struct rte_eth_conf port_conf = port_conf_default;
    // const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (disable_rss) {
        rx_rings = tx_rings = 1;
    }

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error during getting device (port %u) info: %s\n",
                port, strerror(-retval));
        return retval;
    }

    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |=
            DEV_TX_OFFLOAD_MBUF_FAST_FREE;

    if (!disable_rss) {
        port_conf.rx_adv_conf.rss_conf.rss_hf = dev_info.flow_type_rss_offloads;
    }

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;

    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }

    /* Start the Ethernet port. */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    /* Display the port MAC address. */
    struct rte_ether_addr addr;
    retval = rte_eth_macaddr_get(port, &addr);
    if (retval != 0)
        return retval;

    printf("Port %u MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
               ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 "\n",
            port,
            addr.addr_bytes[0], addr.addr_bytes[1],
            addr.addr_bytes[2], addr.addr_bytes[3],
            addr.addr_bytes[4], addr.addr_bytes[5]);

    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0)
        return retval;

    return 0;
}

static int
lcore_work(void* arg)
{
    uint32_t first_queue = (uint32_t) (uint64_t) arg;
    struct rte_mbuf *bufs[BURST_SIZE];
    unsigned lcore_id;
    struct rte_ether_addr original_src_mac;
    // struct rte_ether_addr original_dst_mac;
    uint32_t original_src_ip;
    uint32_t nb_queues = q_per_core;

    uint64_t* rx_stats = rte_zmalloc(
        "rx_stats", nb_queues * 8, RTE_CACHE_LINE_SIZE);
    uint64_t* tx_stats = rte_zmalloc(
        "tx_stats", nb_queues * 8, RTE_CACHE_LINE_SIZE);

    lcore_id = rte_lcore_id();

    printf("Starting core %u with first queue %u\n", lcore_id, first_queue);

    warn_if_not_same_numa(0);

    /* Run until the application is quit or killed. */
    while (!quit) {
        for (uint32_t q_offset = 0; q_offset < nb_queues; ++q_offset) {
            const uint32_t queue = first_queue + q_offset;
            const uint16_t nb_rx = rte_eth_rx_burst(0, queue, bufs, BURST_SIZE);
            if (unlikely(nb_rx == 0)) {
                continue;
            }

            rx_stats[q_offset] += nb_rx;

            for (uint16_t i = 0; i < nb_rx; ++i) {
                
                struct rte_ether_hdr* ether_hdr =
                    rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
                struct rte_ipv4_hdr* ipv4_hdr =
                    rte_pktmbuf_mtod_offset(bufs[i], struct rte_ipv4_hdr *,
                                            sizeof(struct rte_ether_hdr));
                original_src_mac = ether_hdr->s_addr;
                ether_hdr->s_addr = ether_hdr->d_addr;
                ether_hdr->d_addr = original_src_mac;
                // original_dst_mac = ether_hdr->d_addr;
                // void *tmp = &ether_hdr->d_addr.addr_bytes[0];
                // *((uint64_t *)tmp) = 0x000000000000;
                // ether_hdr->s_addr = original_dst_mac;

                original_src_ip = ipv4_hdr->src_addr;
                ipv4_hdr->src_addr = ipv4_hdr->dst_addr;
                ipv4_hdr->dst_addr = original_src_ip;

                for (uint32_t j = 0; j < busy_cycles; ++j) {
                    asm("nop");
                }
            }

            #ifdef DISABLE_TX
                uint16_t buf;
                for (buf = 0; buf < nb_rx; buf++) {
                    rte_pktmbuf_free(bufs[buf]);
                }
            #else
                const uint16_t nb_tx = rte_eth_tx_burst(0, queue, bufs, nb_rx);

                tx_stats[q_offset] += nb_tx;

                /* Free any unsent packets. */
                if (unlikely(nb_tx < nb_rx)) {
                    uint16_t buf;
                    for (buf = nb_tx; buf < nb_rx; buf++) {
                        rte_pktmbuf_free(bufs[buf]);
                    }
                }
            #endif
        }
    }
    uint64_t total_tx = 0;
    uint64_t total_rx = 0;
    for (uint32_t q_offset = 0; q_offset < nb_queues; ++q_offset) {
        uint32_t queue = first_queue + q_offset;
        printf("core %u (queue %u): rx: %lu  tx: %lu\n",
               lcore_id, queue, rx_stats[q_offset], tx_stats[q_offset]);
        total_rx += rx_stats[q_offset];
        total_tx += tx_stats[q_offset];
    }
    printf("core %u (total)   : rx: %lu  tx: %lu\n\n",
           lcore_id, total_rx, total_tx);
    return 0;
}

struct ring_pair {
    struct rte_ring* rx;
    struct rte_ring* tx;
};

static int
soft_lb_lcore_work(void* arg)
{
    struct ring_pair* rings = (struct ring_pair*) arg;
    struct rte_ring* rx_ring = rings->rx;
    struct rte_mbuf *bufs[BURST_SIZE];
    unsigned lcore_id;
    uint64_t rx_stats, tx_stats;

    #ifndef DISABLE_TX
        struct rte_ether_addr original_src_mac;
        // struct rte_ether_addr original_dst_mac;
        uint32_t original_src_ip;
        struct rte_ring* tx_ring = rings->tx;
    #endif

    rx_stats = 0;
    tx_stats = 0;

    lcore_id = rte_lcore_id();

    printf("Starting core %u\n", lcore_id);

    warn_if_not_same_numa(0);

    /* Run until the application is quit or killed. */
    while (!quit) {
        const uint16_t nb_rx = rte_ring_sc_dequeue_burst(rx_ring,
                (void*) bufs, BURST_SIZE, NULL);

        if (unlikely(nb_rx == 0)) {
            continue;
        }

        rx_stats += nb_rx;

        #ifdef DISABLE_TX
            uint16_t buf;
            for (buf = 0; buf < nb_rx; buf++) {
                rte_pktmbuf_free(bufs[buf]);
            }
        #else
            for (uint16_t i = 0; i < nb_rx; ++i) {
                struct rte_ether_hdr* ether_hdr =
                    rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
                struct rte_ipv4_hdr* ipv4_hdr =
                    rte_pktmbuf_mtod_offset(bufs[i], struct rte_ipv4_hdr *,
                                            sizeof(struct rte_ether_hdr));
                original_src_mac = ether_hdr->s_addr;
                ether_hdr->s_addr = ether_hdr->d_addr;
                ether_hdr->d_addr = original_src_mac;
                // original_dst_mac = ether_hdr->d_addr;
                // void *tmp = &ether_hdr->d_addr.addr_bytes[0];
                // *((uint64_t *)tmp) = 0x000000000000;
                // ether_hdr->s_addr = original_dst_mac;

                original_src_ip = ipv4_hdr->src_addr;
                ipv4_hdr->src_addr = ipv4_hdr->dst_addr;
                ipv4_hdr->dst_addr = original_src_ip;

                for (uint32_t j = 0; j < busy_cycles; ++j) {
                    asm("nop");
                }
            }
            const uint16_t nb_tx =
                rte_ring_sp_enqueue_burst(tx_ring, (void*) bufs, nb_rx, NULL);

            tx_stats += nb_tx;

            /* Free any unsent packets. */
            if (unlikely(nb_tx < nb_rx)) {
                uint16_t buf;
                for (buf = nb_tx; buf < nb_rx; buf++) {
                    rte_pktmbuf_free(bufs[buf]);
                }
            }
        #endif
    }

    printf("core %u: rx: %lu  tx: %lu\n", lcore_id, rx_stats, tx_stats);

    return 0;
}

static int
batch_load_balancer(uint16_t nb_cores, struct rte_ring **rx_rings,
                    struct rte_ring **tx_rings)
{
    struct rte_mbuf *bufs[BURST_SIZE];
    unsigned lcore_id;
    uint64_t rx_stats, tx_stats;

    rx_stats = 0;
    tx_stats = 0;

    lcore_id = rte_lcore_id();

    warn_if_not_same_numa(0);

    /* Run until the application quits or is killed. */
    uint16_t current_core = 0;
    while (!quit) {
        uint16_t nb_rx = rte_eth_rx_burst(0, 0, bufs, BURST_SIZE);
        rx_stats += nb_rx;

        uint16_t nb_tx = rte_ring_sp_enqueue_burst(
            rx_rings[current_core], (void*) bufs, nb_rx, NULL);

        /* Free any unsent packets. */
        if (unlikely(nb_tx < nb_rx)) {
            uint16_t buf;
            for (buf = nb_tx; buf < nb_rx; buf++) {
                rte_pktmbuf_free(bufs[buf]);
            }
        }

        nb_rx = rte_ring_sc_dequeue_burst(
            tx_rings[current_core], (void*) bufs, BURST_SIZE, NULL);
        

        #ifndef DISABLE_TX
            nb_tx = rte_eth_tx_burst(0, 0, bufs, nb_rx);
            tx_stats += nb_tx;

            /* Free any unsent packets. */
            if (unlikely(nb_tx < nb_rx)) {
                uint16_t buf;
                for (buf = nb_tx; buf < nb_rx; buf++) {
                    rte_pktmbuf_free(bufs[buf]);
                }
            }
        #endif
        if (++current_core == nb_cores) {
            current_core = 0;
        }
    }

    printf("LOAD BALANCER (%i): rx: %lu  tx: %lu\n",
           lcore_id, rx_stats, tx_stats);

    return 0;
}

static int
hash_load_balancer(uint16_t nb_cores, struct rte_ring **rx_rings,
                   struct rte_ring **tx_rings)
{
    unsigned lcore_id;
    uint64_t rx_stats, tx_stats;
    uint16_t rx_by_core[nb_cores];
    struct rte_mbuf *bufs[nb_cores][BURST_SIZE];

    rx_stats = 0;
    tx_stats = 0;

    lcore_id = rte_lcore_id();

    warn_if_not_same_numa(0);

    for (uint16_t i = 0; i < nb_cores; ++i) {
        rx_by_core[i] = 0;
    }

    /* Run until the application quits or is killed. */
    while (!quit) {
        uint16_t nb_rx = rte_eth_rx_burst(0, 0, bufs[0], BURST_SIZE);
        rx_stats += nb_rx;

        for (uint16_t i = 0; i < nb_rx; ++i) {
            union ipv4_5tuple_t five_tuple;

            get_ipv4_5tuple(bufs[0][i], &five_tuple);
              uint32_t hash = five_tuple_jhash(&five_tuple, 0, 0);
            uint16_t core = hash % nb_cores;
            bufs[core][rx_by_core[core]++] = bufs[0][i];
        }

        for (uint16_t i = 0; i < nb_cores; ++i) {
            uint16_t nb_tx = rte_ring_sp_enqueue_burst(
                rx_rings[i], (void*) bufs[i], rx_by_core[i], NULL);
            /* Free any unsent packets. */
            if (unlikely(nb_tx < rx_by_core[i])) {
                uint16_t buf;
                for (buf = nb_tx; buf < rx_by_core[i]; buf++) {
                    rte_pktmbuf_free(bufs[i][buf]);
                }
            }
            rx_by_core[i] = 0;
        }

        nb_rx = 0;
        for (uint16_t i = 0; i < nb_cores; ++i) {
            nb_rx += rte_ring_sc_dequeue_burst(
                tx_rings[i], (void*) (bufs[0] + nb_rx), BURST_SIZE, NULL);
        }

        #ifndef DISABLE_TX
            uint16_t nb_tx = rte_eth_tx_burst(0, 0, bufs[0], nb_rx);
            tx_stats += nb_tx;

            /* Free any unsent packets. */
            if (unlikely(nb_tx < nb_rx)) {
                uint16_t buf;
                for (buf = nb_tx; buf < nb_rx; buf++) {
                    rte_pktmbuf_free(bufs[0][buf]);
                }
            }
        #endif
    }

    printf("LOAD BALANCER (%i): rx: %lu  tx: %lu\n",
           lcore_id, rx_stats, tx_stats);

    return 0;
}

int
main(int argc, char *argv[])
{
    struct rte_mempool *mbuf_pool;
    unsigned nb_ports;
    struct parsed_args_t parsed_args;

    quit = false;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Initialize the Environment Abstraction Layer (EAL). */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }
    argc -= ret;
    argv += ret;

    ret = parse_args(argc, argv, &parsed_args);
    if (ret) {
        print_usage(argv[0]);
        if (ret == 1) {
            return 0;
        }
        rte_exit(EXIT_FAILURE, "Invalid CLI options\n");
    }

    busy_cycles = parsed_args.busy_cycles;
    q_per_core = parsed_args.q_per_core;
    bool soft_lb = parsed_args.soft_lb;

    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports != 1) {
        rte_exit(EXIT_FAILURE, "Error: support only for one port\n");
    }

    uint16_t slave_lcore_count = rte_lcore_count() - 1;

    printf("Using %u slaves\n", slave_lcore_count);

    unsigned mbuf_entries = 
        nb_ports * slave_lcore_count * q_per_core * RX_RING_SIZE +
        nb_ports * slave_lcore_count * q_per_core * BURST_SIZE +
        nb_ports * slave_lcore_count * q_per_core * TX_RING_SIZE +
        slave_lcore_count * q_per_core * MBUF_CACHE_SIZE;
    
    mbuf_entries = RTE_MAX(mbuf_entries, (unsigned) MIN_NUM_MBUFS);
    /* Creates a new mempool in memory to hold the mbufs. */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", mbuf_entries,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initialize all ports. */
    if (port_init(0, mbuf_pool, slave_lcore_count * q_per_core, 
                  slave_lcore_count * q_per_core, soft_lb))
        rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", 0);

    unsigned lcore_id;

    if (soft_lb) {
        printf("Software LB\n");
        struct rte_ring **rx_rings, **tx_rings;
        struct ring_pair *ring_pairs;

        rx_rings = rte_zmalloc("rings",
            sizeof(struct rte_ring*) * slave_lcore_count * 2,
            RTE_CACHE_LINE_SIZE);
        if (rx_rings == NULL) {
            rte_exit(EXIT_FAILURE, "Failed to allocate ring pointers\n");
        }
        tx_rings = rx_rings + slave_lcore_count;

        ring_pairs = rte_zmalloc("ring_pairs",
            sizeof(struct ring_pair) * slave_lcore_count, RTE_CACHE_LINE_SIZE);
        if (ring_pairs == NULL) {
            rte_free(rx_rings);
            rte_exit(EXIT_FAILURE, "Failed to allocate ring pairs\n");
        }

        uint16_t i = 0;
        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
            char ring_name[50];

            snprintf(ring_name, 50, "rx_ring%03u", lcore_id);
            uint8_t slave_socket_id = rte_lcore_to_socket_id(lcore_id);

            struct rte_ring* ring = rte_ring_create(ring_name, X_RX_RING_SIZE,
                slave_socket_id, RING_F_SC_DEQ | RING_F_SP_ENQ);
            if (ring == NULL) {
                rte_free(rx_rings);
                rte_exit(EXIT_FAILURE, "Failed to create rings\n");
            }
            rx_rings[i] = ring;

            ring_name[0] = 't';
            ring = rte_ring_create(ring_name, X_TX_RING_SIZE,
                slave_socket_id, RING_F_SC_DEQ | RING_F_SP_ENQ);
            if (ring == NULL) {
                rte_free(rx_rings);
                rte_exit(EXIT_FAILURE, "Failed to create rings\n");
            }

            tx_rings[i] = ring;
            ++i;
        }

        i = 0;
        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
            ring_pairs[i].rx = rx_rings[i];
            ring_pairs[i].tx = tx_rings[i];
            rte_eal_remote_launch(
                soft_lb_lcore_work, (void*) &ring_pairs[i], lcore_id);
            ++i;
        }

        if (parsed_args.hash) {
            hash_load_balancer(slave_lcore_count, rx_rings, tx_rings);
        } else {
            batch_load_balancer(slave_lcore_count, rx_rings, tx_rings);
        }

        rte_eal_mp_wait_lcore();

        rte_free(ring_pairs);
        rte_free(rx_rings);
    } else {
        uint64_t queue = 0;
        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
            rte_eal_remote_launch(lcore_work, (void*) queue, lcore_id);
            queue += q_per_core;
        }

        rte_eal_mp_wait_lcore();
    }

    return 0;
}
