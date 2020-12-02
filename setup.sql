CREATE TABLE flows
(
    `begin_at` DateTime64(3) CODEC(DoubleDelta),
    `end_at` DateTime64(3) CODEC(DoubleDelta),
    `vlan` UInt16 CODEC(Gorilla),
    `ipv` UInt8 CODEC(NONE),
    `ipproto` UInt8 CODEC(NONE),
    `saddr` FixedString(16) CODEC(ZSTD(3)),
    `daddr` FixedString(16) CODEC(ZSTD(3)),
    `sport` UInt16 CODEC(NONE),
    `dport` UInt16 CODEC(NONE),
    `gre_key` UInt32 CODEC(Gorilla),
    `packets` UInt64 CODEC(Gorilla),
    `bytes` UInt64 CODEC(Gorilla),
    `syns` UInt32 CODEC(Gorilla),
    `fins` UInt32 CODEC(Gorilla),
    `rsts` UInt32 CODEC(Gorilla),
    INDEX begin_at_idx begin_at TYPE minmax GRANULARITY 2048,
    INDEX end_at_idx end_at TYPE minmax GRANULARITY 2048
)
ENGINE = SummingMergeTree()
PARTITION BY toStartOfDay(begin_at)
ORDER BY (vlan, ipv, ipproto, saddr, daddr, sport, dport, gre_key, begin_at, end_at)
TTL toDateTime(end_at) + toIntervalHour(4);

CREATE TABLE flowstats
(
    `begin_at` DateTime64(3) CODEC(DoubleDelta),
    `end_at` DateTime64(3) CODEC(DoubleDelta),
    `user_ms` UInt32 CODEC(Gorilla),
    `kern_ms` UInt32 CODEC(Gorilla),
    `reads` UInt64 CODEC(Gorilla),
    `packets` UInt64 CODEC(Gorilla),
    `bytes` UInt64 CODEC(Gorilla),
    `flows` UInt32 CODEC(Gorilla),
    `pcap_recv` UInt32 CODEC(Gorilla),
    `pcap_drop` UInt32 CODEC(Gorilla),
    `pcap_ifdrop` UInt32 CODEC(Gorilla),
    INDEX begin_at_idx begin_at TYPE minmax GRANULARITY 2048,
    INDEX end_at_idx end_at TYPE minmax GRANULARITY 2048
)
ENGINE = SummingMergeTree()
PARTITION BY toStartOfDay(begin_at)
ORDER BY (begin_at, end_at)
TTL toDateTime(end_at) + toIntervalHour(4);

CREATE TABLE dns_lookups
(
    `begin_at` DateTime64(3) CODEC(DoubleDelta),
    `end_at` DateTime64(3) CODEC(DoubleDelta),
    `saddr` FixedString(16) CODEC(ZSTD(1)),
    `daddr` FixedString(16) CODEC(ZSTD(1)),
    `sport` UInt16 CODEC(Gorilla),
    `dport` UInt16 CODEC(Gorilla),
    `qid` UInt16 CODEC(Gorilla),
    `name` String CODEC(ZSTD(1)),
    INDEX begin_at_idx begin_at TYPE minmax GRANULARITY 1024,
    INDEX end_at_idx end_at TYPE minmax GRANULARITY 1024
)
ENGINE = MergeTree()
PARTITION BY toStartOfDay(begin_at)
ORDER BY (saddr, daddr, sport, dport, qid, begin_at, end_at);

CREATE TABLE rdns
(
    `begin_at` DateTime64(3) CODEC(DoubleDelta),
    `end_at` DateTime64(3) CODEC(DoubleDelta),
    `addr` FixedString(16) CODEC(ZSTD(1)),
    `name` String CODEC(ZSTD(1)),
    INDEX end_at_idx end_at TYPE minmax GRANULARITY 1024,
    INDEX begin_at_idx begin_at TYPE minmax GRANULARITY 1024
)
ENGINE = MergeTree()
PARTITION BY toStartOfDay(end_at)
ORDER BY (addr, end_at, begin_at);

CREATE MATERIALIZED VIEW flows_5sec
(
    `interval` DateTime CODEC(DoubleDelta),
    `vlan` UInt16 CODEC(Gorilla),
    `ipv` UInt8 CODEC(NONE),
    `ipproto` UInt8 CODEC(NONE),
    `saddr` FixedString(16) CODEC(ZSTD(3)),
    `daddr` FixedString(16) CODEC(ZSTD(3)),
    `sport` UInt16 CODEC(Gorilla),
    `dport` UInt16 CODEC(Gorilla),
    `gre_key` UInt32 CODEC(Gorilla),
    `packets` UInt64 CODEC(Gorilla),
    `bytes` UInt64 CODEC(Gorilla),
    `syns` UInt64 CODEC(Gorilla),
    `fins` UInt64 CODEC(Gorilla),
    `rsts` UInt64 CODEC(Gorilla),
    INDEX interval_idx interval TYPE minmax GRANULARITY 2048,
    INDEX daddr_idx daddr TYPE bloom_filter(0.025) GRANULARITY 8192,
    INDEX daddrport_idx (ipproto, daddr, dport) TYPE bloom_filter(0.025) GRANULARITY 8192,
    INDEX dport_idx (ipproto, dport) TYPE bloom_filter(0.025) GRANULARITY 8192
)
ENGINE = SummingMergeTree
PARTITION BY toStartOfDay(interval)
ORDER BY (vlan, ipv, ipproto, saddr, daddr, sport, dport, gre_key, interval)
AS SELECT
    toStartOfInterval(begin_at, toIntervalSecond(5)) AS interval,
    vlan, ipv, ipproto, saddr, daddr, sport, dport, gre_key,
    sum(packets) AS packets,
    sum(bytes) AS bytes,
    sum(syns) AS syns,
    sum(fins) AS fins,
    sum(rsts) AS rsts
FROM flows
GROUP BY
    interval, vlan, ipv, ipproto, saddr, daddr, sport, dport, gre_key;

CREATE MATERIALIZED VIEW flows_1min
(
    `interval` DateTime CODEC(DoubleDelta),
    `vlan` UInt16 CODEC(Gorilla),
    `ipv` UInt8 CODEC(NONE),
    `ipproto` UInt8 CODEC(NONE),
    `saddr` FixedString(16) CODEC(ZSTD(3)),
    `daddr` FixedString(16) CODEC(ZSTD(3)),
    `sport` UInt16 CODEC(Gorilla),
    `dport` UInt16 CODEC(Gorilla),
    `gre_key` UInt32 CODEC(Gorilla),
    `packets` UInt64 CODEC(Gorilla),
    `bytes` UInt64 CODEC(Gorilla),
    `syns` UInt64 CODEC(Gorilla),
    `fins` UInt64 CODEC(Gorilla),
    `rsts` UInt64 CODEC(Gorilla),
    INDEX interval_idx interval TYPE minmax GRANULARITY 2048,
    INDEX daddr_idx daddr TYPE bloom_filter(0.025) GRANULARITY 8192,
    INDEX daddrport_idx (ipproto, daddr, dport) TYPE bloom_filter(0.025) GRANULARITY 8192,
    INDEX dport_idx (ipproto, dport) TYPE bloom_filter(0.025) GRANULARITY 8192
)
ENGINE = SummingMergeTree
PARTITION BY toStartOfDay(interval)
ORDER BY (vlan, ipv, ipproto, saddr, daddr, sport, dport, gre_key, interval)
AS SELECT
    toStartOfInterval(begin_at, toIntervalSecond(60)) AS interval,
    vlan, ipv, ipproto, saddr, daddr, sport, dport, gre_key,
    sum(packets) AS packets,
    sum(bytes) AS bytes,
    sum(syns) AS syns,
    sum(fins) AS fins,
    sum(rsts) AS rsts
FROM flows
GROUP BY
    interval, vlan, ipv, ipproto, saddr, daddr, sport, dport, gre_key;

CREATE MATERIALIZED VIEW flows_5min
(
    `interval` DateTime CODEC(DoubleDelta),
    `vlan` UInt16 CODEC(Gorilla),
    `ipv` UInt8 CODEC(NONE),
    `ipproto` UInt8 CODEC(NONE),
    `saddr` FixedString(16) CODEC(ZSTD(3)),
    `daddr` FixedString(16) CODEC(ZSTD(3)),
    `sport` UInt16 CODEC(Gorilla),
    `dport` UInt16 CODEC(Gorilla),
    `gre_key` UInt32 CODEC(Gorilla),
    `packets` UInt64 CODEC(Gorilla),
    `bytes` UInt64 CODEC(Gorilla),
    `syns` UInt64 CODEC(Gorilla),
    `fins` UInt64 CODEC(Gorilla),
    `rsts` UInt64 CODEC(Gorilla),
    INDEX interval_idx interval TYPE minmax GRANULARITY 2048,
    INDEX daddr_idx daddr TYPE bloom_filter(0.025) GRANULARITY 8192,
    INDEX daddrport_idx (ipproto, daddr, dport) TYPE bloom_filter(0.025) GRANULARITY 8192,
    INDEX dport_idx (ipproto, dport) TYPE bloom_filter(0.025) GRANULARITY 8192
)
ENGINE = SummingMergeTree
PARTITION BY toStartOfDay(interval)
ORDER BY (vlan, ipv, ipproto, saddr, daddr, sport, dport, gre_key, interval)
AS SELECT
    toStartOfInterval(begin_at, toIntervalSecond(300)) AS interval,
    vlan, ipv, ipproto, saddr, daddr, sport, dport, gre_key,
    sum(packets) AS packets,
    sum(bytes) AS bytes,
    sum(syns) AS syns,
    sum(fins) AS fins,
    sum(rsts) AS rsts
FROM flows
GROUP BY
    interval, vlan, ipv, ipproto, saddr, daddr, sport, dport, gre_key;

CREATE MATERIALIZED VIEW flows_1hr
(
    `interval` DateTime CODEC(DoubleDelta),
    `vlan` UInt16 CODEC(Gorilla),
    `ipv` UInt8 CODEC(NONE),
    `ipproto` UInt8 CODEC(NONE),
    `saddr` FixedString(16) CODEC(ZSTD(3)),
    `daddr` FixedString(16) CODEC(ZSTD(3)),
    `sport` UInt16 CODEC(Gorilla),
    `dport` UInt16 CODEC(Gorilla),
    `gre_key` UInt32 CODEC(Gorilla),
    `packets` UInt64 CODEC(Gorilla),
    `bytes` UInt64 CODEC(Gorilla),
    `syns` UInt64 CODEC(Gorilla),
    `fins` UInt64 CODEC(Gorilla),
    `rsts` UInt64 CODEC(Gorilla),
    INDEX interval_idx interval TYPE minmax GRANULARITY 2048,
    INDEX daddr_idx daddr TYPE bloom_filter(0.025) GRANULARITY 8192,
    INDEX daddrport_idx (ipproto, daddr, dport) TYPE bloom_filter(0.025) GRANULARITY 8192,
    INDEX dport_idx (ipproto, dport) TYPE bloom_filter(0.025) GRANULARITY 8192
)
ENGINE = SummingMergeTree
PARTITION BY toStartOfDay(interval)
ORDER BY (vlan, ipv, ipproto, saddr, daddr, sport, dport, gre_key, interval)
AS SELECT
    toStartOfInterval(begin_at, toIntervalSecond(3600)) AS interval,
    vlan, ipv, ipproto, saddr, daddr, sport, dport, gre_key,
    sum(packets) AS packets,
    sum(bytes) AS bytes,
    sum(syns) AS syns,
    sum(fins) AS fins,
    sum(rsts) AS rsts
FROM flows
GROUP BY
    interval, vlan, ipv, ipproto, saddr, daddr, sport, dport, gre_key;
