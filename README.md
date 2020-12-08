# flow-collector(8)

flow-collector aggregates IP flow data and stores it in a ClickHouse
database.

IP flows are generated from packets captured on one or more Ethernet
interfaces, typically connected to SPAN ports on switches. This
allows for the aggregation of flow information in a redundant
switching environment.

Flows are collected within a timeslice, which is 2.5 seconds long
by default.

The collector also features parsing of DNS packets for building
mappings of IPs to names.

## Todo

- Improve the robustness of the POSTs into clickhouse
- Improve handling of memory shortages
  - investigate merging timeslices under memory pressure
