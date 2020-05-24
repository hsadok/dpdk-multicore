-- DPDK Pktgen lua script

package.path = package.path ..";?.lua;test/?.lua;app/?.lua;"

port_number = "0"
start_delay = 1000 -- ms
measure_delay = 1000 -- ms
num_trials = 10
rate = 0.7
dst_mac = "3c:fd:fe:55:fa:c2"
src_mac = "1c:34:da:41:ca:ac"
pkt_sizes = {64}

pktgen.delay(100)


pktgen.clear("all");
pktgen.cls();
pktgen.reset("all");

for _, pkt_size in ipairs(pkt_sizes) do
    pps_file = io.open("pps" .. pkt_size .. ".txt", "w")
    bps_file = io.open("bps" .. pkt_size .. ".txt", "w")

    pktgen.delay(1000)

    print("Starting pkt size: " .. pkt_size)
    pktgen.clear("all");
    pktgen.reset("all");

    -- change destination addresses so as to change the 5-tuple and work
    -- nicely with RSS
    -- pktgen.dst_ip(port_number, "start", "10.0.0.2")
    -- pktgen.dst_ip(port_number, "min", "10.0.0.2")
    -- pktgen.dst_ip(port_number, "max", "10.0.0.255")
    -- pktgen.dst_ip(port_number, "inc", "0.0.0.1")

    -- pktgen.src_ip(port_number, "start", "10.0.0.1")
    -- pktgen.src_ip(port_number, "min", "10.0.0.1")
    -- pktgen.src_ip(port_number, "max", "10.0.0.1")
    -- pktgen.src_ip(port_number, "inc", "0.0.0.0")

    -- pktgen.dst_mac(port_number, "start", dst_mac)

    -- pktgen.set_range(port_number, "on")

    pktgen.set("all", "seq_cnt", 16);
    pktgen.seq( 0, 0, dst_mac, src_mac, "10.11.0.1",  "10.10.0.1/16", 1321, 80, "ipv4", "tcp", 1, pkt_size);
    pktgen.seq( 1, 0, dst_mac, src_mac, "10.11.0.2",  "10.10.0.2/16", 1321, 80, "ipv4", "tcp", 1, pkt_size);
    pktgen.seq( 2, 0, dst_mac, src_mac, "10.11.0.3",  "10.10.0.3/16", 1321, 80, "ipv4", "tcp", 1, pkt_size);
    pktgen.seq( 3, 0, dst_mac, src_mac, "10.11.0.4",  "10.10.0.4/16", 1321, 80, "ipv4", "tcp", 1, pkt_size);
    pktgen.seq( 4, 0, dst_mac, src_mac, "10.11.0.5",  "10.10.0.5/16", 1321, 80, "ipv4", "tcp", 1, pkt_size);
    pktgen.seq( 5, 0, dst_mac, src_mac, "10.11.0.6",  "10.10.0.6/16", 1321, 80, "ipv4", "tcp", 1, pkt_size);
    pktgen.seq( 6, 0, dst_mac, src_mac, "10.11.0.7",  "10.10.0.7/16", 1321, 80, "ipv4", "tcp", 1, pkt_size);
    pktgen.seq( 7, 0, dst_mac, src_mac, "10.11.0.8",  "10.10.0.8/16", 1321, 80, "ipv4", "tcp", 1, pkt_size);
    pktgen.seq( 8, 0, dst_mac, src_mac, "10.11.0.9",  "10.10.0.9/16", 1321, 80, "ipv4", "tcp", 1, pkt_size);
    pktgen.seq( 9, 0, dst_mac, src_mac, "10.11.0.10", "10.10.0.10/16", 1321, 80, "ipv4", "tcp", 1, pkt_size);
    pktgen.seq(10, 0, dst_mac, src_mac, "10.11.0.11", "10.10.0.11/16", 1321, 80, "ipv4", "tcp", 1, pkt_size);
    pktgen.seq(11, 0, dst_mac, src_mac, "10.11.0.12", "10.10.0.12/16", 1321, 80, "ipv4", "tcp", 1, pkt_size);
    pktgen.seq(12, 0, dst_mac, src_mac, "10.11.0.13", "10.10.0.13/16", 1321, 80, "ipv4", "tcp", 1, pkt_size);
    pktgen.seq(13, 0, dst_mac, src_mac, "10.11.0.14", "10.10.0.14/16", 1321, 80, "ipv4", "tcp", 1, pkt_size);
    pktgen.seq(14, 0, dst_mac, src_mac, "10.11.0.15", "10.10.0.15/16", 1321, 80, "ipv4", "tcp", 1, pkt_size);
    pktgen.seq(15, 0, dst_mac, src_mac, "10.11.0.16", "10.10.0.16/16", 1321, 80, "ipv4", "tcp", 1, pkt_size);


    pktgen.set(port_number, "rate", rate)
    
    pktgen.set(port_number, "size", pkt_size);

    pktgen.start(port_number)
    pktgen.delay(start_delay)
    for trial=1,num_trials do
        pktgen.delay(measure_delay)

        rate_stats = pktgen.portStats("all", "rate")[tonumber(port_number)]

        pps = rate_stats.pkts_rx
        throughput = rate_stats.mbits_rx
        print(pps)
        print(throughput)

        pps_file:write(pps, "\n")
        bps_file:write(throughput, "\n")
    end

    pktgen.stop(port_number)

    pktgen.delay(1000)

    pps_file:close()
    bps_file:close()
end

pktgen.quit()
