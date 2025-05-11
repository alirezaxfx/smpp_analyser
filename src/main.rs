use log;
use log4rs;
use pcap::Capture;
use std::collections::HashMap;
use std::env;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone)]
pub struct SessionData {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    s_port: u16,
    d_port: u16,
    ts: libc::timeval,
    req_p_num: u64,
}

pub struct TCPSegment {
    seq: u32,
    data: Vec<u8>,
}

pub struct TCPStream {
    remaining_buffer: Vec<TCPSegment>,
}

impl TCPStream {
    pub fn new() -> Self {
        return TCPStream {
            remaining_buffer: Vec::new(),
        };
    }

    fn add_tcp_segment(&mut self, data: &[u8], seq: u32) {
        let tcp_segment = TCPSegment {
            data: data.to_vec(),
            seq,
        };

        for (index, item) in self.remaining_buffer.iter().enumerate() {
            if tcp_segment.seq == item.seq {
                // Duplicated do nothing
                return;
            }
            if tcp_segment.seq < item.seq {
                self.remaining_buffer.insert(index, tcp_segment);
                return;
            }
        }
        self.remaining_buffer.push(tcp_segment);
    }

    fn check_fragmentation(&mut self, last_seq_shuould_be: &mut u32) -> Vec<u8> {
        let mut data = Vec::new();
        self.remaining_buffer.retain(|item| {
            if *last_seq_shuould_be != 0 && *last_seq_shuould_be != item.seq {
                return true;
            }
            *last_seq_shuould_be = item.seq + item.data.len() as u32;
            data.extend_from_slice(&item.data);
            return false;
        });
        return data;
    }
}

#[derive(Default)]
pub struct SMPPStats {
    resp_time_2ms_count: u64,
    resp_time_2ms_sum: u64,

    resp_time_5ms_count: u64,
    resp_time_5ms_sum: u64,

    resp_time_10ms_count: u64,
    resp_time_10ms_sum: u64,

    resp_time_30ms_count: u64,
    resp_time_30ms_sum: u64,

    resp_time_50ms_count: u64,
    resp_time_50ms_sum: u64,

    resp_time_other_count: u64,
    resp_time_other_sum: u64,

    total_sent_request: u16,
    max_total_sent_request: u16,
}

#[derive(Default)]
pub struct ConcurrentSentRequestStats {
    sent_requests: u16,
    max_sent_requests: u16,
}

pub struct ProcessSMPP {
    all_tcp_streams: HashMap<String, TCPStream>,
    all_smpp_requests: HashMap<String, SessionData>,
    concurrent_sent_request_per_tcp_sessions: HashMap<String, ConcurrentSentRequestStats>,
    processing_packet_num: u64,
    last_ts: libc::timeval,
    smpp_stats: SMPPStats,
}

impl ProcessSMPP {
    // Constructor-like method to create a new Rectangle
    fn new() -> ProcessSMPP {
        return ProcessSMPP {
            all_tcp_streams: HashMap::new(),
            all_smpp_requests: HashMap::new(),
            concurrent_sent_request_per_tcp_sessions: HashMap::new(),
            smpp_stats: SMPPStats::default(),
            processing_packet_num: 0,
            last_ts: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
        };
    }

    pub fn parse_linux_sll(&mut self, data: &[u8], session_data: SessionData) {
        if data.len() >= 16 {
            let packet_type = u16::from_be_bytes([data[2], data[3]]);
            let ethertype = u16::from_be_bytes([data[14], data[15]]);
            log::debug!(
                "Linux SLL Layer: Packet Type = {}, Ethertype = 0x{:04x}",
                packet_type,
                ethertype
            );

            match ethertype {
                0x0800 => {
                    self.parse_ipv4(&data[16..], session_data);
                }
                0x86DD => {
                    // parse_ipv6(&data[16..]);
                }
                _ => log::debug!("Unknown Ethertype"),
            }
        } else {
            log::debug!("Packet too short for Linux SLL parsing");
        }
    }

    pub fn parse_ethernet(&mut self, data: &[u8], session_data: SessionData) {
        if data.len() >= 14 {
            let ethertype = u16::from_be_bytes([data[12], data[13]]);
            log::debug!(
                "Ethernet Layer: SrcMac:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} DstMac:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} Ethertype: 0x{:04x}",
                data[0],
                data[1],
                data[2],
                data[3],
                data[4],
                data[5],
                data[6],
                data[7],
                data[8],
                data[9],
                data[10],
                data[11],
                ethertype
            );

            match ethertype {
                0x0800 => {
                    log::debug!("IPv4 Packet detected");
                    self.parse_ipv4(&data[14..], session_data);
                }
                0x86DD => {
                    log::debug!("IPv6 Packet detected");
                    // parse_ipv6(&data[14..]);
                }
                _ => log::debug!("Unknown Ethertype"),
            }
        }
    }

    fn parse_ipv4(&mut self, data: &[u8], mut session_data: SessionData) {
        if data.len() >= 20 {
            session_data.src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
            session_data.dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
            let protocol = data[9];
            log::debug!(
                "IPv4 Layer: Src IP = {}, Dst IP = {}, Protocol = {}",
                session_data.src_ip,
                session_data.dst_ip,
                protocol
            );

            match protocol {
                6 => {
                    self.parse_tcp(&data[20..], session_data);
                }
                17 => {
                    // parse_udp(&data[20..]);
                }
                _ => log::debug!("Unknown Protocol"),
            }
        } else {
            log::warn!("Packet too short for IPv4 parsing");
        }
    }

    #[allow(dead_code)]
    fn parse_ipv6(&mut self, data: &[u8], _session_data: &SessionData) {
        if data.len() >= 40 {
            let src_ip = Ipv6Addr::from([
                data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
                data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
            ]);
            let dst_ip = Ipv6Addr::from([
                data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
                data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
            ]);
            let next_header = data[6];
            log::debug!(
                "IPv6 Layer: Src IP = {}, Dst IP = {}, Next Header = {}",
                src_ip,
                dst_ip,
                next_header
            );

            match next_header {
                6 => {
                    log::debug!("TCP Packet detected");
                    // parse_tcp(&data[40..]);
                }
                17 => {
                    log::debug!("UDP Packet detected");
                    // parse_udp(&data[40..]);
                }
                _ => log::warn!("Unknown Next Header"),
            }
        } else {
            log::warn!("Packet too short for IPv6 parsing");
        }
    }

    #[allow(dead_code)]
    fn parse_udp(&mut self, data: &[u8]) {
        if data.len() >= 8 {
            let src_port = u16::from_be_bytes([data[0], data[1]]);
            let dst_port = u16::from_be_bytes([data[2], data[3]]);
            let length = u16::from_be_bytes([data[4], data[5]]);
            log::debug!(
                "UDP Layer: Src Port = {}, Dst Port = {}, Length = {}",
                src_port,
                dst_port,
                length
            );
        } else {
            log::warn!("Packet too short for UDP parsing");
        }
    }

    fn create_hash_key(
        &self,
        a_ip: &Ipv4Addr,
        a_port: u16,
        b_ip: &Ipv4Addr,
        b_port: u16,
    ) -> String {
        return format!("{}:{}-{}:{}", a_ip, a_port, b_ip, b_port,);
    }

    fn parse_tcp(&mut self, data: &[u8], mut session_data: SessionData) {
        if data.len() >= 20 {
            session_data.s_port = u16::from_be_bytes([data[0], data[1]]);
            session_data.d_port = u16::from_be_bytes([data[2], data[3]]);

            let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

            let data_offset = (data[12] >> 4) & 0x0F; // Get the upper 4 bits
            let tcp_header_length = (data_offset * 4) as usize; // Convert to bytes
            log::debug!(
                "TCP Layer: Src Port = {}, Dst Port = {}",
                session_data.s_port,
                session_data.d_port
            );

            if data.len() > tcp_header_length {
                let hash_key1 = self.create_hash_key(
                    &session_data.src_ip,
                    session_data.s_port,
                    &session_data.dst_ip,
                    session_data.d_port,
                );

                let hash_key2 = self.create_hash_key(
                    &session_data.dst_ip,
                    session_data.d_port,
                    &session_data.src_ip,
                    session_data.s_port,
                );

                let concurren_sent_request_stats = if let Some(value) = self
                    .concurrent_sent_request_per_tcp_sessions
                    .get_mut(&hash_key1)
                {
                    value
                } else if let Some(value) = self
                    .concurrent_sent_request_per_tcp_sessions
                    .get_mut(&hash_key2)
                {
                    value
                } else {
                    self.concurrent_sent_request_per_tcp_sessions
                        .entry(hash_key1.clone())
                        .or_insert_with(ConcurrentSentRequestStats::default)
                };

                let tcp_stream = self
                    .all_tcp_streams
                    .entry(hash_key1.clone())
                    .or_insert_with(TCPStream::new);

                tcp_stream.add_tcp_segment(&data[tcp_header_length..], seq);
                let mut last_seq_should_be = 0_u32;
                let reassemble_data = tcp_stream.check_fragmentation(&mut last_seq_should_be);

                if !reassemble_data.is_empty() {
                    // let b = &mut self.last_ts;
                    if let Some(value) = Self::process_smpp(
                        &reassemble_data,
                        session_data,
                        self.processing_packet_num,
                        tcp_stream,
                        &mut self.all_smpp_requests,
                        &mut self.smpp_stats,
                        concurren_sent_request_stats,
                    ) {
                        let tcp_session = self
                            .all_tcp_streams
                            .get_mut(&hash_key1)
                            .expect("Session should exist");
                        tcp_session.add_tcp_segment(value, last_seq_should_be - value.len() as u32);
                    }
                }
            }
        } else {
            log::warn!("Packet too short for TCP parsing");
        }
    }

    fn process_smpp<'a>(
        data: &'a [u8],
        mut session_data: SessionData,
        processing_packet_num: u64,
        tcp_stream: &mut TCPStream,
        all_smpp_requests: &mut HashMap<String, SessionData>,
        smpp_stats: &mut SMPPStats,
        concurrent_sent_request: &mut ConcurrentSentRequestStats,
    ) -> Option<&'a [u8]> {
        if data.len() >= 16 {
            let smpp_len = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
            let operation = u32::from_be_bytes(data[4..8].try_into().unwrap());
            let sequence = u32::from_be_bytes(data[12..16].try_into().unwrap());

            if smpp_len <= 0 || smpp_len >= 1500 {
                return None;
            }

            if smpp_len > data.len() {
                return Some(&data);
            }

            match operation {
                0x00000004 => {
                    // Submit_sm
                    let hash_key = format!(
                        "{}:{}-{}:{}_{}",
                        session_data.src_ip,
                        session_data.s_port,
                        session_data.dst_ip,
                        session_data.d_port,
                        sequence
                    );
                    log::debug!("Submit_sm Req sequence:{} hash_key:{}", sequence, hash_key);
                    if all_smpp_requests.get(&hash_key).is_some() {
                        log::error!(
                            "Duplicate hash_key:{} on packet_number:{}",
                            hash_key,
                            processing_packet_num
                        );
                    }

                    session_data.req_p_num = processing_packet_num;
                    concurrent_sent_request.sent_requests += 1;
                    smpp_stats.total_sent_request += 1;

                    if concurrent_sent_request.max_sent_requests
                        < concurrent_sent_request.sent_requests
                    {
                        concurrent_sent_request.max_sent_requests =
                            concurrent_sent_request.sent_requests;
                    }

                    if smpp_stats.max_total_sent_request < smpp_stats.total_sent_request {
                        smpp_stats.max_total_sent_request = smpp_stats.total_sent_request;
                    }

                    all_smpp_requests.insert(hash_key, session_data.clone());
                }
                0x80000004 => {
                    // Submit_sm Resp
                    let hash_key = format!(
                        "{}:{}-{}:{}_{}",
                        session_data.dst_ip,
                        session_data.d_port,
                        session_data.src_ip,
                        session_data.s_port,
                        sequence
                    );
                    // log::debug!("Submit_sm Ans sequence:{} hash_key:{}", sequence, hash_key);
                    let option_old_session_data = all_smpp_requests.get(&hash_key);
                    match option_old_session_data {
                        Some(old_session_data) => {
                            let diff_time = diff_of_ts(&session_data.ts, &old_session_data.ts);
                            log::debug!(
                                "Submit_sm Ans sequence:{} dif_time:{}ms",
                                sequence,
                                diff_time / 1000
                            );

                            if diff_time <= 2000 {
                                smpp_stats.resp_time_2ms_count += 1;
                                smpp_stats.resp_time_2ms_sum += diff_time as u64;
                            } else if diff_time <= 5000 {
                                smpp_stats.resp_time_5ms_count += 1;
                                smpp_stats.resp_time_5ms_sum += diff_time as u64;
                            } else if diff_time <= 10000 {
                                smpp_stats.resp_time_10ms_count += 1;
                                smpp_stats.resp_time_10ms_sum += diff_time as u64;
                            } else if diff_time <= 30000 {
                                smpp_stats.resp_time_30ms_count += 1;
                                smpp_stats.resp_time_30ms_sum += diff_time as u64;
                            } else if diff_time <= 50000 {
                                smpp_stats.resp_time_50ms_count += 1;
                                smpp_stats.resp_time_50ms_sum += diff_time as u64;
                            } else {
                                smpp_stats.resp_time_other_count += 1;
                                smpp_stats.resp_time_other_sum += diff_time as u64;
                            }

                            let var1 = all_smpp_requests.remove(&hash_key);
                            if var1.is_some() {
                                concurrent_sent_request.sent_requests -= 1;
                                smpp_stats.total_sent_request -= 1;
                            } else {
                                log::info!(
                                    "Missing request sequence:{} hash_key:{}",
                                    sequence,
                                    hash_key
                                );
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }

            if data.len() > smpp_len {
                return Self::process_smpp(
                    &data[smpp_len..],
                    session_data,
                    processing_packet_num,
                    tcp_stream,
                    all_smpp_requests,
                    smpp_stats,
                    concurrent_sent_request,
                );
            }
            return None;
        }
        return Some(&data);
    }
}

fn main() {
    // Get command-line arguments
    let args: Vec<String> = env::args().collect();

    // Verify filename is provided
    if args.len() != 2 {
        log::error!("Usage: {} <pcap-file>", args[0]);
        std::process::exit(1);
    }

    let _ = log4rs::init_file("log4rs.yaml", Default::default());

    let filename = &args[1];
    let mut cap =
        Capture::from_file(filename).expect(&format!("Failed to open PCAP file: {}", filename));

    log::info!("Start Processing File:{}", filename);

    // Get the datalink type
    let datalink = cap.get_datalink();

    let mut process_smpp = ProcessSMPP::new();

    while let Ok(packet) = cap.next_packet() {
        process_smpp.processing_packet_num += 1;

        let session_data: SessionData = SessionData {
            src_ip: Ipv4Addr::new(0, 0, 0, 0),
            dst_ip: Ipv4Addr::new(0, 0, 0, 0),
            s_port: 0,
            d_port: 0,
            ts: packet.header.ts,
            req_p_num: 0,
        };

        if compare_to_ts(&process_smpp.last_ts, &session_data.ts) == -1 {
            process_smpp.last_ts = session_data.ts.clone();
        }

        // Parse based on link type
        match datalink {
            pcap::Linktype::LINUX_SLL => process_smpp.parse_linux_sll(packet.data, session_data),
            pcap::Linktype::ETHERNET => process_smpp.parse_ethernet(packet.data, session_data),
            _ => {
                log::warn!("Unsupported link type: {:?}", datalink);
            }
        };
    }

    log::info!("----------------------------------------------------------");
    let all_resp_time_count = process_smpp.smpp_stats.resp_time_2ms_count
        + process_smpp.smpp_stats.resp_time_5ms_count
        + process_smpp.smpp_stats.resp_time_10ms_count
        + process_smpp.smpp_stats.resp_time_30ms_count
        + process_smpp.smpp_stats.resp_time_50ms_count
        + process_smpp.smpp_stats.resp_time_other_count;

    let all_resp_time_sum = process_smpp.smpp_stats.resp_time_2ms_sum
        + process_smpp.smpp_stats.resp_time_5ms_sum
        + process_smpp.smpp_stats.resp_time_10ms_sum
        + process_smpp.smpp_stats.resp_time_30ms_sum
        + process_smpp.smpp_stats.resp_time_50ms_sum
        + process_smpp.smpp_stats.resp_time_other_sum;

    log::info!(
        "Average resp time:{:7.2}ms",
        (all_resp_time_sum as f64 / all_resp_time_count as f64) / 1000 as f64
    );

    log::info!(
        "resp time  2ms count:{:10} avg:{:7.2}(ms) pct:{:5.2}%",
        process_smpp.smpp_stats.resp_time_2ms_count,
        ((process_smpp.smpp_stats.resp_time_2ms_sum as f64)
            / (process_smpp.smpp_stats.resp_time_2ms_count as f64))
            / 1000.0_f64,
        100.0 * process_smpp.smpp_stats.resp_time_2ms_count as f64 / all_resp_time_count as f64
    );

    log::info!(
        "resp time  5ms count:{:10} avg:{:7.2}(ms) pct:{:5.2}%",
        process_smpp.smpp_stats.resp_time_5ms_count,
        ((process_smpp.smpp_stats.resp_time_5ms_sum as f64)
            / (process_smpp.smpp_stats.resp_time_5ms_count as f64))
            / 1000.0_f64,
        100.0 * process_smpp.smpp_stats.resp_time_5ms_count as f64 / all_resp_time_count as f64
    );

    log::info!(
        "resp time 10ms count:{:10} avg:{:7.2}(ms) pct:{:5.2}%",
        process_smpp.smpp_stats.resp_time_10ms_count,
        ((process_smpp.smpp_stats.resp_time_10ms_sum as f64)
            / (process_smpp.smpp_stats.resp_time_10ms_count as f64))
            / 1000.0_f64,
        100.0 * process_smpp.smpp_stats.resp_time_10ms_count as f64 / all_resp_time_count as f64
    );

    log::info!(
        "resp time 15ms count:{:10} avg:{:7.2}(ms) pct:{:5.2}%",
        process_smpp.smpp_stats.resp_time_30ms_count,
        ((process_smpp.smpp_stats.resp_time_30ms_sum as f64)
            / (process_smpp.smpp_stats.resp_time_30ms_count as f64))
            / 1000.0_f64,
        100.0 * process_smpp.smpp_stats.resp_time_30ms_count as f64 / all_resp_time_count as f64
    );

    log::info!(
        "resp time 30ms count:{:10} avg:{:7.2}(ms) pct:{:5.2}%",
        process_smpp.smpp_stats.resp_time_50ms_count,
        ((process_smpp.smpp_stats.resp_time_50ms_sum as f64)
            / (process_smpp.smpp_stats.resp_time_50ms_count as f64))
            / 1000.0_f64,
        100.0 * process_smpp.smpp_stats.resp_time_50ms_count as f64 / all_resp_time_count as f64
    );

    log::info!(
        "resp time XXms count:{:10} avg:{:7.2}(ms) pct:{:5.2}%",
        process_smpp.smpp_stats.resp_time_other_count,
        ((process_smpp.smpp_stats.resp_time_other_sum as f64)
            / (process_smpp.smpp_stats.resp_time_other_count as f64))
            / 1000.0_f64,
        100.0 * process_smpp.smpp_stats.resp_time_other_count as f64 / all_resp_time_count as f64
    );

    let mut timeout_count = 0_u32;
    let mut all_remaining_unanswer_request = 0_u32;

    all_remaining_unanswer_request += process_smpp.all_smpp_requests.len() as u32;
    for (key, value) in &process_smpp.all_smpp_requests {
        let diff_time = diff_of_ts(&process_smpp.last_ts, &value.ts);
        if diff_time > 2000000 {
            log::warn!(
                "Key:{} request has been Timeout(Request hasn't any answer within {:6}ms PacketNumber:{}).",
                key,
                diff_time / 1000_i64,
                value.req_p_num
            );
            timeout_count += 1;
        }
    }

    log::info!("----------------------------------------------------------");

    let mut sum_max_sent_request = 0;
    for (key, value) in process_smpp.concurrent_sent_request_per_tcp_sessions {
        log::info!(
            "Max Sent Request tcp_session:{:43} count:{:5}",
            key,
            value.max_sent_requests
        );
        sum_max_sent_request += value.max_sent_requests;
    }
    log::info!(
        "Sum all Request in each TCP sessions :{:5} vs Global View Total Reuqest:{:5}",
        sum_max_sent_request,
        process_smpp.smpp_stats.max_total_sent_request
    );
    log::info!("----------------------------------------------------------");
    log::warn!(
        "Missing Answer Count:{:10} Timeout_count:{:10}",
        all_remaining_unanswer_request - timeout_count,
        timeout_count
    );
}

fn compare_to_ts(a: &libc::timeval, b: &libc::timeval) -> i8 {
    let a_value = a.tv_sec as u64 * 1000000_u64 + a.tv_usec as u64;
    let b_value = b.tv_sec as u64 * 1000000_u64 + b.tv_usec as u64;
    if a_value < b_value {
        return -1;
    } else if a_value > b_value {
        return 1;
    }
    return 0;
}

fn diff_of_ts(a: &libc::timeval, b: &libc::timeval) -> i64 {
    let a_value = a.tv_sec as u64 * 1000000_u64 + a.tv_usec as u64;
    let b_value = b.tv_sec as u64 * 1000000_u64 + b.tv_usec as u64;
    return a_value as i64 - b_value as i64;
}
