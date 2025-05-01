mod tracerouter;
use std::{env, io::ErrorKind, mem::MaybeUninit, net::SocketAddr, time::Duration};

use local_ip_address::local_ip;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tracerouter::{calc_checksum, parse_sender_ip, resolve_host};

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 || args[1].is_empty() {
        eprintln!("Usage: tracerouter <hostname>");
        std::process::exit(1);
    }
    println!("Tracing route to {}...", &args[1]);

    let my_ip = local_ip().unwrap_or_else(|_| panic!("Could not get local IP."));

    let dest_ips = resolve_host(&args[1]);
    if dest_ips.len() == 0 {
        eprintln!("Error: Could not find IP for {}", &args[1]);
        std::process::exit(1);
    }
    println!("ips: {dest_ips:?}");
    println!("my_ip: {:?}", {my_ip});

    // Create our IPV4 Socket
    let socket = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::ICMPV4)
    ).expect("Error: Could not initialize Socket.  
        It is required for program to be running in a high privilege state.");

    // Specify to kernel we're sending our own IP header
    // If false, system will take care of it
    socket.set_header_included_v4(true).expect("Could not specify IP_HDRINCL header.");

    let mut packet= [0u8; 20 + 8]; // IP Header (20 bytes) + ICMP (8 bytes)

    // IP Header (simplified, version 4, no options)
    // First 4 bits are the version (4) and the preceding 4 bits IHL (5) (big-endian represented)
    packet[0] = 0x45;                       // Version: 4, IHL: 5
    // packet[1] = 0;                       // ToS omitted because bucket is already 0
    packet[2] = 0;                          // High Byte
    packet[3] = 28;                         // Low Byte
    // Identification (0)
    // Flags + Fragment Offset (0 unspecified)
    // packet[8] = 4;                       // TTL (Late populated)
    packet[9] = 1;                          // Protocol (ICMP)

    let ip_checksum = calc_checksum(&packet[0..20]);
    packet[10] = (ip_checksum >> 8) as u8;  // High Byte
    packet[11] = (ip_checksum & 0xFF) as u8;// Low Byte

    let my_ip_str = my_ip.to_string();
    let mut my_num_ip = my_ip_str.split(".");

    // Set local IP Address to packet
    for index in 12..=15 {
        packet[index] = my_num_ip.next().unwrap().parse::<u8>().unwrap();
    }

    // ICMP Header
    packet[20] = 8;         // Type (Echo Request)
    // packet[21] = 0;      // Code (Omitted, already 0)
    // packet[22] = 0;      //  Checksum (u16)
    // packet[23] = 0;
    packet[24] = 0x12;      // Identifier
    packet[25] = 0x34;
    packet[26] = 0x00;      // Sequence Number
    packet[27] = 0x01;

    let icmp_checksum = calc_checksum(&packet[20..=27]);
    packet[22] = (icmp_checksum >> 8) as u8;  // High Byte
    packet[23] = (icmp_checksum & 0xFF) as u8;// Low Byte

    // Uses each destination IP address to until an request is successfully completed
    for dest_ip in dest_ips {
        // Parse IP to number as u8 
        let str = dest_ip.to_string();
        let mut num_ip= str.split(".");

        // Extract all 4 IPV4 fields advancing iterator parsing it to u8;
        // Like 192 (first parse) and the subsequent: 168, 1, 1
        for index in 16..=19 {
            packet[index] = num_ip.next().unwrap().parse::<u8>().unwrap();
        }

        for ttl in 1..=30 {
            // Set TTL on IP header
            packet[8] = ttl;

            // Effectivelly send our Packet, blocking current thread until a response is read or TTL end is reached.
            socket.set_read_timeout(Some(Duration::from_secs(3)))?;
            socket.send_to(&packet, &SockAddr::from(SocketAddr::new(dest_ip, 0)))?;
            println!("Tracing with TTL: {ttl}");

            // 56 bytes buffer - High buffer on convential values (56 bytes on TTL outlive)
            let mut buffer: [MaybeUninit<u8>; 512] = [MaybeUninit::uninit(); 512];

            match socket.recv_from(&mut buffer) {
                Ok((size, sender)) => {
                    println!("Received {size} bytes from {sender:?}");

                    // Responses generally are 56 (Time Exceed - IP Header/ICMP of sender and original IP Header) 
                    // or 28 (Success, IPHeader/ICMP packet of sender).
                    let received_data = unsafe {
                        std::slice::from_raw_parts(
                            buffer.as_ptr() as *const u8,
                            size
                        )
                    };

                    let received_ip = parse_sender_ip(&received_data[12..=15]);

                    // Received ICMP type
                    let icmp_type = received_data[20];
                    println!("icmp_type: {icmp_type}");

                    if icmp_type == 11 {
                        println!("TTL: {ttl} on {received_ip}\n");

                        // Adjust by your flavor
                        std::thread::sleep(Duration::from_secs(1));
                        continue;
                    }

                    println!("Reached destiny: {received_ip}");
                    break;
                },
                Err(err) if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::TimedOut => {
                    eprintln!("TTL={ttl} Timeout - No Response.\n");
                },
                Err(err) => { return Err(err) }
            };
        }
    }
    // dbg!(packet);

    Ok(())
}
