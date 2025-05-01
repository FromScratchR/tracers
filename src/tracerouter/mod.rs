use std::net::IpAddr;
use dns_lookup::lookup_host;

/// Lookup host and return a list of valid IPV4-only addresses.
/// 
pub fn resolve_host(hostname: &String) -> Vec<IpAddr> {
    match lookup_host(hostname) {
        Ok(ips) => {
            ips
            .into_iter()
            .filter(|ip| ip.is_ipv4())
            .collect::<Vec<IpAddr>>()
        }
        Err(e) => {
            eprintln!("Could not find valid IPs for {hostname}, {e}");
            std::process::exit(1);
        }
    }
}

/// Makes data into 2 bytes words, sum and invert them (NOT bit operation)
/// 
/// [0x32, 0x00, 0x49, 0x30, [...]] -> Raw Vec (u8 representation)
/// 
/// [0x3200, 0x4930, 0x0001, 0x3842] -> What we need
/// 
pub fn calc_checksum(data: &[u8]) -> u16 {
    // u32 so we can handle u16 bit overflow later
    let mut sum = 0u32; // -> 00000000 00000000 00000000 00000000;
    let mut i = 0;

    // -1 Set odd handling, as we step 2 each time when an odd is found 
    // the conditional is not true because it's value is equal to data.len() - 1
    while i < data.len() - 1 {
        // Get 1 byte and shift it by 1 byte.
        // Now we got "1 byte extra space" since we're dealing with an u8 as cast it to u32 in the process;
        // Ex: Our u8 00000010 becomes 0000000 00000000 00000010 00000000 (u32 bits aligned)
        // This way we just free the needed space to block another byte into it (data[i+1]).
        // "|" Add the bits so as we already got the free byte (8 bits),
        // we can just add them casting to u32 as only same types are allowed to sum.
        let word = (data[i] as u32) << 8 | (data[i + 1] as u32);

        sum += word;
        i += 2;
    }

    // Odd buffer handling
    if i == data.len() -1 {
        sum += (data[i] as u32) << 8;
    }

    // Strip zeroed bytes from u32 sum until a valid u16 is set.
    // Finally, this is an operation to make our u32 with possible overflow 
    // to fit into u16 correctly, following the checksum algorithm.
    while (sum >> 16) > 0 {
        // Sum lower 16 bits with overflow (if present)
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

pub fn parse_sender_ip(ip: &[u8]) -> String {
    let mut str_ip = String::new();

    for i in 1..ip.len() {
        str_ip += &(ip[i].to_string() + ".");
    }

    // Remove last . for ip
    str_ip.pop();

    str_ip
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assert checksum of a dummy ICMP packet is correct.
    /// 
    #[test]
    fn pair_checksum() {
        let buf: [u8; 8] = [0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01];
        let result: u16 = 0xE5CA;

        assert_eq!(result, calc_checksum(&buf));
    }

    #[test]
    fn odd_checksum() {
        // Same as above but with additional 0x23 on final.
        let buf: [u8; 9] = [0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01, 0x23];
        let result: u16 = 0xC2CA;

        assert_eq!(result, calc_checksum(&buf));
    }
}