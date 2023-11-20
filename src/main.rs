mod pcap;

use std::fs;
use std::io;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;
use std::mem;
use std::ops::Shl;
use std::slice;
use std::{thread, time::Duration};
use std::process::Command;


fn main() -> io::Result<()> {
    let mut file = fs::File::open("class_splash_3.pcap")?;

    let pcap_header: pcap::FileHeader = read(&mut file)?;
    if pcap_header.magic != 2712847316 {
        println!("Invalid pcap file.");
        return Ok(());
    }

    const SIZE_LINK_HEADER: usize = 14;
    match pcap_header.linktype {
        1 => {
            // size_link_header = 14_u32;
        },
        
        _ => {
            println!("Invalid link type.");
            return Ok(());
        }
    }

    let mut packets = Vec::new();
    let mut is_eof = false;
    while !is_eof {
        let mut ignore_packet = false;
        let mut packet: pcap::Packet = Default::default();

        match read::<pcap::PacketHeader>(&mut file) {
            Ok(header) => {
                packet.header = header;
            },
            Err(err) => {
                if err.kind() == ErrorKind::UnexpectedEof { is_eof = true }
                else { println!("Che-to poshlo ne tak..."); return Ok(()) }
            }
        }
        
        if is_eof { break }

        match read::<[u8; SIZE_LINK_HEADER]>(&mut file) {
            Ok(buffer) => {
                let t = (buffer[buffer.len() - 2] as u16).shl(8) + (buffer[buffer.len() - 1] as u16);
                ignore_packet = t != 0x0800_u16
            },
            Err(err) => {
                if err.kind() == ErrorKind::UnexpectedEof { is_eof = true }
                else { println!("Che-to poshlo ne tak..."); return Ok(()) }
            }
        }

        if is_eof { break }

        let mut event: pcap::Event = unsafe { mem::zeroed() };
        unsafe {
            let caplen = packet.header.caplen as usize;
            let struct_slice = slice::from_raw_parts_mut(&mut event as *mut _ as *mut u8, caplen - SIZE_LINK_HEADER);
            let result = file.read_exact(struct_slice);
            match result {
                Ok(()) => {
                    packet.event = event;
                }

                Err(err) => {
                    if err.kind() == ErrorKind::UnexpectedEof { is_eof = true }
                    else { println!("Che-to poshlo ne tak... {}", err.kind()); return Ok(()) }
                },
            }
        }

        if ignore_packet { continue }
        packets.push(packet);
    }

    println!("N = {}", packets.len());

    // Syn-SynAck / Время
    let mut synsynack_time = String::new();
    // Syn-SynAck / длина
    let mut synsynack_size = String::new();
    // Syn-SynAck / ICMP
    let mut synsynack_icmp = String::new();
    // Длина / Время
    let mut size_time = String::new();

    const WINDOW_SIZE: usize = 100;
    let mut i = 0;
    for window in packets.windows(WINDOW_SIZE) {
        let mut syn = 0.0;
        let mut synack = 0.0;
        let mut size = 0.0;
        let mut time = 0.0;
        let mut icmp = 0.0;
        
        let mut j = 0;
        for packet in window {
            syn += if packet.is_syn() { 1.0 } else { 0.0 };
            synack += if packet.is_synack() { 1.0 } else { 0.0 };
            size += packet.event.ip.total_length as f64;
            if i + j > 0 {
                time += packet.get_time_sec() - packets[i + j - 1].get_time_sec();
            }

            icmp += if packet.event.ip.protocol == 1 { 1.0 } else { 0.0 };

            j += 1;
        }

        size /= WINDOW_SIZE as f64;
        time /= WINDOW_SIZE as f64;

        let synsynack = syn - synack;

        synsynack_time.push_str(format!("{:.6},{:.6}\n", time, synsynack).as_str());
        synsynack_size.push_str(format!("{:.6},{:.6}\n", size, synsynack).as_str());
        synsynack_icmp.push_str(format!("{:.6},{:.6}\n", icmp, synsynack).as_str());
        size_time.push_str(format!("{:.6},{:.6}\n", size, time).as_str());

        i += 1;
    }
    
    fs::write("synsynack_time.csv", synsynack_time)?;
    fs::write("synsynack_size.csv", synsynack_size)?;
    fs::write("synsynack_icmp.csv", synsynack_icmp)?;
    fs::write("size_time.csv", size_time)?;

    
    Command::new("python")
        .arg("plot.py")
        .arg("synsynack_time.csv")
        .arg("time")
        .arg("syn-synack")
        .arg("1")
        .output()
        .expect("Failed to execute command");
    
    Command::new("python")
        .arg("plot.py")
        .arg("synsynack_size.csv")
        .arg("size")
        .arg("syn-synack")
        .arg("1")
        .output()
        .expect("Failed to execute command");
    
    Command::new("python")
        .arg("plot.py")
        .arg("synsynack_icmp.csv")
        .arg("icmp")
        .arg("syn-synack")
        .arg("1")
        .output()
        .expect("Failed to execute command");
    
    Command::new("python")
        .arg("plot.py")
        .arg("size_time.csv")
        .arg("time")
        .arg("size")
        .arg("1")
        .output()
        .expect("Failed to execute command");
    

    Ok(())
}

fn read<T>(file: &mut fs::File) -> Result<T, Error> {
    let mut buffer: T = unsafe { mem::zeroed() };
    let size = mem::size_of::<T>();
    unsafe {
        let struct_slice = slice::from_raw_parts_mut(&mut buffer as *mut _ as *mut u8, size);
        let result = file.read_exact(struct_slice);
        if let Some(err) = result.err() {
            return Err(err);
        }
    }
    return Ok(buffer);
}
