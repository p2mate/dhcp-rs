use std::net::{UdpSocket};
use dhcp_packet::DhcpPacket;

extern crate strum;
#[macro_use]
extern crate strum_macros;

mod dhcp_packet;

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:67").unwrap();
    loop {
        let mut buf = [0; 2048];
        let (number_of_bytes, src_addr) = socket.recv_from(&mut buf).unwrap();
        let packet = DhcpPacket::parse(&buf[0..number_of_bytes]);
        //println!("{:x?} {:?} {:x?}", number_of_bytes, src_addr, &packet);
        println!("{}\n", packet.unwrap().1);
    }
}
