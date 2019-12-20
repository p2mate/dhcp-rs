extern crate byte_string;

use pnet::packet::arp;
use pnet::datalink;
use nom::number::complete::{be_u8, be_u16, be_u32};
use nom::sequence::{tuple, terminated, preceded};
use nom::{bytes::complete::tag, bytes::complete::take, combinator::map, combinator::value, combinator::verify};
use byte_string::ByteStr;
use std::net::Ipv4Addr;
use std::time;
use nom::multi::{fold_many0, length_data};
use nom::lib::std::collections::HashMap;
use nom::combinator::map_parser;
use std::fmt;

type Input<'a> = &'a [u8];
type Result<'a, T> = nom::IResult<Input<'a>, T, ()>;

#[derive(Debug, Clone)]
pub struct DhcpDuration(time::Duration);

#[derive(Debug, Clone)]
pub struct DhcpBytes(Vec<u8>);

impl std::convert::From<Vec<u8>> for DhcpBytes {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl DhcpDuration {
    fn new(s: u64, n: u32) -> Self {
        DhcpDuration(time::Duration::new(s, n))
    }
}

#[derive(Debug, Copy, Clone, Display)]
pub enum BootpOpcode {
    BootRequest,
    BootReply,
}

#[derive(Debug, Clone, Display)]
pub enum DhcpMessageType {
    #[strum(to_string = "Discover")]
    DhcpDiscover,
    #[strum(to_string = "Offer")]
    DhcpOffer,
    #[strum(to_string = "Request")]
    DhcpRequest,
    #[strum(to_string = "Decline")]
    DhcpDecline,
    #[strum(to_string = "Ack")]
    DhcpAck,
    #[strum(to_string = "Nak")]
    DhcpNak,
    #[strum(to_string = "Release")]
    DhcpRelease,
    #[strum(to_string = "Inform")]
    DhcpInform,
    #[strum(to_string = "Force Renew")]
    DhcpForceRenew,
}

impl DhcpMessageType {
    fn parse(buf: Input) -> Result<Self> {
        map(preceded(verify_option_length(|x| x == 1), be_u8), |x|
            match x {
                1 => Self::DhcpDiscover,
                2 => Self::DhcpOffer,
                3 => Self::DhcpRequest,
                4 => Self::DhcpDecline,
                5 => Self::DhcpAck,
                6 => Self::DhcpNak,
                7 => Self::DhcpRelease,
                8 => Self::DhcpInform,
                9 => Self::DhcpForceRenew,
                _ => panic!("Unknown DHCP message type {}", x),
            })(buf)
    }
}

type DhcpClientIdentifier = DhcpBytes;

impl DhcpBytes {
    fn parse(buf: Input) -> Result<Self> {
        map(length_data(verify_option_length(|x| x > 2)),
            |x| x.to_vec().into())(buf)
    }
}

#[derive(Debug, Clone, Copy, Display)]
pub enum DhcpForceRenewNonceAlgos {
    #[strum(to_string = "HMAC MD5")]
    HmacMd5,
    #[strum(to_string = "Unknown HMAC")]
    Other(u8),
}

impl DhcpForceRenewNonceAlgos {
    fn parse(byte: u8) -> Self {
        match byte {
            1 => Self::HmacMd5,
            x => Self::Other(x),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DhcpForceRenewNonceCapable(Vec<DhcpForceRenewNonceAlgos>);

impl DhcpForceRenewNonceCapable {
    fn parse(buf: Input) -> Result<Self> {
        map(length_data(verify_option_length(|x| x > 0)),
            |x| DhcpForceRenewNonceCapable(x.into_iter().
                map(|y| DhcpForceRenewNonceAlgos::parse(*y)).collect()),
        )(buf)
    }
}

impl fmt::Display for DhcpForceRenewNonceCapable {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        let output: String = self.0.iter().
            map(|x| fmt::format(format_args!("{}, ", x))).collect();
        write!(w, "{}", output.trim_end_matches(" ,"))
    }
}

const DHCP_OPTION_SUBNETMASK: u8 = 1;
const DHCP_OPTION_ROUTER: u8 = 3;
const DHCP_OPTION_DNSSERVER: u8 = 6;
const DHCP_OPTION_HOSTNAME: u8 = 12;
const DHCP_OPTION_DOMAINNAME: u8 = 15;
const DHCP_OPTION_INTERFACEMTU: u8 = 26;
const DHCP_OPTION_BROADCAST_ADDR: u8 = 28;
const DHCP_OPTION_LEASETIME: u8 = 51;
const DHCP_OPTION_MSGTYPE: u8 = 53;
const DHCP_OPTION_SERVERID: u8 = 54;
const DHCP_OPTION_PARAM_REQUEST_LIST: u8 = 55;
const DHCP_OPTION_MAX_MSG_SIZE: u8 = 57;
const DHCP_OPTION_RENEWAL_INTERVAL: u8 = 58;
const DHCP_OPTION_REBINDING_INTERVAL: u8 = 59;
const DHCP_OPTION_VENDOR_CLASS_ID: u8 = 60;
const DHCP_OPTION_CLIENT_IDENTIFIER: u8 = 61;
const DHCP_OPTION_RAPID_COMMIT: u8 = 80;
const DHCP_OPTION_DOMAIN_SEARCH: u8 = 119;
const DHCP_OPTION_FORCE_RENEW_NONCE_CAP: u8 = 145;
const DHCP_OPTION_END: u8 = 255;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Display)]
pub enum DhcpOptionID {
    #[strum(to_string="Subnet Mask")]
    SubnetMask,
    Router,
    #[strum(to_string="DNS Server")]
    DNSserver,
    #[strum(to_string="Host Name")]
    HostName,
    #[strum(to_string="Domain Name")]
    DomainName,
    #[strum(to_string="Interface MTU")]
    InterfaceMTU,
    #[strum(to_string="Broadcast Address")]
    BroadcastAddr,
    #[strum(to_string="Lease Time")]
    LeaseTime,
    #[strum(to_string="Server ID")]
    ServerID,
    #[strum(to_string="Renewal Interval")]
    RenewalInterval,
    #[strum(to_string="Rebinding Interval")]
    RebindingInterval,
    #[strum(to_string="Domain Search")]
    DomainSearch,
    #[strum(to_string="Message Type")]
    MsgType,
    #[strum(to_string="Client Identifier")]
    ClientIdentifier,
    #[strum(to_string="Rapid Commit")]
    RapidCommit,
    #[strum(to_string="Maximum Message Size")]
    MaxMsgSize,
    #[strum(to_string="Vendor Class ID")]
    VendorClassId,
    #[strum(to_string="Force Renew Nonce Capable")]
    ForceRenewNonceCap,
    #[strum(to_string="Parameter Request List")]
    ParameterRequestList,
    OptionEnd,
    Pad,
    #[strum(to_string="Unknown Parameter")]
    Other(u8),
}

impl DhcpOptionID {
    pub fn from(id: u8) -> Self {
        match id {
            DHCP_OPTION_SUBNETMASK => DhcpOptionID::SubnetMask,
            DHCP_OPTION_ROUTER => DhcpOptionID::Router,
            DHCP_OPTION_DNSSERVER => DhcpOptionID::DNSserver,
            DHCP_OPTION_HOSTNAME => DhcpOptionID::HostName,
            DHCP_OPTION_DOMAINNAME => DhcpOptionID::DomainName,
            DHCP_OPTION_INTERFACEMTU => DhcpOptionID::InterfaceMTU,
            DHCP_OPTION_BROADCAST_ADDR => DhcpOptionID::BroadcastAddr,
            DHCP_OPTION_LEASETIME => DhcpOptionID::LeaseTime,
            DHCP_OPTION_MSGTYPE => DhcpOptionID::MsgType,
            DHCP_OPTION_SERVERID => DhcpOptionID::ServerID,
            DHCP_OPTION_PARAM_REQUEST_LIST => DhcpOptionID::ParameterRequestList,
            DHCP_OPTION_MAX_MSG_SIZE => DhcpOptionID::MaxMsgSize,
            DHCP_OPTION_RENEWAL_INTERVAL => DhcpOptionID::RenewalInterval,
            DHCP_OPTION_REBINDING_INTERVAL => DhcpOptionID::RebindingInterval,
            DHCP_OPTION_VENDOR_CLASS_ID => DhcpOptionID::VendorClassId,
            DHCP_OPTION_CLIENT_IDENTIFIER => DhcpOptionID::ClientIdentifier,
            DHCP_OPTION_RAPID_COMMIT => DhcpOptionID::RapidCommit,
            DHCP_OPTION_DOMAIN_SEARCH => DhcpOptionID::DomainSearch,
            DHCP_OPTION_FORCE_RENEW_NONCE_CAP => DhcpOptionID::ForceRenewNonceCap,
            DHCP_OPTION_END => DhcpOptionID::OptionEnd,
            0 => DhcpOptionID::Pad,
            o => DhcpOptionID::Other(o),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DhcpOptionIDs(Vec<DhcpOptionID>);

impl std::convert::From<&Vec<DhcpOptionID>> for DhcpOptionIDs {
    fn from(v: &Vec<DhcpOptionID>) -> Self {
        Self(v.to_vec())
    }
}

impl std::convert::From<&DhcpOptionIDs> for Vec<DhcpOptionID> {
    fn from(v: &DhcpOptionIDs) -> Vec<DhcpOptionID> {
        v.0.to_vec()
    }
}

impl DhcpOptionIDs {
    fn parse(buf: Input) -> Result<Self> {
        map(length_data(be_u8),
            |x| DhcpOptionIDs(x.into_iter()
                .map(|y| DhcpOptionID::from(*y)).collect()),
        )(buf)
    }
}

fn display_vec_spaces<T>(w: &mut fmt::Formatter, vec: &Vec<T>) -> fmt::Result
    where T: fmt::Display {
    let output: String = vec.iter().map(|x| {
        fmt::format(format_args!("{} ", x))
    }).collect();
    write!(w, "{}", output.trim_end())
}

impl fmt::Display for DhcpOptionIDs {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        display_vec_spaces(w, &self.into())
    }
}

#[derive(Debug, Clone)]
pub struct DhcpOptionOther {
    pub option: DhcpBytes,
    pub option_id: u8,
}
impl fmt::Display for DhcpOptionOther {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        write!(w,"({:02x}) {}", self.option_id, self.option)
    }
}

#[derive(Debug, Clone)]
pub struct Ipv4AddrList(Vec<Ipv4Addr>);

impl Ipv4AddrList {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        let output: String = self.0.iter().
            map(|x| fmt::format(format_args!("{}, ", x))).collect();
        write!(w, "{}", output.trim_end_matches(" ,"))
    }
}

#[derive(Debug, Clone)]
pub enum DhcpOption {
    MessageType(DhcpMessageType),
    ClientIdentifier(DhcpClientIdentifier),
    RapidCommit,
    MaxMsgSize(usize),
    VendorClassId(String),
    HostName(String),
    ForceRenewNonceCapable(DhcpForceRenewNonceCapable),
    ParameterRequestList(DhcpOptionIDs),
    SubNetMask(u32),
    Router(Ipv4AddrList),
    DNSserver(Ipv4AddrList),
    DomainName(String),
    InterfaceMTU(u16),
    BroadcastAddr(Ipv4Addr),
    LeaseTime(DhcpDuration),
    Other(DhcpOptionOther),
    ServerID(Ipv4Addr),
    RenewalPeriod(DhcpDuration),
    RebindingPeriod(DhcpDuration),
    DomainSearch(DhcpBytes),
    Pad,
    End,
}

impl fmt::Display for DhcpDuration {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        write!(w, "{}.{}", self.0.as_secs(), self.0.as_nanos())
    }
}

impl fmt::Display for DhcpBytes {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        let output: String = self.0.iter().map(|x| {
            fmt::format(format_args!("{:02x} ", x))
        }).collect();
        write!(w, "{}", output.trim_end())
    }
}

impl fmt::Display for DhcpOption {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MessageType(t) => t.fmt(w),
            Self::ClientIdentifier(b) | Self::DomainSearch(b) => b.fmt(w),
            Self::RapidCommit => write!(w, "Rapid Commit"),
            Self::MaxMsgSize(t) => t.fmt(w),
            Self::HostName(t) | Self::VendorClassId(t) | Self::DomainName(t) => t.fmt(w),
            Self::BroadcastAddr(t) | Self::ServerID(t) => t.fmt(w),
            Self::LeaseTime(t) | Self::RenewalPeriod(t) | Self::RebindingPeriod(t) => t.fmt(w),
            Self::SubNetMask(m) => write!(w, "{:#08x}", m),
            Self::InterfaceMTU(m) => m.fmt(w),
            Self::Router(l) | Self::DNSserver(l) => l.fmt(w),
            Self::ForceRenewNonceCapable(n) => n.fmt(w),
            Self::Pad | Self::End => write!(w,""),
            Self::Other(o) => write!(w,"{}", o),
            Self::ParameterRequestList(p) => write!(w,"{}", p),
        }
    }
}

fn parse_ipv4_option_list(buf: Input) -> Result<Vec<Ipv4Addr>>
{
    map_parser(length_data(verify_option_length(|x| x >= 4 && (x % 4) == 0)),
               parse_ipv4_list)(buf)
}

fn parse_ipv4_list(buf: Input) -> Result<Vec<Ipv4Addr>>
{
    fold_many0(parse_ipv4, Vec::new(), |mut addrs: Vec<_>, addr| {
        addrs.push(addr.unwrap());
        addrs
    })(buf)
}

fn parse_string(buf: Input) -> Result<String>
{
    map(length_data(verify_option_length(|x| x > 0)),
        |x| String::from_utf8(x.to_vec()).unwrap())(buf)
}

fn verify_option_length<'a>(function: fn(u8) -> bool) -> impl Fn(&'a [u8]) -> Result<u8>
{
    verify(be_u8, move |x| function(*x))
}

impl DhcpOption {
    fn parse<'a, 'b>(option_id: &'b DhcpOptionID, buf: Input<'a>) -> Result<'a, Self> {
        match option_id {
            DhcpOptionID::Router =>
                map(parse_ipv4_option_list,
                    |x| DhcpOption::Router(Ipv4AddrList(x)))(buf),
            DhcpOptionID::DNSserver =>
                map(parse_ipv4_option_list,
                    |x| DhcpOption::DNSserver(Ipv4AddrList(x)))(buf),
            DhcpOptionID::HostName =>
                map(parse_string, |x| DhcpOption::HostName(x))(buf),
            DhcpOptionID::DomainName =>
                map(parse_string, |x| DhcpOption::DomainName(x))(buf),
            DhcpOptionID::InterfaceMTU =>
                map(preceded(verify_option_length(|x| x == 2), be_u16),
                    |x| DhcpOption::InterfaceMTU(x))(buf),
            DhcpOptionID::BroadcastAddr =>
                map(preceded(verify_option_length(|x| x == 4), parse_ipv4),
                    |x| DhcpOption::BroadcastAddr(x.unwrap()))(buf),
            DhcpOptionID::LeaseTime =>
                map(preceded(verify_option_length(|x| x == 4), be_u32),
                    |x| DhcpOption::LeaseTime(DhcpDuration::new(x.into(), 0)))(buf),
            DhcpOptionID::MsgType =>
                map(DhcpMessageType::parse, |x| DhcpOption::MessageType(x))(buf),
            DhcpOptionID::OptionEnd =>
                Ok((buf, DhcpOption::End)),
            DhcpOptionID::ServerID =>
                map(preceded(verify_option_length(|x| x == 4), parse_ipv4),
                    |x| DhcpOption::ServerID(x.unwrap()))(buf),
            DhcpOptionID::ParameterRequestList =>
                map(DhcpOptionIDs::parse, |x| DhcpOption::ParameterRequestList(x))(buf),
            DhcpOptionID::SubnetMask =>
                map(preceded(verify_option_length(|x| x == 4), be_u32),
                    |x| DhcpOption::SubNetMask(x))(buf),
            DhcpOptionID::MaxMsgSize =>
                map(preceded(verify_option_length(|x| x == 2),
                             verify(be_u16, |x| *x >= 576)),
                    |x| DhcpOption::MaxMsgSize(x.into()))(buf),
            DhcpOptionID::RenewalInterval =>
                map(preceded(verify_option_length(|x| x == 4), be_u32),
                    |x| DhcpOption::RenewalPeriod(DhcpDuration::new(x.into(), 0)))(buf),
            DhcpOptionID::RebindingInterval =>
                map(preceded(verify_option_length(|x| x == 4), be_u32),
                    |x| DhcpOption::RebindingPeriod(DhcpDuration::new(x.into(), 0)))(buf),
            DhcpOptionID::VendorClassId =>
                map(parse_string, |x| DhcpOption::VendorClassId(x))(buf),
            DhcpOptionID::ClientIdentifier =>
                map(DhcpClientIdentifier::parse, |x| DhcpOption::ClientIdentifier(x))(buf),
            DhcpOptionID::RapidCommit =>
                value(DhcpOption::RapidCommit, verify_option_length(|x| x == 0))(buf),
            DhcpOptionID::ForceRenewNonceCap =>
                map(DhcpForceRenewNonceCapable::parse, |x| DhcpOption::ForceRenewNonceCapable(x))(buf),
            DhcpOptionID::DomainSearch =>
                map(length_data(be_u8), |x| DhcpOption::DomainSearch(x.to_vec().into()))(buf),
            DhcpOptionID::Pad =>
                Ok((buf, DhcpOption::Pad)),
            DhcpOptionID::Other(o) =>
                map(length_data(be_u8), |x| DhcpOption::Other(DhcpOptionOther { option_id: *o, option: x.to_vec().into() }))(buf),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DhcpPacket {
    pub ciaddr: Option<Ipv4Addr>,
    pub yiaddr: Option<Ipv4Addr>,
    pub siaddr: Option<Ipv4Addr>,
    pub giaddr: Option<Ipv4Addr>,
    pub opcode: BootpOpcode,
    pub hops: usize,
    pub hlen: usize,
    pub htype: arp::ArpHardwareType,
    pub xid: u32,
    pub secs: DhcpDuration,
    pub broadcast: bool,
    pub chaddr: datalink::MacAddr,
    pub options: HashMap<DhcpOptionID, DhcpOption>,
}

impl BootpOpcode {
    fn parse(buf: Input) -> Result<Self> {
        let opcode = be_u8(buf);
        match opcode {
            Err(e) => Result::Err(e),
            Ok(number) => match number {
                (buf, 1) => Result::Ok((buf, BootpOpcode::BootRequest)),
                (buf, 2) => Result::Ok((buf, BootpOpcode::BootReply)),
                (buf, o) => panic!("Unknown opcode {}", o),
            }
        }
    }
}

fn parse_dhcp_hwarp(buf: Input) -> Result<arp::ArpHardwareType> {
    value(arp::ArpHardwareTypes::Ethernet, tag([1]))(buf)
}

fn parse_flags(buf: Input) -> Result<bool> {
    map(be_u16, |x| match x {
        0x8000 => true,
        0x0000 => false,
        f => panic!("unknown flags {:x?}", f)
    })(buf)
}

fn take4(buf: Input) -> Result<&ByteStr>
{
    map(take(4_usize), |x| ByteStr::new(x))(buf)
}

fn parse_ipv4(buf: Input) -> Result<Option<Ipv4Addr>>
{
    map(take4, |x| if x == ByteStr::new(&[0_u8, 0_u8, 0_u8, 0_u8]) {
        None
    } else {
        Some(Ipv4Addr::new(x[0], x[1], x[2], x[3]))
    })(buf)
}

fn new_macaddr(buf: &[u8]) -> datalink::MacAddr
{
    datalink::MacAddr::new(buf[0], buf[1], buf[2], buf[3], buf[4], buf[5])
}

fn parse_chaddr(buf: Input) -> Result<datalink::MacAddr>
{
    terminated(map(take(6_usize), |x| new_macaddr(x)), take(10_usize))(buf)
}

fn parse_dhcp_option(buf: Input) -> Result<(DhcpOptionID, DhcpOption)>
{
    let (buf2, option_id) = be_u8(buf)?;
    let option_id = DhcpOptionID::from(option_id);
    let (buf2, option) = DhcpOption::parse(&option_id, buf2)?;
    Ok((buf2, (option_id, option)))
}

fn parse_dhcp_options(buf: Input) -> Result<HashMap<DhcpOptionID, DhcpOption>>
{
    fold_many0(parse_dhcp_option, HashMap::new(), |mut options: HashMap<_, _>, option| {
        match option.0 {
            DhcpOptionID::OptionEnd => None,
            DhcpOptionID::Pad => None,
            option_id => options.insert(option_id, option.1),
        };
        options
    })(buf)
}

impl DhcpPacket {
    pub fn parse(buf: Input) -> Result<Self> {
        let dhcp_packet = map(tuple((BootpOpcode::parse, parse_dhcp_hwarp, be_u8, be_u8, be_u32, be_u16,
                                     parse_flags, parse_ipv4, parse_ipv4, parse_ipv4, parse_ipv4,
                                     terminated(parse_chaddr, take(192_usize)),
                                     verify(take(4_usize), |x: &[u8]| x.len() == 4
                                         && x == [0x63, 0x82, 0x53, 0x63]),
                                     parse_dhcp_options)),
                              |(opcode, htype, hlen, hops, xid, sec, broadcast, ciaddr, yiaddr, siaddr, giaddr, chaddr, _, options)|
                                  {
                                      Self {
                                          ciaddr,
                                          yiaddr,
                                          siaddr,
                                          giaddr,
                                          opcode,
                                          hops: hops as usize,
                                          hlen: hlen as usize,
                                          htype,
                                          xid,
                                          secs: DhcpDuration::new(sec.into(), 0),
                                          broadcast,
                                          chaddr,
                                          options,
                                      }
                                  })(buf);
        dhcp_packet
    }
}

impl fmt::Display for DhcpPacket {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        let msg_type = self.options.get(&DhcpOptionID::MsgType).map(|x| x.to_string()).unwrap_or("Message type missing".to_string());
        let hostname = self.options.get(&DhcpOptionID::HostName).map(|x| x.to_string()).unwrap_or("No hostname".to_string());
        let subnetmask = self.options.get(&DhcpOptionID::SubnetMask).map(|x| x.to_string()).unwrap_or("No subnet mask".to_string());
        writeln!(w, "Message Type: {}", msg_type)?;
        writeln!(w, "Host name: {}", hostname)?;
        writeln!(w, "Subnet mask: {}", subnetmask)?;
        writeln!(w, "xid: {:x}", self.xid)
    }
}