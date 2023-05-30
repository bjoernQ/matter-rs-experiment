use core::cell::RefCell;
use core::fmt::Write;
use core::pin::pin;
use core::str::FromStr;

use domain::base::header::Flags;
use domain::base::iana::Class;
use domain::base::octets::{Octets256, Octets64, OctetsBuilder};
use domain::base::{Dname, MessageBuilder, Record, ShortBuf};
use domain::rdata::{Aaaa, Ptr, Srv, Txt, A};
use embassy_futures::select::select;
use embassy_net::udp::UdpSocket;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_time::{Duration, Timer};
use log::info;

use matter::error::{Error, ErrorCode};
use matter::transport::network::{IpAddr, Ipv4Addr, Ipv6Addr};
use matter::utils::select::EitherUnwrap;

const IP_BROADCAST_ADDRS: [(IpAddr, u16); 2] = [
    (IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), 5353),
    (
        IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb)),
        5353,
    ),
];

#[allow(clippy::too_many_arguments)]
pub fn create_record(
    id: u16,
    hostname: &str,
    ip: [u8; 4],
    ipv6: Option<[u8; 16]>,

    ttl_sec: u32,

    name: &str,
    service: &str,
    protocol: &str,
    port: u16,
    service_subtypes: &[&str],
    txt_kvs: &[(&str, &str)],

    buffer: &mut [u8],
) -> Result<usize, ShortBuf> {
    let target = domain::base::octets::Octets2048::new();
    let message = MessageBuilder::from_target(target)?;

    let mut message = message.answer();

    let mut ptr_str = heapless::String::<40>::new();
    write!(ptr_str, "{}.{}.local", service, protocol).unwrap();

    let mut dname = heapless::String::<60>::new();
    write!(dname, "{}.{}.{}.local", name, service, protocol).unwrap();

    let mut hname = heapless::String::<40>::new();
    write!(hname, "{}.local", hostname).unwrap();

    let ptr: Dname<Octets64> = Dname::from_str(&ptr_str).unwrap();
    let record: Record<Dname<Octets64>, Ptr<_>> = Record::new(
        Dname::from_str("_services._dns-sd._udp.local").unwrap(),
        Class::In,
        ttl_sec,
        Ptr::new(ptr),
    );
    message.push(record)?;

    let t: Dname<Octets64> = Dname::from_str(&dname).unwrap();
    let record: Record<Dname<Octets64>, Ptr<_>> = Record::new(
        Dname::from_str(&ptr_str).unwrap(),
        Class::In,
        ttl_sec,
        Ptr::new(t),
    );
    message.push(record)?;

    for sub_srv in service_subtypes {
        let mut ptr_str = heapless::String::<40>::new();
        write!(ptr_str, "{}._sub.{}.{}.local", sub_srv, service, protocol).unwrap();

        let ptr: Dname<Octets64> = Dname::from_str(&ptr_str).unwrap();
        let record: Record<Dname<Octets64>, Ptr<_>> = Record::new(
            Dname::from_str("_services._dns-sd._udp.local").unwrap(),
            Class::In,
            ttl_sec,
            Ptr::new(ptr),
        );
        message.push(record)?;

        let t: Dname<Octets64> = Dname::from_str(&dname).unwrap();
        let record: Record<Dname<Octets64>, Ptr<_>> = Record::new(
            Dname::from_str(&ptr_str).unwrap(),
            Class::In,
            ttl_sec,
            Ptr::new(t),
        );
        message.push(record)?;
    }

    let target: Dname<Octets64> = Dname::from_str(&hname).unwrap();
    let record: Record<Dname<Octets64>, Srv<_>> = Record::new(
        Dname::from_str(&dname).unwrap(),
        Class::In,
        ttl_sec,
        Srv::new(0, 0, port, target),
    );
    message.push(record)?;

    // only way I found to create multiple parts in a Txt
    // each slice is the length and then the data
    let mut octets = Octets256::new();
    //octets.append_slice(&[1u8, b'X']).unwrap();
    //octets.append_slice(&[2u8, b'A', b'B']).unwrap();
    //octets.append_slice(&[0u8]).unwrap();
    for (k, v) in txt_kvs {
        octets
            .append_slice(&[(k.len() + v.len() + 1) as u8])
            .unwrap();
        octets.append_slice(k.as_bytes()).unwrap();
        octets.append_slice(&[b'=']).unwrap();
        octets.append_slice(v.as_bytes()).unwrap();
    }

    let txt = Txt::from_octets(&mut octets).unwrap();

    let record: Record<Dname<Octets64>, Txt<_>> =
        Record::new(Dname::from_str(&dname).unwrap(), Class::In, ttl_sec, txt);
    message.push(record)?;

    let record: Record<Dname<Octets64>, A> = Record::new(
        Dname::from_str(&hname).unwrap(),
        Class::In,
        ttl_sec,
        A::from_octets(ip[0], ip[1], ip[2], ip[3]),
    );
    message.push(record)?;

    if let Some(ipv6) = ipv6 {
        let record: Record<Dname<Octets64>, Aaaa> = Record::new(
            Dname::from_str(&hname).unwrap(),
            Class::In,
            ttl_sec,
            Aaaa::new(ipv6.into()),
        );
        message.push(record)?;
    }

    let headerb = message.header_mut();
    headerb.set_id(id);
    headerb.set_opcode(domain::base::iana::Opcode::Query);
    headerb.set_rcode(domain::base::iana::Rcode::NoError);

    let mut flags = Flags::new();
    flags.qr = true;
    flags.aa = true;
    headerb.set_flags(flags);

    let target = message.finish();

    buffer[..target.len()].copy_from_slice(target.as_ref());

    Ok(target.len())
}

pub type Notification = embassy_sync::signal::Signal<NoopRawMutex, ()>;

#[derive(Debug, Clone)]
struct MdnsEntry {
    key: heapless::String<64>,
    record: heapless::Vec<u8, 1024>,
}

impl MdnsEntry {
    #[inline(always)]
    const fn new() -> Self {
        Self {
            key: heapless::String::new(),
            record: heapless::Vec::new(),
        }
    }
}

pub struct Mdns<'a> {
    id: u16,
    hostname: &'a str,
    ip: [u8; 4],
    ipv6: Option<[u8; 16]>,
    entries: RefCell<heapless::Vec<MdnsEntry, 4>>,
    notification: Notification,
    udp: RefCell<Option<UdpSocket<'a>>>,
}

impl<'a> Mdns<'a> {
    #[inline(always)]
    pub const fn new(
        id: u16,
        hostname: &'a str,
        ip: [u8; 4],
        ipv6: Option<[u8; 16]>,
        udp: Option<UdpSocket<'a>>,
    ) -> Self {
        Self {
            id,
            hostname,
            ip,
            ipv6,
            entries: RefCell::new(heapless::Vec::new()),
            notification: Notification::new(),
            udp: RefCell::new(udp),
        }
    }

    pub fn split(&mut self) -> (MdnsApi<'_, 'a>, MdnsRunner<'_, 'a>) {
        (MdnsApi(&*self), MdnsRunner(&*self))
    }

    async fn bind(&self) -> Result<(), Error> {
        // if self.udp.borrow().is_none() {
        //     *self.udp.borrow_mut() =
        //         Some(UdpListener::new(SocketAddr::new(IP_BIND_ADDR.0, IP_BIND_ADDR.1)).await?);
        // }

        Ok(())
    }

    pub fn close(&mut self) {
        *self.udp.borrow_mut() = None;
    }

    fn key(&self, name: &str, service: &str, protocol: &str, port: u16) -> heapless::String<64> {
        let mut key = heapless::String::new();

        write!(&mut key, "{name}.{service}.{protocol}.{port}").unwrap();

        key
    }
}

pub struct MdnsApi<'a, 'b>(&'a Mdns<'b>);

impl<'a, 'b> MdnsApi<'a, 'b> {
    pub fn add(
        &self,
        name: &str,
        service: &str,
        protocol: &str,
        port: u16,
        service_subtypes: &[&str],
        txt_kvs: &[(&str, &str)],
    ) -> Result<(), Error> {
        info!(
            "Registering mDNS service {}/{}.{} [{:?}]/{}, keys [{:?}]",
            name, service, protocol, service_subtypes, port, txt_kvs
        );

        let key = self.0.key(name, service, protocol, port);

        let mut entries = self.0.entries.borrow_mut();

        entries.retain(|entry| entry.key != key);
        entries
            .push(MdnsEntry::new())
            .map_err(|_| ErrorCode::NoSpace)?;

        let entry = entries.iter_mut().last().unwrap();
        entry
            .record
            .resize(1024, 0)
            .map_err(|_| ErrorCode::NoSpace)
            .unwrap();

        match create_record(
            self.0.id,
            self.0.hostname,
            self.0.ip,
            self.0.ipv6,
            60, /*ttl_sec*/
            name,
            service,
            protocol,
            port,
            service_subtypes,
            txt_kvs,
            &mut entry.record,
        ) {
            Ok(len) => entry.record.truncate(len),
            Err(_) => {
                entries.pop();
                Err(ErrorCode::NoSpace)?;
            }
        }

        self.0.notification.signal(());

        Ok(())
    }

    pub fn remove(
        &self,
        name: &str,
        service: &str,
        protocol: &str,
        port: u16,
    ) -> Result<(), Error> {
        info!(
            "Deregistering mDNS service {}/{}.{}/{}",
            name, service, protocol, port
        );

        let key = self.0.key(name, service, protocol, port);

        let mut entries = self.0.entries.borrow_mut();

        let old_len = entries.len();

        entries.retain(|entry| entry.key != key);

        if entries.len() != old_len {
            self.0.notification.signal(());
        }

        Ok(())
    }
}

pub struct MdnsRunner<'a, 'b>(&'a Mdns<'b>);

impl<'a, 'b> MdnsRunner<'a, 'b> {
    pub async fn run(&mut self) -> Result<(), Error> {
        let mut broadcast = pin!(self.broadcast());
        let mut respond = pin!(self.respond());

        select(&mut broadcast, &mut respond).await.unwrap()
    }

    #[allow(clippy::await_holding_refcell_ref)]
    async fn broadcast(&self) -> Result<(), Error> {
        loop {
            select(
                self.0.notification.wait(),
                Timer::after(Duration::from_secs(30)),
            )
            .await;

            let mut index = 0;

            loop {
                let entry = self.0.entries.borrow().get(index).cloned();

                if let Some(entry) = entry {
                    info!("Broadasting mDNS entry {}", &entry.key);

                    self.0.bind().await?;

                    let udp = self.0.udp.borrow();
                    let udp = udp.as_ref().unwrap();

                    for (_addr, _port) in IP_BROADCAST_ADDRS {
                        let endpoint = smoltcp::wire::IpEndpoint::new(
                            embassy_net::IpAddress::Ipv4(embassy_net::Ipv4Address::new(
                                224, 0, 0, 251,
                            )),
                            5353,
                        );
                        udp.send_to(&entry.record, endpoint).await.unwrap();
                    }

                    index += 1;
                } else {
                    break;
                }
            }
        }
    }

    #[allow(clippy::await_holding_refcell_ref)]
    async fn respond(&self) -> Result<(), Error> {
        loop {
            let mut buf = [0; 1580];

            let udp = self.0.udp.borrow();
            let udp = udp.as_ref().unwrap();

            let (_len, _addr) = udp.recv_from(&mut buf).await.unwrap();

            info!("Received UDP packet");

            // TODO: Process the incoming packed and only answer what we are being queried about

            self.0.notification.signal(());
        }
    }
}

impl<'a, 'b> matter::mdns::Mdns for MdnsApi<'a, 'b> {
    fn add(
        &mut self,
        name: &str,
        service: &str,
        protocol: &str,
        port: u16,
        service_subtypes: &[&str],
        txt_kvs: &[(&str, &str)],
    ) -> Result<(), Error> {
        MdnsApi::add(
            self,
            name,
            service,
            protocol,
            port,
            service_subtypes,
            txt_kvs,
        )
    }

    fn remove(
        &mut self,
        name: &str,
        service: &str,
        protocol: &str,
        port: u16,
    ) -> Result<(), Error> {
        MdnsApi::remove(self, name, service, protocol, port)
    }
}
