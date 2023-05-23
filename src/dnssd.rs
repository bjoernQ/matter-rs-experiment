use core::fmt::Write;
use domain::base::header::Flags;
use domain::base::iana::Class;
use domain::base::octets::{Octets256, Octets64, OctetsBuilder};
use domain::base::{Dname, MessageBuilder, Record};
use domain::rdata::{Aaaa, Ptr, Srv, Txt};
use esp_println::println;
use esp_wifi::wifi_interface::UdpSocket;
use matter::mdns::Mdns;
use smoltcp::wire::{IpAddress, Ipv4Address};

use core::str::FromStr;

pub struct DnsSdResponder<'a, 'b> {
    socket: UdpSocket<'a, 'b>,
    next_announce: u64,
}

impl<'a, 'b> DnsSdResponder<'a, 'b> {
    pub fn new(mut socket: UdpSocket<'a, 'b>, _local_ip: [u8; 4]) -> Self {
        socket
            .join_multicast_group(IpAddress::Ipv4(Ipv4Address::new(224, 0, 0, 251)))
            .unwrap();
        socket.bind(5353).unwrap();

        Self {
            socket,
            next_announce: 0,
        }
    }

    pub fn poll(&mut self, millis: u64) {
        self.handle_incoming();
        self.handle_announce(millis);
    }

    fn handle_incoming(&mut self) {
        // let msg = self.socket.receive(&mut self.buffer);

        // if let Ok((msg, _from, _port)) = msg {
        //     log::trace!("DNSSD Received");
        // }
    }

    fn handle_announce(&mut self, timestamp: u64) {
        if timestamp > self.next_announce {
            self.next_announce += 10_000; // announce every 10 secs for now

            log::info!("announce");
            unsafe {
                if RECORD_LEN > 0 {
                    log::info!("send announcement");

                    self.socket
                        .send(
                            IpAddress::Ipv4(Ipv4Address::new(224, 0, 0, 251)),
                            5353,
                            &RECORD[..RECORD_LEN],
                        )
                        .unwrap();
                }
            }
        }
    }
}

impl<'a, 'b> Mdns for DnsSdResponder<'a, 'b> {
    fn add(
        &mut self,
        _name: &str,
        _service: &str,
        _protocol: &str,
        _port: u16,
        _service_subtypes: &[&str],
        _txt_kvs: &[(&str, &str)],
    ) -> Result<(), matter::error::Error> {
        Ok(())
    }

    fn remove(
        &mut self,
        name: &str,
        service: &str,
        protocol: &str,
        port: u16,
    ) -> Result<(), matter::error::Error> {
        println!("MDNS remove {} {} {} {}", name, service, protocol, port);
        unsafe {
            RECORD_LEN = 0;
        }
        Ok(())
    }
}

static mut RECORD: [u8; 1000] = [0u8; 1000];
static mut RECORD_LEN: usize = 0;

pub struct FakeDnsResponder {
    pub local_ip: [u16; 8],
}

impl Mdns for FakeDnsResponder {
    fn add(
        &mut self,
        name: &str,
        service: &str,
        protocol: &str,
        port: u16,
        service_subtypes: &[&str],
        txt_kvs: &[(&str, &str)],
    ) -> Result<(), matter::error::Error> {
        println!("MDNS add {} {} {} {}", name, service, protocol, port);
        for n in service_subtypes {
            println!("SUB {}", n);
        }
        for (k, v) in txt_kvs {
            println!("TXT {} => {}", k, v);
        }

        let len = create_record(
            unsafe { &mut RECORD },
            0,
            "esp32c3",
            &self.local_ip,
            name,
            service,
            protocol,
            port,
            service_subtypes,
            txt_kvs,
        );

        unsafe {
            RECORD_LEN = len;
        }
        Ok(())
    }

    fn remove(
        &mut self,
        name: &str,
        service: &str,
        protocol: &str,
        port: u16,
    ) -> Result<(), matter::error::Error> {
        println!("MDNS remove {} {} {} {}", name, service, protocol, port);
        Ok(())
    }
}

fn create_record(
    buffer: &mut [u8],
    id: u16,
    hostname: &str,
    ip: &[u16; 8],

    name: &str,
    service: &str,
    protocol: &str,
    port: u16,
    service_subtypes: &[&str],
    txt_kvs: &[(&str, &str)],
) -> usize {
    const TTL: u32 = 60;

    let target = domain::base::octets::Octets2048::new();
    let message = MessageBuilder::from_target(target).unwrap();

    let mut message = message.answer();

    let mut ptr_str = heapless::String::<40>::new();
    write!(ptr_str, "{}.{}.local", service, protocol).unwrap();

    let mut dname = heapless::String::<60>::new();
    write!(dname, "{}.{}.{}.local", name, service, protocol).unwrap();

    let mut hname = heapless::String::<40>::new();
    write!(hname, "{}.local", hostname).unwrap();

    let ptr: Dname<Octets64> = Dname::from_str(&ptr_str).unwrap();
    let record: Record<Dname<Octets64>, Ptr<_>> = Record::new(
        Dname::from_str(&"_services._dns-sd._udp.local").unwrap(),
        Class::In,
        TTL,
        Ptr::new(ptr),
    );
    message.push(record).unwrap();

    let t: Dname<Octets64> = Dname::from_str(&dname).unwrap();
    let record: Record<Dname<Octets64>, Ptr<_>> = Record::new(
        Dname::from_str(&ptr_str).unwrap(),
        Class::In,
        TTL,
        Ptr::new(t),
    );
    message.push(record).unwrap();

    for sub_srv in service_subtypes {
        let mut ptr_str = heapless::String::<40>::new();
        write!(ptr_str, "{}._sub.{}.{}.local", sub_srv, service, protocol).unwrap();

        let ptr: Dname<Octets64> = Dname::from_str(&ptr_str).unwrap();
        let record: Record<Dname<Octets64>, Ptr<_>> = Record::new(
            Dname::from_str(&"_services._dns-sd._udp.local").unwrap(),
            Class::In,
            TTL,
            Ptr::new(ptr),
        );
        message.push(record).unwrap();

        let t: Dname<Octets64> = Dname::from_str(&dname).unwrap();
        let record: Record<Dname<Octets64>, Ptr<_>> = Record::new(
            Dname::from_str(&ptr_str).unwrap(),
            Class::In,
            TTL,
            Ptr::new(t),
        );
        message.push(record).unwrap();
    }

    let target: Dname<Octets64> = Dname::from_str(&hname).unwrap();
    let record: Record<Dname<Octets64>, Srv<_>> = Record::new(
        Dname::from_str(&dname).unwrap(),
        Class::In,
        TTL,
        Srv::new(0, 0, port, target),
    );
    message.push(record).unwrap();

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
        Record::new(Dname::from_str(&dname).unwrap(), Class::In, TTL, txt);
    message.push(record).unwrap();

    let record: Record<Dname<Octets64>, Aaaa> = Record::new(
        Dname::from_str(&hname).unwrap(),
        Class::In,
        TTL,
        Aaaa::new((*ip).into()),
    );
    message.push(record).unwrap();

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
    target.len()
}
