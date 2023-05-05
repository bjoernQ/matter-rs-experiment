#![no_std]
#![no_main]

use core::borrow::Borrow;

use embedded_svc::ipv4::Interface;
use embedded_svc::wifi::Wifi;
use embedded_svc::wifi::{ClientConfiguration, Configuration};
use esp_backtrace as _;
use esp_println::println;
use esp_wifi::wifi::utils::create_network_interface;
use esp_wifi::wifi::WifiMode;
use esp_wifi::wifi_interface::WifiStack;
use esp_wifi::{current_millis, initialize};
use hal::clock::{ClockControl, CpuClock};
use hal::systimer::SystemTimer;
use hal::Rng;
use hal::{peripherals::Peripherals, prelude::*, timer::TimerGroup, Rtc};
use matter::data_model::cluster_basic_information::BasicInfoConfig;
use matter::data_model::core::DataModel;
use matter::data_model::device_types::DEV_TYPE_ON_OFF_LIGHT;
use matter::data_model::objects::{Endpoint, Handler, Node};
use matter::data_model::sdm::dev_att::DevAttDataFetcher;
use matter::data_model::system_model::descriptor;
use matter::data_model::{cluster_on_off, root_endpoint};
use matter::interaction_model::core::InteractionModel;
use matter::secure_channel::spake2p::VerifierData;
use matter::transport::mgr::{RecvAction, TransportMgr};
use matter::transport::network::Address;
// use matter::transport::packet::{MAX_RX_BUF_SIZE, MAX_TX_BUF_SIZE};
use matter::{CommissioningData, Matter};
use smoltcp::iface::SocketStorage;
use smoltcp::wire::Ipv4Address;

mod dev_attr;
use dev_attr::HardCodedDevAtt;

mod dnssd;
use dnssd::DnsSdResponder;

use crate::dnssd::FakeDnsResponder;

extern crate alloc;

#[global_allocator]
static ALLOCATOR: esp_alloc::EspHeap = esp_alloc::EspHeap::empty();

const SSID: &str = env!("SSID");
const PASSWORD: &str = env!("PASSWORD");

fn init_heap() {
    const HEAP_SIZE: usize = 2 * 1024;

    extern "C" {
        static mut _heap_start: u32;
    }

    unsafe {
        let heap_start = &_heap_start as *const _ as usize;
        ALLOCATOR.init(heap_start as *mut u8, HEAP_SIZE);
    }
}

#[entry]
fn main() -> ! {
    esp_println::logger::init_logger_from_env();
    init_heap();

    let peripherals = Peripherals::take();
    let mut system = peripherals.SYSTEM.split();
    let clocks = ClockControl::configure(system.clock_control, CpuClock::Clock160MHz).freeze();

    // Disable the RTC and TIMG watchdog timers
    let mut rtc = Rtc::new(peripherals.RTC_CNTL);
    let timer_group0 = TimerGroup::new(
        peripherals.TIMG0,
        &clocks,
        &mut system.peripheral_clock_control,
    );
    let mut wdt0 = timer_group0.wdt;
    let timer_group1 = TimerGroup::new(
        peripherals.TIMG1,
        &clocks,
        &mut system.peripheral_clock_control,
    );
    let mut wdt1 = timer_group1.wdt;
    rtc.swd.disable();
    rtc.rwdt.disable();
    wdt0.disable();
    wdt1.disable();

    let systimer = SystemTimer::new(peripherals.SYSTIMER);
    initialize(
        systimer.alarm0,
        Rng::new(peripherals.RNG),
        system.radio_clock_control,
        &clocks,
    )
    .unwrap();

    // Connect to wifi
    let (wifi, _) = peripherals.RADIO.split();
    let mut socket_set_entries: [SocketStorage; 3] = Default::default();
    let (iface, device, mut controller, sockets) =
        create_network_interface(wifi, WifiMode::Sta, &mut socket_set_entries);
    let wifi_stack = WifiStack::new(iface, device, sockets, current_millis);

    let client_config = Configuration::Client(ClientConfiguration {
        ssid: SSID.into(),
        password: PASSWORD.into(),
        ..Default::default()
    });
    let res = controller.set_configuration(&client_config);
    println!("wifi_set_configuration returned {:?}", res);

    controller.start().unwrap();
    println!("is wifi started: {:?}", controller.is_started());

    println!("wifi_connect {:?}", controller.connect());

    // wait to get connected
    println!("Wait to get connected");
    loop {
        let res = controller.is_connected();
        match res {
            Ok(connected) => {
                if connected {
                    break;
                }
            }
            Err(err) => {
                println!("{:?}", err);
                loop {}
            }
        }
    }
    println!("{:?}", controller.is_connected());

    let mut local_ip = [0u8; 4];
    // wait for getting an ip address
    println!("Wait to get an ip address");
    loop {
        wifi_stack.work();

        if wifi_stack.is_iface_up() {
            println!("got ip {:?}", wifi_stack.get_ip_info());
            local_ip.copy_from_slice(&wifi_stack.get_ip_info().unwrap().ip.octets());
            break;
        }
    }

    // these buffers were 1536
    let mut rx_meta1 = [smoltcp::socket::udp::PacketMetadata::EMPTY; 4];
    let mut rx_buffer1 = [0u8; 1100];
    let mut tx_meta1 = [smoltcp::socket::udp::PacketMetadata::EMPTY; 4];
    let mut tx_buffer1 = [0u8; 900];
    let mut matter_socket = wifi_stack.get_udp_socket(
        &mut rx_meta1,
        &mut rx_buffer1,
        &mut tx_meta1,
        &mut tx_buffer1,
    );

    matter_socket.bind(5540).unwrap();

    let mut rx_meta1 = [smoltcp::socket::udp::PacketMetadata::EMPTY; 4];
    let mut rx_buffer1 = [0u8; 800];
    let mut tx_meta1 = [smoltcp::socket::udp::PacketMetadata::EMPTY; 4];
    let mut tx_buffer1 = [0u8; 800];
    let mdns_socket = wifi_stack.get_udp_socket(
        &mut rx_meta1,
        &mut rx_buffer1,
        &mut tx_meta1,
        &mut tx_buffer1,
    );

    println!("All good - let's go");

    // vid/pid should match those in the DAC
    let dev_info = BasicInfoConfig {
        vid: 0xFFF1,
        pid: 0x8000,
        hw_ver: 2,
        sw_ver: 1,
        sw_ver_str: "1",
        serial_no: "aabbccdd",
        device_name: "OnOff Light",
    };

    let mut mdns = DnsSdResponder::new(mdns_socket, local_ip);
    let mut dummy_dns = FakeDnsResponder { local_ip };

    let matter = Matter::new(
        &dev_info,
        &mut dummy_dns,
        epoch,
        matter_rand, // my_replay_rand,
        5540,
    );

    let dev_att = HardCodedDevAtt::new();

    let mut buf = [0; 1526]; // was 4096

    matter
        .start(
            CommissioningData {
                // TODO: Hard-coded for now
                verifier: VerifierData::new_with_pw(123456, *matter.borrow()),
                discriminator: 250,
            },
            &mut buf,
        )
        .unwrap();

    let matter = &matter;
    let dev_att = &dev_att;

    let mut transport = TransportMgr::new(matter);

    let mut rx_buf = [0; 800]; // was MAX_RX_BUF_SIZE
    let mut tx_buf = [0; 900]; // was MAX_TX_BUF_SIZE

    loop {
        mdns.poll(current_millis());

        let (len, from, from_port) = if let Ok(res) = matter_socket.receive(&mut rx_buf) {
            res
        } else {
            (0usize, [0u8, 0u8, 0u8, 0u8], 0)
        };

        if len == 0 {
            continue;
        }

        let addr = no_std_net::SocketAddr::V4(no_std_net::SocketAddrV4::new(
            no_std_net::Ipv4Addr::new(from[0], from[1], from[2], from[3]),
            from_port,
        ));
        let addr = matter::transport::network::Address::Udp(addr);
        println!("RECEIVED {} bytes", len);
        let mut completion = transport.recv(addr, &mut rx_buf[..len], &mut tx_buf);

        while let Some(action) = completion.next_action().unwrap() {
            match action {
                RecvAction::Send(addr, buf) => {
                    if let Address::Udp(no_std_net::SocketAddr::V4(addr)) = addr {
                        let port = addr.port();
                        let addr = addr.ip().octets();
                        println!("SENDING {} bytes to {:?}:{}", buf.len(), addr, port);
                        matter_socket
                            .send(Ipv4Address::from_bytes(&addr), port, buf)
                            .unwrap();
                    }
                }
                RecvAction::Interact(mut ctx) => {
                    let node = Node {
                        id: 0,
                        endpoints: &[
                            root_endpoint::endpoint(0),
                            Endpoint {
                                id: 1,
                                device_type: DEV_TYPE_ON_OFF_LIGHT,
                                clusters: &[descriptor::CLUSTER, cluster_on_off::CLUSTER],
                            },
                        ],
                    };

                    let mut handler = handler(matter, dev_att);

                    let mut im =
                        InteractionModel(DataModel::new(matter.borrow(), &node, &mut handler));

                    if im.handle(&mut ctx).unwrap() {
                        if ctx.send().unwrap() {
                            let addr = ctx.tx.peer;
                            if let Address::Udp(no_std_net::SocketAddr::V4(addr)) = addr {
                                let port = addr.port();
                                let addr = addr.ip().octets();
                                println!("SENDING {} bytes", ctx.tx.as_slice().len());
                                matter_socket
                                    .send(Ipv4Address::from_bytes(&addr), port, ctx.tx.as_slice())
                                    .unwrap();
                            }
                        }
                    }
                }
            }
        }

        if let Some(_data) = matter.store_fabrics(&mut buf).unwrap() {
            // psm.store("fabrics", data)?;
            println!("TODO store fabrics");
        }

        if let Some(_data) = matter.store_acls(&mut buf).unwrap() {
            // psm.store("acls", data)?;
            println!("TODO store acls");
        }
    }
}

fn epoch() -> core::time::Duration {
    core::time::Duration::from_millis(current_millis())
}

fn matter_rand(buffer: &mut [u8]) {
    for b in buffer.iter_mut() {
        *b = unsafe { esp_wifi::wifi::rand() as u8 };
    }
}

fn handler<'a>(matter: &'a Matter<'a>, dev_att: &'a dyn DevAttDataFetcher) -> impl Handler + 'a {
    root_endpoint::handler(0, dev_att, matter)
        .chain(
            1,
            descriptor::ID,
            descriptor::DescriptorCluster::new(*matter.borrow()),
        )
        .chain(
            1,
            cluster_on_off::ID,
            cluster_on_off::OnOffCluster::new(*matter.borrow()),
        )
}
