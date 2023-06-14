#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]
#![feature(async_fn_in_trait)]

use core::cell::RefCell;
use core::mem::MaybeUninit;
use core::pin::pin;

use embassy_executor::Executor;
use embassy_executor::_export::StaticCell;
use hal::gpio::{Gpio5, Output, PushPull};
use matter::error::Error;
use matter::mdns::{DefaultMdns, DefaultMdnsRunner};
use matter::transport::packet::{MAX_RX_BUF_SIZE, MAX_TX_BUF_SIZE};
use matter::transport::runner::{RxBuf, TransportRunner, TxBuf};

use core::borrow::{Borrow, BorrowMut};
use embassy_futures::select::{self, select3, select4};
use embassy_net::udp::UdpSocket;
use embassy_net::{udp::PacketMetadata, Config, Ipv4Address, Stack, StackResources};
use embassy_time::{Duration, Timer};
use embedded_svc::wifi::Wifi;
use embedded_svc::wifi::{ClientConfiguration, Configuration};
use esp_backtrace as _;
use esp_println::println;
use esp_wifi::wifi::{WifiController, WifiDevice, WifiEvent, WifiMode, WifiState};
use esp_wifi::{current_millis, initialize};
use hal::clock::{ClockControl, CpuClock};
use hal::systimer::SystemTimer;
use hal::{embassy, Rng, IO};
use hal::{peripherals::Peripherals, prelude::*, timer::TimerGroup, Rtc};
use log::info;
use matter::data_model::cluster_basic_information::BasicInfoConfig;
use matter::data_model::device_types::DEV_TYPE_ON_OFF_LIGHT;
use matter::data_model::objects::{DataModelHandler, Endpoint, Handler, HandlerCompat, Node};
use matter::data_model::system_model::descriptor;
use matter::data_model::{cluster_on_off, root_endpoint};
use matter::secure_channel::spake2p::VerifierData;
use matter::transport::core::Transport;
use matter::transport::exchange::MAX_EXCHANGES;
use matter::transport::network::Address;
use matter::transport::pipe::{Chunk, Pipe};
use matter::utils::select::EitherUnwrap;
use matter::{CommissioningData, Matter};
use no_std_net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use smoltcp::wire::{IpAddress, IpEndpoint, Ipv6Address};

mod dev_attr;

extern crate alloc;

#[global_allocator]
static ALLOCATOR: esp_alloc::EspHeap = esp_alloc::EspHeap::empty();

const SSID: &str = env!("SSID");
const PASSWORD: &str = env!("PASSWORD");

static LED: critical_section::Mutex<RefCell<Option<Gpio5<Output<PushPull>>>>> =
    critical_section::Mutex::new(RefCell::new(None));

macro_rules! singleton {
    ($val:expr) => {{
        type T = impl Sized;
        static STATIC_CELL: StaticCell<T> = StaticCell::new();
        let (x,) = STATIC_CELL.init(($val,));
        x
    }};
}

static EXECUTOR: StaticCell<Executor> = StaticCell::new();

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

    let io = IO::new(peripherals.GPIO, peripherals.IO_MUX);
    let led = io.pins.gpio5.into_push_pull_output();
    critical_section::with(|cs| {
        LED.borrow_ref_mut(cs).replace(led);
    });

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
    let (wifi_interface, controller) = esp_wifi::wifi::new_with_mode(wifi, WifiMode::Sta);

    embassy::init(&clocks, timer_group0.timer0);

    let config = Config::Dhcp(Default::default());

    let seed = 1234; // very random, very secure seed

    // Init network stack
    let stack = &*singleton!(Stack::new(
        wifi_interface,
        config,
        singleton!(StackResources::<3>::new()),
        seed
    ));

    let executor = EXECUTOR.init(Executor::new());
    executor.run(|spawner| {
        spawner.spawn(connection(controller)).ok();
        spawner.spawn(net_task(&stack)).ok();
        spawner.spawn(task(&stack)).ok();
    })
}

#[embassy_executor::task]
async fn connection(mut controller: WifiController<'static>) {
    println!("start connection task");
    println!("Device capabilities: {:?}", controller.get_capabilities());
    loop {
        match esp_wifi::wifi::get_wifi_state() {
            WifiState::StaConnected => {
                // wait until we're no longer connected
                controller.wait_for_event(WifiEvent::StaDisconnected).await;
                Timer::after(Duration::from_millis(5000)).await
            }
            _ => {}
        }
        if !matches!(controller.is_started(), Ok(true)) {
            let client_config = Configuration::Client(ClientConfiguration {
                ssid: SSID.into(),
                password: PASSWORD.into(),
                ..Default::default()
            });
            controller.set_configuration(&client_config).unwrap();
            println!("Starting wifi");
            controller.start().await.unwrap();
            println!("Wifi started!");
        }
        println!("About to connect...");

        match controller.connect().await {
            Ok(_) => println!("Wifi connected!"),
            Err(e) => {
                println!("Failed to connect to wifi: {e:?}");
                Timer::after(Duration::from_millis(5000)).await
            }
        }
    }
}

#[embassy_executor::task]
async fn net_task(stack: &'static Stack<WifiDevice<'static>>) {
    stack.run().await
}

#[embassy_executor::task]
async fn task(stack: &'static Stack<WifiDevice<'static>>) {
    loop {
        if stack.is_link_up() {
            break;
        }
        Timer::after(Duration::from_millis(500)).await;
    }

    let mut ipv4_addr_octets = [0u8; 4];
    let mut ipv6_addr_octets = [0u8; 16];

    println!("Waiting to get IP address...");
    loop {
        if let Some(config) = stack.config() {
            ipv4_addr_octets.copy_from_slice(config.address.address().as_bytes());
            // TODO hardcoded link local address for now - you will need to change it!
            ipv6_addr_octets.copy_from_slice(&[
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x36, 0xb4, 0x72, 0xff, 0xfe, 0x4c, 0x44, 0x10,
            ]);
            break;
        }
        Timer::after(Duration::from_millis(500)).await;
    }

    println!("Got IPv4: {:?}", &ipv4_addr_octets);
    println!("Got IPv6: {:x?}", &ipv6_addr_octets);

    let mut rx_meta = [PacketMetadata::EMPTY; 16];
    let mut rx_buffer = [0; 4096];
    let mut tx_meta = [PacketMetadata::EMPTY; 16];
    let mut tx_buffer = [0; 4096];

    let mut matter_udp_socket = UdpSocket::new(
        stack,
        &mut rx_meta,
        &mut rx_buffer,
        &mut tx_meta,
        &mut tx_buffer,
    );
    matter_udp_socket.bind(5540).unwrap();

    let mut rx_meta = [PacketMetadata::EMPTY; 16];
    let mut rx_buffer = [0; 4096];
    let mut tx_meta = [PacketMetadata::EMPTY; 16];
    let mut tx_buffer = [0; 4096];

    let mut dnssd_udp_socket = UdpSocket::new(
        stack,
        &mut rx_meta,
        &mut rx_buffer,
        &mut tx_meta,
        &mut tx_buffer,
    );
    dnssd_udp_socket.bind(5353).unwrap();

    let dev_det = BasicInfoConfig {
        vid: 0xFFF1,
        pid: 0x8000,
        hw_ver: 2,
        sw_ver: 1,
        sw_ver_str: "1",
        serial_no: "aabbccdd",
        device_name: "OnOff Light",
    };

    let mdns = DefaultMdns::new(
        0,
        "matter-demo",
        ipv4_addr_octets,
        Some(ipv6_addr_octets),
        0,
        &dev_det,
        matter::MATTER_PORT,
    );

    let mut mdns_runner = DefaultMdnsRunner::new(&mdns);

    info!("mDNS initialized: {:p}, {:p}", &mdns, &mdns_runner);

    let dev_att = dev_attr::HardCodedDevAtt::new();

    let matter = Matter::new(
        // vid/pid should match those in the DAC
        &dev_det,
        &dev_att,
        &mdns,
        epoch,
        matter_rand,
        matter::MATTER_PORT,
    );

    let mut runner = TransportRunner::new(&matter);

    let mut buf = [0; 4096];
    let buf = &mut buf;

    info!("Transport runner initialized: {:p}", &runner);

    let mut tx_buf = TxBuf::uninit();
    let mut rx_buf = RxBuf::uninit();

    // //  let psm_path = std::env::temp_dir().join("matter-iot");
    // //  info!("Persisting from/to {}", psm_path.display());

    // //  let psm = matter::persist::FilePsm::new(psm_path)?;

    // //  load(transport.matter(), &psm)?;

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

    let handler = HandlerCompat(handler(&matter));

    let matter = &matter;
    let node = &node;
    let handler = &handler;
    let runner = &mut runner;
    let tx_buf = &mut tx_buf;
    let rx_buf = &mut rx_buf;

    let dev_comm = CommissioningData {
        // TODO: Hard-coded for now
        verifier: VerifierData::new_with_pw(123456, *matter.borrow()),
        discriminator: 250,
    };

    info!(
        "About to run wth node {:p}, handler {:p}, transport runner {:p}, mdns_runner {:p}",
        node, handler, runner, &mdns_runner
    );

    let matter_udp_socket = &matter_udp_socket;

    let mut tx_buf = TxBuf::uninit();
    let mut rx_buf = RxBuf::uninit();

    let tx_buf = &mut tx_buf;
    let rx_buf = &mut rx_buf;

    let mut transport_run = pin!(async move {
        let tx_pipe = Pipe::new(unsafe { tx_buf.assume_init_mut() });
        let rx_pipe = Pipe::new(unsafe { rx_buf.assume_init_mut() });

        let tx_pipe = &tx_pipe;
        let rx_pipe = &rx_pipe;

        let mut tx = pin!(async move {
            loop {
                {
                    let mut data = tx_pipe.data.lock().await;

                    if let Some(chunk) = data.chunk {
                        let remote_endpoint = match chunk.addr.unwrap_udp().ip() {
                            no_std_net::IpAddr::V4(v4) => IpEndpoint::new(
                                smoltcp::wire::IpAddress::Ipv4(Ipv4Address::from_bytes(
                                    &v4.octets(),
                                )),
                                chunk.addr.unwrap_udp().port(),
                            ),
                            no_std_net::IpAddr::V6(v6) => IpEndpoint::new(
                                smoltcp::wire::IpAddress::Ipv6(Ipv6Address::from_bytes(
                                    &v6.octets(),
                                )),
                                chunk.addr.unwrap_udp().port(),
                            ),
                        };

                        matter_udp_socket
                            .send_to(&data.buf[chunk.start..chunk.end], remote_endpoint)
                            .await
                            .unwrap();

                        data.chunk = None;
                        tx_pipe.data_consumed_notification.signal(());
                    }
                }

                tx_pipe.data_supplied_notification.wait().await;
            }
        });

        let mut rx = pin!(async move {
            loop {
                {
                    let mut data = rx_pipe.data.lock().await;

                    if data.chunk.is_none() {
                        let (len, addr) = matter_udp_socket.recv_from(&mut data.buf).await.unwrap();
                        let port = addr.port;

                        let addr = match addr.addr {
                            IpAddress::Ipv4(_) => {
                                let mut addr_bytes = [0u8; 4];
                                addr_bytes.copy_from_slice(addr.addr.as_bytes());
                                let ip_addr = Ipv4Addr::from(addr_bytes);
                                let addr = SocketAddr::V4(SocketAddrV4::new(ip_addr, port));
                                addr
                            }
                            IpAddress::Ipv6(_) => {
                                let mut addr_bytes = [0u8; 16];
                                addr_bytes.copy_from_slice(addr.addr.as_bytes());
                                let ip_addr = Ipv6Addr::from(addr_bytes);
                                let addr = SocketAddr::V6(SocketAddrV6::new(ip_addr, port, 0, 0));
                                addr
                            }
                        };

                        data.chunk = Some(Chunk {
                            start: 0,
                            end: len,
                            addr: Address::Udp(addr),
                        });
                        rx_pipe.data_supplied_notification.signal(());
                    }
                }

                rx_pipe.data_consumed_notification.wait().await;
            }
        });

        let mut run =
            pin!(async move { runner.run(tx_pipe, rx_pipe, dev_comm, node, handler).await });

        select3(&mut tx, &mut rx, &mut run).await.unwrap()
    });

    let mut mdns_run = pin!(async move {
        type MdnsTxBuf = MaybeUninit<[u8; MAX_TX_BUF_SIZE]>;
        type MdnsRxBuf = MaybeUninit<[u8; MAX_RX_BUF_SIZE]>;

        let mut tx_buf = MdnsTxBuf::uninit();
        let mut rx_buf = MdnsRxBuf::uninit();

        let tx_buf = &mut tx_buf;
        let rx_buf = &mut rx_buf;

        let tx_pipe = Pipe::new(unsafe { tx_buf.assume_init_mut() });
        let rx_pipe = Pipe::new(unsafe { rx_buf.assume_init_mut() });

        let tx_pipe = &tx_pipe;
        let rx_pipe = &rx_pipe;

        let udp = &dnssd_udp_socket;

        let mut tx = pin!(async move {
            loop {
                {
                    let mut data = tx_pipe.data.lock().await;

                    if let Some(chunk) = data.chunk {
                        let remote_endpoint = match chunk.addr.unwrap_udp().ip() {
                            no_std_net::IpAddr::V4(v4) => IpEndpoint::new(
                                smoltcp::wire::IpAddress::Ipv4(Ipv4Address::from_bytes(
                                    &v4.octets(),
                                )),
                                chunk.addr.unwrap_udp().port(),
                            ),
                            no_std_net::IpAddr::V6(v6) => IpEndpoint::new(
                                smoltcp::wire::IpAddress::Ipv6(Ipv6Address::from_bytes(
                                    &v6.octets(),
                                )),
                                chunk.addr.unwrap_udp().port(),
                            ),
                        };

                        udp.send_to(&data.buf[chunk.start..chunk.end], remote_endpoint)
                            .await
                            .unwrap();

                        data.chunk = None;
                        tx_pipe.data_consumed_notification.signal(());
                    }
                }

                tx_pipe.data_supplied_notification.wait().await;
            }
        });

        let mut rx = pin!(async move {
            loop {
                {
                    let mut data = rx_pipe.data.lock().await;

                    if data.chunk.is_none() {
                        let (len, addr) = matter_udp_socket.recv_from(&mut data.buf).await.unwrap();
                        let port = addr.port;

                        let addr = match addr.addr {
                            IpAddress::Ipv4(_) => {
                                let mut addr_bytes = [0u8; 4];
                                addr_bytes.copy_from_slice(addr.addr.as_bytes());
                                let ip_addr = Ipv4Addr::from(addr_bytes);
                                let addr = SocketAddr::V4(SocketAddrV4::new(ip_addr, port));
                                addr
                            }
                            IpAddress::Ipv6(_) => {
                                let mut addr_bytes = [0u8; 16];
                                addr_bytes.copy_from_slice(addr.addr.as_bytes());
                                let ip_addr = Ipv6Addr::from(addr_bytes);
                                let addr = SocketAddr::V6(SocketAddrV6::new(ip_addr, port, 0, 0));
                                addr
                            }
                        };

                        data.chunk = Some(Chunk {
                            start: 0,
                            end: len,
                            addr: Address::Udp(addr),
                        });
                        rx_pipe.data_supplied_notification.signal(());
                    }
                }

                rx_pipe.data_consumed_notification.wait().await;
            }
        });

        let mut run = pin!(async move { mdns_runner.run(tx_pipe, rx_pipe).await });

        select3(&mut tx, &mut rx, &mut run).await.unwrap()
    });

    let mut fut = pin!(async move {
        select::select(
            &mut transport_run,
            &mut mdns_run,
            //save(transport, &psm),
        )
        .await
        .unwrap()
    });

    fut.await.unwrap();

    info!("About to exit");

    loop {}
}

fn handler<'a>(matter: &'a Matter<'a>) -> impl Handler + 'a {
    root_endpoint::handler(0, matter)
        .chain(
            1,
            descriptor::ID,
            descriptor::DescriptorCluster::new(*matter.borrow()),
        )
        .chain(
            1,
            cluster_on_off::ID,
            OnOffClusterHandlerWrapper {
                wrapped: cluster_on_off::OnOffCluster::new(*matter.borrow()),
                value: RefCell::new(false),
            },
        )
}

struct OnOffClusterHandlerWrapper {
    wrapped: cluster_on_off::OnOffCluster,
    value: RefCell<bool>,
}

impl Handler for OnOffClusterHandlerWrapper {
    fn read(
        &self,
        attr: &matter::data_model::objects::AttrDetails,
        encoder: matter::data_model::objects::AttrDataEncoder,
    ) -> Result<(), matter::error::Error> {
        self.wrapped.read(attr, encoder)
    }

    fn write(
        &self,
        attr: &matter::data_model::objects::AttrDetails,
        data: matter::data_model::objects::AttrData,
    ) -> Result<(), matter::error::Error> {
        self.wrapped.write(attr, data)
    }

    fn invoke(
        &self,
        exchange: &matter::transport::exchange::Exchange,
        cmd: &matter::data_model::objects::CmdDetails,
        data: &matter::tlv::TLVElement,
        encoder: matter::data_model::objects::CmdDataEncoder,
    ) -> Result<(), matter::error::Error> {
        match cmd.cmd_id.try_into()? {
            cluster_on_off::Commands::Off => {
                *self.value.borrow_mut() = false;
            }
            cluster_on_off::Commands::On => {
                *self.value.borrow_mut() = true;
            }
            cluster_on_off::Commands::Toggle => {
                let mut value = self.value.borrow_mut();
                *value = !*value;
            }
        }

        let state = *self.value.borrow();
        critical_section::with(|cs| {
            let mut led = LED.borrow_ref_mut(cs);
            let led = (*led).borrow_mut().as_mut().unwrap();
            match state {
                true => led.set_high().unwrap(),
                false => led.set_low().unwrap(),
            }
        });
        self.wrapped.invoke(exchange, cmd, data, encoder)
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
