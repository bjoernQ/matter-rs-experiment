use core::cell::RefCell;

use matter::data_model::cluster_basic_information::BasicInfoConfig;
use matter::error::{Error, ErrorCode};

use matter::mdns::{
    proto::{Host, Services},
    Service, ServiceMode,
};

pub struct Mdns<'a> {
    host: Host<'a>,
    dev_det: &'a BasicInfoConfig<'a>,
    matter_port: u16,
    services: RefCell<heapless::Vec<(heapless::String<40>, ServiceMode), 4>>,
}

impl<'a> Mdns<'a> {
    #[inline(always)]
    pub const fn new(
        id: u16,
        hostname: &'a str,
        ip: [u8; 4],
        ipv6: Option<[u8; 16]>,
        dev_det: &'a BasicInfoConfig<'a>,
        matter_port: u16,
    ) -> Self {
        Self {
            host: Host {
                id,
                hostname,
                ip,
                ipv6,
            },
            dev_det,
            matter_port,
            services: RefCell::new(heapless::Vec::new()),
        }
    }

    pub fn add(&self, service: &str, mode: ServiceMode) -> Result<(), Error> {
        let mut services = self.services.borrow_mut();

        services.retain(|(name, _)| name != service);
        services
            .push((service.into(), mode))
            .map_err(|_| ErrorCode::NoSpace)?;
        Ok(())
    }

    pub fn remove(&self, service: &str) -> Result<(), Error> {
        let mut services = self.services.borrow_mut();

        services.retain(|(name, _)| name != service);

        Ok(())
    }

    pub fn for_each<F>(&self, mut callback: F) -> Result<(), Error>
    where
        F: FnMut(&Service) -> Result<(), Error>,
    {
        let services = self.services.borrow();

        for (service, mode) in &*services {
            mode.service(self.dev_det, self.matter_port, service, |service| {
                callback(service)
            })?;
        }

        Ok(())
    }
}

impl<'a> matter::mdns::Mdns for Mdns<'a> {
    fn add(&self, service: &str, mode: ServiceMode) -> Result<(), Error> {
        Mdns::add(self, service, mode)
    }

    fn remove(&self, service: &str) -> Result<(), Error> {
        Mdns::remove(self, service)
    }
}

impl<'a> Services for Mdns<'a> {
    type Error = matter::error::Error;

    fn for_each<F>(&self, callback: F) -> Result<(), Error>
    where
        F: FnMut(&Service) -> Result<(), Error>,
    {
        Mdns::for_each(self, callback)
    }
}

impl<'a> Mdns<'a> {
    pub fn generate_broadcast(&self, buffer: &mut [u8]) -> usize {
        self.host.broadcast(&self, buffer, 60).unwrap()
    }

    pub fn generate_response(&self, data: &[u8], buffer: &mut [u8]) -> usize {
        self.host.respond(&self, data, buffer, 60).unwrap()
    }
}
