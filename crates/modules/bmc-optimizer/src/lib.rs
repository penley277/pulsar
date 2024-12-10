use std::{
    fmt,
    net::{Ipv4Addr, SocketAddr},
};

use bpf_common::{
    ebpf_program, parsing::BufferIndex, program::BpfContext, BpfSender, Pid, Program,
    ProgramBuilder, ProgramError,
};
use nix::sys::socket::{SockaddrIn, SockaddrIn6};
use bpf_common::aya::programs::tc;
use pulsar_core::pdk::{ConfigError, ModuleConfig};
// use crate::pulsar::Config;

const MODULE_NAME: &str = "bmc-optimizer";

pub async fn program(
    ctx: BpfContext,
    sender: impl BpfSender<NetworkEvent>,
    config: Config,
) -> Result<Program, ProgramError> {
    let attach_to_lsm = ctx.lsm_supported();
    let binary = ebpf_program!(&ctx, "probes");
    let _ = tc::qdisc_add_clsact(&*config.interface);
    let mut builder = ProgramBuilder::new(ctx, MODULE_NAME, binary)
         .tc_ingress("tc_ingress", &*config.interface);

    let mut program = builder.start().await?;
    // program
    //     .read_events("map_output_network_event", sender)
    //     .await?;
    Ok(program)
}

#[derive(Clone, Debug, Default)]
pub struct Config {
    interface: String,
}

impl TryFrom<&ModuleConfig> for Config {
    type Error = ConfigError;
    fn try_from(config: &ModuleConfig) -> Result<Self, Self::Error> {
        Ok(Config {
            interface: config.with_default("interface", "enp1s0".to_string())?.to_string(),
        })
    }
}

#[derive(Debug)]
#[repr(C)]
pub enum NetworkEvent {
    Bind {
        addr: Addr,
        proto: Proto,
    },
    Listen {
        addr: Addr,
        // TCP-only
    },
    Connect {
        dst: Addr,
        proto: Proto,
    },
    Accept {
        src: Addr,
        dst: Addr,
        // TCP-only
    },
    // NOTE: source/destination here indicate the communication side rather
    // than the source of the message.
    Send {
        src: Addr,
        dst: Addr,
        data: BufferIndex<[u8]>,
        data_len: u32,
        proto: Proto,
    },
    Receive {
        src: Addr,
        dst: Addr,
        data: BufferIndex<[u8]>,
        data_len: u32,
        proto: Proto,
    },
    Close {
        original_pid: Pid,
        src: Addr,
        dst: Addr,
        // TCP-only
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C, u8)]
pub enum Addr {
    V4(SockaddrIn),
    V6(SockaddrIn6),
}

impl From<SocketAddr> for Addr {
    fn from(value: SocketAddr) -> Self {
        match value {
            SocketAddr::V4(v) => Addr::V4(v.into()),
            SocketAddr::V6(v) => Addr::V6(v.into()),
        }
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Addr::V4(v) => write!(f, "{v}"),
            Addr::V6(v) => write!(f, "{v}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Proto {
    TCP = 0,
    UDP = 1,
}

impl fmt::Display for NetworkEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkEvent::Bind { addr, proto } => write!(f, "bind on {addr} ({proto:?})"),
            NetworkEvent::Listen { addr } => write!(f, "listen on {addr}"),
            NetworkEvent::Connect { dst, proto } => write!(f, "connect -> {dst} ({proto:?})"),
            NetworkEvent::Accept { src, dst } => write!(f, "accept {src} -> {dst}"),
            NetworkEvent::Send { data_len, .. } => write!(f, "sent {data_len} bytes"),
            NetworkEvent::Receive { data_len, .. } => write!(f, "received {data_len} bytes"),
            NetworkEvent::Close {
                src,
                dst,
                original_pid,
            } => write!(f, "close {src} -> {dst} (original pid: {original_pid})"),
        }
    }
}


pub mod pulsar {
    use super::*;
    use bpf_common::{parsing::IndexError, program::BpfEvent, BpfSenderWrapper};
    use pulsar_core::{
        event::Host,
        pdk::{IntoPayload, ModuleContext, ModuleError, Payload, SimplePulsarModule},
    };
    use pulsar_core::pdk::{ConfigError, ModuleConfig};

    pub struct BmcOptimizerModule;

    impl SimplePulsarModule for BmcOptimizerModule {
        type Config = Config;
        type State = XdpExampleStatus;

        const MODULE_NAME: &'static str = MODULE_NAME;
        const DEFAULT_ENABLED: bool = true;

        async fn init_state(
            &self,
            config: &Self::Config,
            ctx: &ModuleContext,
        ) -> Result<Self::State, ModuleError> {
            let dns_ctx: ModuleContext = ctx.clone();

            // intercept DNS
            let sender =
                BpfSenderWrapper::new(ctx.clone(), move |event: &BpfEvent<NetworkEvent>| {
                    
                });

            Ok(Self::State {
                _ebpf_program: program(ctx.get_bpf_context(), sender, config.clone()).await?,
            })
        }
    }

    pub struct XdpExampleStatus {
        _ebpf_program: Program,
    }

    impl From<Addr> for Host {
        fn from(value: Addr) -> Self {
            match value {
                Addr::V4(v) => {
                    let bits = v.ip();
                    let octects = [
                        (bits >> 24) as u8,
                        (bits >> 16) as u8,
                        (bits >> 8) as u8,
                        bits as u8,
                    ];

                    Host {
                        ip: Ipv4Addr::from(octects).into(),
                        port: v.port(),
                    }
                }

                Addr::V6(v) => Host {
                    ip: v.ip().into(),
                    port: v.port(),
                },
            }
        }
    }

    impl IntoPayload for NetworkEvent {
        type Error = IndexError;

        fn try_into_payload(data: BpfEvent<Self>) -> Result<Payload, Self::Error> {
            Ok(match data.payload {
                NetworkEvent::Bind { addr, proto } => Payload::Bind {
                    address: addr.into(),
                    is_tcp: matches!(proto, Proto::TCP),
                },
                NetworkEvent::Listen { addr } => Payload::Listen {
                    address: addr.into(),
                },
                NetworkEvent::Connect { dst, proto } => Payload::Connect {
                    destination: dst.into(),
                    is_tcp: matches!(proto, Proto::TCP),
                },
                NetworkEvent::Accept { src, dst } => Payload::Accept {
                    source: src.into(),
                    destination: dst.into(),
                },
                NetworkEvent::Send {
                    src,
                    dst,
                    data_len,
                    proto,
                    ..
                } => Payload::Send {
                    source: src.into(),
                    destination: dst.into(),
                    len: data_len as usize,
                    is_tcp: matches!(proto, Proto::TCP),
                },
                NetworkEvent::Receive {
                    src,
                    dst,
                    data_len,
                    proto,
                    ..
                } => Payload::Receive {
                    source: src.into(),
                    destination: dst.into(),
                    len: data_len as usize,
                    is_tcp: matches!(proto, Proto::TCP),
                },
                NetworkEvent::Close {
                    src,
                    dst,
                    original_pid: _,
                } => Payload::Close {
                    source: src.into(),
                    destination: dst.into(),
                },
            })
        }
    }

}
