use neli_proc_macros::neli_enum;

use crate as neli;

/// Internet address families
#[neli_enum(serialized_type = "libc::c_uchar")]
pub enum Af {
    Inet = libc::AF_INET as libc::c_uchar,
    Inet6 = libc::AF_INET6 as libc::c_uchar,
}

/// General address families for sockets
#[neli_enum(serialized_type = "u8")]
pub enum RtAddrFamily {
    Unspecified = libc::AF_UNSPEC as u8,
    UnixOrLocal = libc::AF_UNIX as u8,
    Inet = libc::AF_INET as u8,
    Inet6 = libc::AF_INET6 as u8,
    Ipx = libc::AF_IPX as u8,
    Netlink = libc::AF_NETLINK as u8,
    X25 = libc::AF_X25 as u8,
    Ax25 = libc::AF_AX25 as u8,
    Atmpvc = libc::AF_ATMPVC as u8,
    Appletalk = libc::AF_APPLETALK as u8,
    Packet = libc::AF_PACKET as u8,
    Alg = libc::AF_ALG as u8,
}

/// `rtm_type`
/// The results of a lookup from a route table
#[neli_enum(serialized_type = "libc::c_uchar")]
pub enum Rtn {
    Unspec = libc::RTN_UNSPEC,
    Unicast = libc::RTN_UNICAST,
    Local = libc::RTN_LOCAL,
    Broadcast = libc::RTN_BROADCAST,
    Anycast = libc::RTN_ANYCAST,
    Multicast = libc::RTN_MULTICAST,
    Blackhole = libc::RTN_BLACKHOLE,
    Unreachable = libc::RTN_UNREACHABLE,
    Prohibit = libc::RTN_PROHIBIT,
    Throw = libc::RTN_THROW,
    Nat = libc::RTN_NAT,
    Xresolve = libc::RTN_XRESOLVE,
}

/// `rtm_protocol`
/// The origins of routes that are defined in the kernel
#[neli_enum(serialized_type = "libc::c_uchar")]
pub enum Rtprot {
    Unspec = libc::RTPROT_UNSPEC,
    Redirect = libc::RTPROT_REDIRECT,
    Kernel = libc::RTPROT_KERNEL,
    Boot = libc::RTPROT_BOOT,
    Static = libc::RTPROT_STATIC,
}

/// `rtm_scope`
/// The distance between destinations
#[neli_enum(serialized_type = "libc::c_uchar")]
pub enum RtScope {
    Universe = libc::RT_SCOPE_UNIVERSE,
    Site = libc::RT_SCOPE_SITE,
    Link = libc::RT_SCOPE_LINK,
    Host = libc::RT_SCOPE_HOST,
    Nowhere = libc::RT_SCOPE_NOWHERE,
}

/// `rt_class_t`
/// Reserved route table identifiers
#[neli_enum(serialized_type = "libc::c_uchar")]
pub enum RtTable {
    Unspec = libc::RT_TABLE_UNSPEC,
    Compat = libc::RT_TABLE_COMPAT,
    Default = libc::RT_TABLE_DEFAULT,
    Main = libc::RT_TABLE_MAIN,
    Local = libc::RT_TABLE_LOCAL,
}

impl_trait!(
    /// Marker trait for [`Rtattr`][crate::rtnl::Rtattr] field,
    /// `rta_type`.
    pub RtaType,
    libc::c_ushort,
    /// Wrapper that is usable for all values in
    /// [`Rtattr`][crate::rtnl::Rtattr] field, `rta_type`
    pub RtaTypeWrapper,
    Ifla,
    Ifa,
    Rta,
    Tca,
    Nda,
    IflaInfo,
    IflaVlan,
    IflaVlanQos,
);

/// Enum usable with [`Rtattr`][crate::rtnl::Rtattr] field,
/// `rta_type`.
/// Values are interface information message attributes. Used with
/// [`Ifinfomsg`][crate::rtnl::Ifinfomsg].
#[neli_enum(serialized_type = "libc::c_ushort")]
pub enum Ifla {
    Unspec = libc::IFLA_UNSPEC,
    Address = libc::IFLA_ADDRESS,
    Broadcast = libc::IFLA_BROADCAST,
    Ifname = libc::IFLA_IFNAME,
    Mtu = libc::IFLA_MTU,
    Link = libc::IFLA_LINK,
    Qdisc = libc::IFLA_QDISC,
    Stats = libc::IFLA_STATS,
    Cost = libc::IFLA_COST,
    Priority = libc::IFLA_PRIORITY,
    Master = libc::IFLA_MASTER,
    Wireless = libc::IFLA_WIRELESS,
    Protinfo = libc::IFLA_PROTINFO,
    Txqlen = libc::IFLA_TXQLEN,
    Map = libc::IFLA_MAP,
    Weight = libc::IFLA_WEIGHT,
    Operstate = libc::IFLA_OPERSTATE,
    Linkmode = libc::IFLA_LINKMODE,
    Linkinfo = libc::IFLA_LINKINFO,
    NetNsPid = libc::IFLA_NET_NS_PID,
    Ifalias = libc::IFLA_IFALIAS,
    NumVf = libc::IFLA_NUM_VF,
    VfinfoList = libc::IFLA_VFINFO_LIST,
    Stats64 = libc::IFLA_STATS64,
    VfPorts = libc::IFLA_VF_PORTS,
    PortSelf = libc::IFLA_PORT_SELF,
    AfSpec = libc::IFLA_AF_SPEC,
    Group = libc::IFLA_GROUP,
    NetNsFd = libc::IFLA_NET_NS_FD,
    ExtMask = libc::IFLA_EXT_MASK,
    Promiscuity = libc::IFLA_PROMISCUITY,
    NumTxQueues = libc::IFLA_NUM_TX_QUEUES,
    NumRxQueues = libc::IFLA_NUM_RX_QUEUES,
    Carrier = libc::IFLA_CARRIER,
    PhysPortId = libc::IFLA_PHYS_PORT_ID,
    CarrierChanges = libc::IFLA_CARRIER_CHANGES,
    PhysSwitchId = libc::IFLA_PHYS_SWITCH_ID,
    LinkNetnsid = libc::IFLA_LINK_NETNSID,
    PhysPortName = libc::IFLA_PHYS_PORT_NAME,
    ProtoDown = libc::IFLA_PROTO_DOWN,
    GsoMaxSegs = libc::IFLA_GSO_MAX_SEGS,
    GsoMaxSize = libc::IFLA_GSO_MAX_SIZE,
    Pad = libc::IFLA_PAD,
    Xdp = libc::IFLA_XDP,
    Event = libc::IFLA_EVENT,
    NewNetnsid = libc::IFLA_NEW_NETNSID,
    IfNetnsid = libc::IFLA_IF_NETNSID,
    CarrierUpCount = libc::IFLA_CARRIER_UP_COUNT,
    CarrierDownCount = libc::IFLA_CARRIER_DOWN_COUNT,
    NewIfindex = libc::IFLA_NEW_IFINDEX,
    MinMtu = libc::IFLA_MIN_MTU,
    MaxMtu = libc::IFLA_MAX_MTU,
    PropList = libc::IFLA_PROP_LIST,
    AltIfname = libc::IFLA_ALT_IFNAME,
    PermAddress = libc::IFLA_PERM_ADDRESS,
    ProtoDownReason = libc::IFLA_PROTO_DOWN_REASON,
}

/// Enum usable with [`Rtattr`][crate::rtnl::Rtattr] field,
/// `rta_type`.
/// Values are nested attributes to IFLA_LINKMODE.
#[neli_enum(serialized_type = "libc::c_ushort")]
pub enum IflaInfo {
    Unspec = libc::IFLA_INFO_UNSPEC,
    Kind = libc::IFLA_INFO_KIND,
    Data = libc::IFLA_INFO_DATA,
    Xstats = libc::IFLA_INFO_XSTATS,
    SlaveKind = libc::IFLA_INFO_SLAVE_KIND,
    SlaveData = libc::IFLA_INFO_SLAVE_DATA,
}

/// Enum usable with [`Rtattr`][crate::rtnl::Rtattr] field,
/// `rta_type`.
/// Values are interface information message attributes. Used with
/// [`Ifinfomsg`][crate::rtnl::Ifinfomsg].
#[neli_enum(serialized_type = "libc::c_ushort")]
pub enum IflaVlan {
    Unspec = 0,
    Id = 1,
    Flags = 2,
    EgressQos = 3,
    IngressQos = 4,
    Protocol = 5,
}

/// Enum usable with [`Rtattr`][crate::rtnl::Rtattr] field,
/// `rta_type`.
/// Values are interface information message attributes. Used with
/// [`Ifinfomsg`][crate::rtnl::Ifinfomsg].
#[neli_enum(serialized_type = "libc::c_ushort")]
pub enum IflaVlanQos {
    Unspec = 0,
    Mapping = 1,
}

/// rtnetlink-related values for `nl_type` in
/// [`Nlmsghdr`][crate::nl::Nlmsghdr].
#[neli_enum(serialized_type = "u16")]
#[allow(missing_docs)]
pub enum Rtm {
    Newlink = libc::RTM_NEWLINK,
    Dellink = libc::RTM_DELLINK,
    Getlink = libc::RTM_GETLINK,
    Setlink = libc::RTM_SETLINK,
    Newaddr = libc::RTM_NEWADDR,
    Deladdr = libc::RTM_DELADDR,
    Getaddr = libc::RTM_GETADDR,
    Newroute = libc::RTM_NEWROUTE,
    Delroute = libc::RTM_DELROUTE,
    Getroute = libc::RTM_GETROUTE,
    Newneigh = libc::RTM_NEWNEIGH,
    Delneigh = libc::RTM_DELNEIGH,
    Getneigh = libc::RTM_GETNEIGH,
    Newrule = libc::RTM_NEWRULE,
    Delrule = libc::RTM_DELRULE,
    Getrule = libc::RTM_GETRULE,
    Newqdisc = libc::RTM_NEWQDISC,
    Delqdisc = libc::RTM_DELQDISC,
    Getqdisc = libc::RTM_GETQDISC,
    Newtclass = libc::RTM_NEWTCLASS,
    Deltclass = libc::RTM_DELTCLASS,
    Gettclass = libc::RTM_GETTCLASS,
    Newtfilter = libc::RTM_NEWTFILTER,
    Deltfilter = libc::RTM_DELTFILTER,
    Gettfilter = libc::RTM_GETTFILTER,
    Newaction = libc::RTM_NEWACTION,
    Delaction = libc::RTM_DELACTION,
    Getaction = libc::RTM_GETACTION,
    Newprefix = libc::RTM_NEWPREFIX,
    Getmulticast = libc::RTM_GETMULTICAST,
    Getanycast = libc::RTM_GETANYCAST,
    Newneightbl = libc::RTM_NEWNEIGHTBL,
    Getneightbl = libc::RTM_GETNEIGHTBL,
    Setneightbl = libc::RTM_SETNEIGHTBL,
    Newnduseropt = libc::RTM_NEWNDUSEROPT,
    Newaddrlabel = libc::RTM_NEWADDRLABEL,
    Deladdrlabel = libc::RTM_DELADDRLABEL,
    Getaddrlabel = libc::RTM_GETADDRLABEL,
    Getdcb = libc::RTM_GETDCB,
    Setdcb = libc::RTM_SETDCB,
    Newnetconf = libc::RTM_NEWNETCONF,
    Getnetconf = libc::RTM_GETNETCONF,
    Newmdb = libc::RTM_NEWMDB,
    Delmdb = libc::RTM_DELMDB,
    Getmdb = libc::RTM_GETMDB,
    Newnsid = libc::RTM_NEWNSID,
    Delnsid = libc::RTM_DELNSID,
    Getnsid = libc::RTM_GETNSID,
}

/// Enum usable with [`Rtattr`][crate::rtnl::Rtattr] field,
/// `rta_type`.
/// Values are routing message attributes. Used with
/// [`Rtmsg`][crate::rtnl::Rtmsg].
#[neli_enum(serialized_type = "libc::c_ushort")]
pub enum Rta {
    Unspec = libc::RTA_UNSPEC,
    Dst = libc::RTA_DST,
    Src = libc::RTA_SRC,
    Iif = libc::RTA_IIF,
    Oif = libc::RTA_OIF,
    Gateway = libc::RTA_GATEWAY,
    Priority = libc::RTA_PRIORITY,
    Prefsrc = libc::RTA_PREFSRC,
    Metrics = libc::RTA_METRICS,
    Multipath = libc::RTA_MULTIPATH,
    Protoinfo = libc::RTA_PROTOINFO, // no longer used in Linux
    Flow = libc::RTA_FLOW,
    Cacheinfo = libc::RTA_CACHEINFO,
    Session = libc::RTA_SESSION, // no longer used in Linux
    MpAlgo = libc::RTA_MP_ALGO,  // no longer used in Linux
    Table = libc::RTA_TABLE,
    Mark = libc::RTA_MARK,
    MfcStats = libc::RTA_MFC_STATS,
    #[cfg(target_env = "gnu")]
    Via = libc::RTA_VIA,
    #[cfg(target_env = "gnu")]
    Newdst = libc::RTA_NEWDST,
    #[cfg(target_env = "gnu")]
    Pref = libc::RTA_PREF,
    #[cfg(target_env = "gnu")]
    EncapType = libc::RTA_ENCAP_TYPE,
    #[cfg(target_env = "gnu")]
    Encap = libc::RTA_ENCAP,
    #[cfg(target_env = "gnu")]
    Expires = libc::RTA_EXPIRES,
    #[cfg(target_env = "gnu")]
    Pad = libc::RTA_PAD,
    #[cfg(target_env = "gnu")]
    Uid = libc::RTA_UID,
    #[cfg(target_env = "gnu")]
    TtlPropagate = libc::RTA_TTL_PROPAGATE,
}

/// Enum usable with [`Rtattr`][crate::rtnl::Rtattr] field,
/// `rta_type`.
/// Values specify queuing discipline attributes. Used with
/// [`Tcmsg`][crate::rtnl::Tcmsg].
#[neli_enum(serialized_type = "libc::c_ushort")]
pub enum Tca {
    Unspec = libc::TCA_UNSPEC,
    Kind = libc::TCA_KIND,
    Options = libc::TCA_OPTIONS,
    Stats = libc::TCA_STATS,
    Xstats = libc::TCA_XSTATS,
    Rate = libc::TCA_RATE,
    Fcnt = libc::TCA_FCNT,
    Stats2 = libc::TCA_STATS2,
    Stab = libc::TCA_STAB,
}

/// Enum usable with [`Rtattr`][crate::rtnl::Rtattr] field,
/// `rta_type`.
/// Values specify neighbor table attributes
#[neli_enum(serialized_type = "libc::c_ushort")]
pub enum Nda {
    Unspec = libc::NDA_UNSPEC,
    Dst = libc::NDA_DST,
    Lladdr = libc::NDA_LLADDR,
    Cacheinfo = libc::NDA_CACHEINFO,
    Probes = libc::NDA_PROBES,
    Vlan = libc::NDA_VLAN,
    Port = libc::NDA_PORT,
    Vni = libc::NDA_VNI,
    Ifindex = libc::NDA_IFINDEX,
    #[cfg(target_env = "gnu")]
    Master = libc::NDA_MASTER,
    #[cfg(target_env = "gnu")]
    LinkNetnsid = libc::NDA_LINK_NETNSID,
    #[cfg(target_env = "gnu")]
    SrcVni = libc::NDA_SRC_VNI,
}

/// Interface types
#[neli_enum(serialized_type = "libc::c_ushort")]
pub enum Arphrd {
    Netrom = libc::ARPHRD_NETROM,
    Ether = libc::ARPHRD_ETHER,
    Eether = libc::ARPHRD_EETHER,
    AX25 = libc::ARPHRD_AX25,
    Pronet = libc::ARPHRD_PRONET,
    Chaos = libc::ARPHRD_CHAOS,
    Ieee802 = libc::ARPHRD_IEEE802,
    Arcnet = libc::ARPHRD_ARCNET,
    Appletlk = libc::ARPHRD_APPLETLK,
    Dlci = libc::ARPHRD_DLCI,
    Atm = libc::ARPHRD_APPLETLK,
    Metricom = libc::ARPHRD_METRICOM,
    Ieee1394 = libc::ARPHRD_IEEE1394,
    Eui64 = libc::ARPHRD_EUI64,
    Infiniband = libc::ARPHRD_INFINIBAND,

    Loopback = libc::ARPHRD_LOOPBACK,

    // Possibly more types here - need to look into ARP more
    Void = libc::ARPHRD_VOID,
    None = libc::ARPHRD_NONE,
}

/// Enum usable with [`Rtattr`][crate::rtnl::Rtattr] field,
/// `rta_type`.
/// Values are interface address message attributes. Used with
/// [`Ifaddrmsg`][crate::rtnl::Ifaddrmsg].
#[allow(missing_docs)]
#[neli_enum(serialized_type = "u16")]
pub enum Ifa {
    Unspec = libc::IFA_UNSPEC,
    Address = libc::IFA_ADDRESS,
    Local = libc::IFA_LOCAL,
    Label = libc::IFA_LABEL,
    Broadcast = libc::IFA_BROADCAST,
    Anycast = libc::IFA_ANYCAST,
    Cacheinfo = libc::IFA_CACHEINFO,
    Multicast = libc::IFA_MULTICAST,
    #[cfg(target_env = "gnu")]
    Flags = libc::IFA_FLAGS,
}

impl_flags!(
    /// Values for `ifi_flags` in
    /// [`Ifinfomsg`][crate::rtnl::Ifinfomsg].
    pub Iff: libc::c_uint {
        UP = libc::IFF_UP as libc::c_uint,
        BROADCAST = libc::IFF_BROADCAST as libc::c_uint,
        DEBUG = libc::IFF_DEBUG as libc::c_uint,
        LOOPBACK = libc::IFF_LOOPBACK as libc::c_uint,
        POINTOPOINT = libc::IFF_POINTOPOINT as libc::c_uint,
        RUNNING = libc::IFF_RUNNING as libc::c_uint,
        NOARP = libc::IFF_NOARP as libc::c_uint,
        PROMISC = libc::IFF_PROMISC as libc::c_uint,
        NOTRAILERS = libc::IFF_NOTRAILERS as libc::c_uint,
        ALLMULTI = libc::IFF_ALLMULTI as libc::c_uint,
        MASTER = libc::IFF_MASTER as libc::c_uint,
        SLAVE = libc::IFF_SLAVE as libc::c_uint,
        MULTICAST = libc::IFF_MULTICAST as libc::c_uint,
        PORTSEL = libc::IFF_PORTSEL as libc::c_uint,
        AUTOMEDIA = libc::IFF_AUTOMEDIA as libc::c_uint,
        DYNAMIC = libc::IFF_DYNAMIC as libc::c_uint,
        LOWERUP = libc::IFF_LOWER_UP as libc::c_uint,
        DORMANT = libc::IFF_DORMANT as libc::c_uint,
        ECHO = libc::IFF_ECHO as libc::c_uint,
        // Possibly more types here - need to look into private flags for interfaces
    }
);

impl_flags!(
    /// Interface address flags
    pub IfaF: u8 {
        SECONDARY = libc::IFA_F_SECONDARY as u8,
        TEMPORARY = libc::IFA_F_TEMPORARY as u8,
        NODAD = libc::IFA_F_NODAD as u8,
        OPTIMISTIC = libc::IFA_F_OPTIMISTIC as u8,
        DADFAILED = libc::IFA_F_DADFAILED as u8,
        HOMEADDRESS = libc::IFA_F_HOMEADDRESS as u8,
        DEPRECATED = libc::IFA_F_DEPRECATED as u8,
        TENTATIVE = libc::IFA_F_TENTATIVE as u8,
        PERMANENT = libc::IFA_F_PERMANENT as u8,
    }
);

impl_flags!(
    /// `rtm_flags`
    /// Flags for rtnetlink messages
    pub RtmF: libc::c_uint {
        NOTIFY = libc::RTM_F_NOTIFY,
        CLONED = libc::RTM_F_CLONED,
        EQUALIZE = libc::RTM_F_EQUALIZE,
        PREFIX = libc::RTM_F_PREFIX,

        #[cfg(target_env = "gnu")]
        LOOKUPTABLE = libc::RTM_F_LOOKUP_TABLE,
        #[cfg(target_env = "gnu")]
        FIBMATCH = libc::RTM_F_FIB_MATCH,
    }
);

impl_flags!(
    /// Arp neighbor cache entry states
    #[allow(missing_docs)]
    pub Nud: u16 {
        NONE = libc::NUD_NONE,
        INCOMPLETE = libc::NUD_INCOMPLETE,
        REACHABLE = libc::NUD_REACHABLE,
        STALE = libc::NUD_STALE,
        DELAY = libc::NUD_DELAY,
        PROBE = libc::NUD_PROBE,
        FAILED = libc::NUD_FAILED,
        NOARP = libc::NUD_NOARP,
        PERMANENT = libc::NUD_PERMANENT,
    }
);

impl_flags!(
    /// Arp neighbor cache entry flags
    #[allow(missing_docs)]
    pub Ntf: u8 {
        USE = libc::NTF_USE,
        SELF = libc::NTF_SELF,
        MASTER = libc::NTF_MASTER,
        PROXY = libc::NTF_PROXY,
        #[cfg(target_env = "gnu")]
        EXT_LEARNED = libc::NTF_EXT_LEARNED,
        #[cfg(target_env = "gnu")]
        OFFLOADED = libc::NTF_OFFLOADED,
        ROUTER = libc::NTF_ROUTER,
    }
);

impl_flags!(
    /// Vlan flags
    #[allow(missing_docs)]
    pub VlanFlags: u8 {
        REORDER_HDR = 0x1,
        GVRP = 0x2,
        LOOSE_BINDING = 0x4,
        MVRP = 0x8,
        BRIDGE_BINDING = 0x10,
    }
);
