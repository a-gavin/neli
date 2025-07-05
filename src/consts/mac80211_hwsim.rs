use neli_proc_macros::neli_enum;

use crate::{self as neli};

/// Supported commands for the Linux `mac80211_hwsim` generic netlink (genl) driver
#[neli_enum(serialized_type = "u8")]
pub enum Mac80211HwsimCmd {
    /// Unspecified command to catch errors
    Unspec = libc::HWSIM_CMD_UNSPEC as u8,
    /// Request to register and received all broadcasted frames by any `mac80211_hwsim` radio device.
    Register = libc::HWSIM_CMD_REGISTER as u8,
    /// Send/receive a broadcasted frame from/to kernel/user space, uses:
    /// * [`Mac80211HwsimAttr::AddrTransmitter`]
    /// * [`Mac80211HwsimAttr::AddrReceiver`]
    /// * [`Mac80211HwsimAttr::Frame`]
    /// * [`Mac80211HwsimAttr::Flags`]
    /// * [`Mac80211HwsimAttr::RxRate`]
    /// * [`Mac80211HwsimAttr::Signal`]
    /// * [`Mac80211HwsimAttr::Cookie`]
    /// * [`Mac80211HwsimAttr::Freq`] (optional)
    Frame = libc::HWSIM_CMD_FRAME as u8,
    /// Transmission info report from user space to kernel, uses:
    /// * [`Mac80211HwsimAttr::AddrTransmitter`]
    /// * [`Mac80211HwsimAttr::Flags`]
    /// * [`Mac80211HwsimAttr::TxInfo`]
    /// * [`Mac80211HwsimAttr::TxInfoFlags`]
    /// * [`Mac80211HwsimAttr::Signal`]
    /// * [`Mac80211HwsimAttr::Cookie`]
    TxInfoFrame = libc::HWSIM_CMD_TX_INFO_FRAME as u8,
    /// Create a new radio with the given parameters, returns the radio ID (>= 0) or negative
    /// on errors, if successful then multicast the result, uses optional parameter:
    /// * [`Mac80211HwsimAttr::RegStrictReg`]
    /// * [`Mac80211HwsimAttr::SupportP2pDevice`]
    /// * [`Mac80211HwsimAttr::DestroyRadioOnClose`]
    /// * [`Mac80211HwsimAttr::Channels`]
    /// * [`Mac80211HwsimAttr::NoVif`]
    /// * [`Mac80211HwsimAttr::RadioName`]
    /// * [`Mac80211HwsimAttr::UseChanctx`]
    /// * [`Mac80211HwsimAttr::RegHintAlpha2`]
    /// * [`Mac80211HwsimAttr::RegCustomReg`]
    /// * [`Mac80211HwsimAttr::PermAddr`]
    NewRadio = libc::HWSIM_CMD_NEW_RADIO as u8,
    /// Destroy a radio, reply is multicasted
    DelRadio = libc::HWSIM_CMD_DEL_RADIO as u8,
    /// Fetch information about existing radios, uses: [`Mac80211HwsimAttr::RadioId`]
    GetRadio = libc::HWSIM_CMD_GET_RADIO as u8,
    /// Add a receive MAC address (given in the [`Mac80211HwsimAttr::AddrReceiver`] attribute)
    /// to a device identified by [`Mac80211HwsimAttr::AddrTransmitter`]. This lets wmediumd forward
    /// frames to this receiver address for a given station.
    AddMacAddr = libc::HWSIM_CMD_ADD_MAC_ADDR as u8,
    /// Remove the MAC address again, the attributes are the same as to [`Mac80211HwsimCmd::AddMacAddr`].
    DelMacAddr = libc::HWSIM_CMD_DEL_MAC_ADDR as u8,
    /// Request to start peer measurement with the [`Mac80211HwsimAttr::PmsrRequest`].
    /// Result will be sent back asynchronously with [`Mac80211HwsimCmd::ReportPmsr`].
    StartPmsr = libc::HWSIM_CMD_START_PMSR as u8,
    /// Abort previously started peer measurement.
    AbortPmsr = libc::HWSIM_CMD_ABORT_PMSR as u8,
    /// Report peer measurement data.
    ReportPmsr = libc::HWSIM_CMD_REPORT_PMSR as u8,
}
impl neli::consts::genl::Cmd for Mac80211HwsimCmd {}

/// Supported attributes for the Linux `mac80211_hwsim` generic netlink (genl) driver
#[neli_enum(serialized_type = "u16")]
pub enum Mac80211HwsimAttr {
    /// Unspecified attribute to catch errors
    Unspec = libc::HWSIM_ATTR_UNSPEC as u16,
    /// MAC address of the radio device that the frame is broadcasted to
    AddrReceiver = libc::HWSIM_ATTR_ADDR_RECEIVER as u16,
    /// MAC address of the radio device that the frame was broadcasted from
    AddrTransmitter = libc::HWSIM_ATTR_ADDR_TRANSMITTER as u16,
    /// Data array
    Frame = libc::HWSIM_ATTR_FRAME as u16,
    /// `mac80211` transmission flags, used to process properly the frame at user space
    Flags = libc::HWSIM_ATTR_FLAGS as u16,
    /// Estimated rx rate index for this frame at user space
    RxRate = libc::HWSIM_ATTR_RX_RATE as u16,
    /// Estimated RX signal for this frame at user space
    Signal = libc::HWSIM_ATTR_SIGNAL as u16,
    /// `ieee80211_tx_rate` array
    TxInfo = libc::HWSIM_ATTR_TX_INFO as u16,
    /// `sk_buff` cookie to identify the frame
    Cookie = libc::HWSIM_ATTR_COOKIE as u16,
    /// `u32` attribute used with the [`Mac80211HwsimCmd::NewRadio`] command giving the
    /// number of channels supported by the new radio
    Channels = libc::HWSIM_ATTR_CHANNELS as u16,
    /// `u32` attribute used with [`Mac80211HwsimCmd::DelRadio`] only to destroy a radio
    RadioId = libc::HWSIM_ATTR_RADIO_ID as u16,
    /// Alpha2 for regulatory driver hint (nla string, length 2)
    RegHintAlpha2 = libc::HWSIM_ATTR_REG_HINT_ALPHA2 as u16,
    /// Custom regulatory domain index (`u32` attribute)
    RegCustomReg = libc::HWSIM_ATTR_REG_CUSTOM_REG as u16,
    /// Request REGULATORY_STRICT_REG (flag attribute)
    RegStrictReg = libc::HWSIM_ATTR_REG_STRICT_REG as u16,
    /// Support P2P Device virtual interface (flag)
    SupportP2pDevice = libc::HWSIM_ATTR_SUPPORT_P2P_DEVICE as u16,
    /// Used with the [`Mac80211HwsimCmd::NewRadio`] command to force use of channel contexts even
    /// when only a single channel is supported
    UseChanctx = libc::HWSIM_ATTR_USE_CHANCTX as u16,
    /// Used with the [`Mac80211HwsimCmd::NewRadio`] command to force radio removal when process that
    /// created the radio dies
    DestroyRadioOnClose = libc::HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE as u16,
    /// Name of radio, e.g. phy666
    RadioName = libc::HWSIM_ATTR_RADIO_NAME as u16,
    /// Do not create vif (wlanX) when creating radio
    NoVif = libc::HWSIM_ATTR_NO_VIF as u16,
    /// Frequency at which packet is transmitted or received
    Freq = libc::HWSIM_ATTR_FREQ as u16,
    /// Padding attribute for 64-bit values, ignore
    Pad = libc::HWSIM_ATTR_PAD as u16,
    /// Additional flags for corresponding rates of [`Mac80211HwsimAttr::TxInfo`]
    TxInfoFlags = libc::HWSIM_ATTR_TX_INFO_FLAGS as u16,
    /// Permanent mac address of new radio
    PermAddr = libc::HWSIM_ATTR_PERM_ADDR as u16,
    /// `u32` attribute of supported interface types bits
    IftypeSupport = libc::HWSIM_ATTR_IFTYPE_SUPPORT as u16,
    /// `u32` array of supported cipher types
    CipherSupport = libc::HWSIM_ATTR_CIPHER_SUPPORT as u16,
    /// Claim MLO support (exact parameters TBD) for the new radio
    MloSupport = libc::HWSIM_ATTR_MLO_SUPPORT as u16,
    /// Nested attribute used with [`Mac80211HwsimCmd::NewRadio`] to provide peer measurement
    /// capabilities (`nl80211_peer_measurement_attrs`)
    PmsrSupport = libc::HWSIM_ATTR_PMSR_SUPPORT as u16,
    /// Nested attribute used with  [`Mac80211HwsimCmd::StartPmsr`] to provide details about peer
    /// measurement request (`nl80211_peer_measurement_attrs`)
    PmsrRequest = libc::HWSIM_ATTR_PMSR_REQUEST as u16,
    /// Nested attributed used with [`Mac80211HwsimCmd::ReportPmsr`]  to provide peer measurement
    /// result (`nl80211_peer_measurement_attrs`)
    PmsrResult = libc::HWSIM_ATTR_PMSR_RESULT as u16,
    /// Register multiple wiphy radios (flag). Adds one radio for each band. Number of supported
    /// channels will be set for each radio instead of for the wiphy.
    MultiRadio = libc::HWSIM_ATTR_MULTI_RADIO as u16,
}
impl neli::consts::genl::NlAttrType for Mac80211HwsimAttr {}
