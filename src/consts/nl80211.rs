use linux_raw_sys::netlink::*;

#[cfg(doc)]
use crate::consts::rtnl::Iff;
#[cfg(doc)]
use linux_raw_sys::netlink::{
    NL80211_MAX_NR_AKM_SUITES, NL80211_MAX_SUPP_RATES, NL80211_MAX_SUPP_SELECTORS,
    NL80211_MULTICAST_GROUP_NAN, NL80211_VENDOR_ID_IS_LINUX,
};

use crate as neli;

/// Supported `nl80211` commands (`enum nl80211_cmd`)
#[neli::neli_enum(serialized_type = "u8")]
pub enum Nl80211Command {
    /// Unspecified command to catch errors
    Unspecified = nl80211_commands::NL80211_CMD_UNSPEC as u8,
    /// Request information about a wiphy or dump request to get a list of all present wiphys.
    GetWiphy = nl80211_commands::NL80211_CMD_GET_WIPHY as u8,
    /// Set wiphy parameters, needs [`Nl80211Attr::Wiphy`] or [`Nl80211Attr::Ifindex`].
    ///
    /// Can be used to set:
    /// - [`Nl80211Attr::WiphyName`]
    /// - [`Nl80211Attr::WiphyTxqParams`]
    /// - [`Nl80211Attr::WiphyFreq`]
    /// - [`Nl80211Attr::WiphyFreqOffset`]
    /// - [`Nl80211Attr::WiphyRetryShort`]
    /// - [`Nl80211Attr::WiphyRetryLong`]
    /// - [`Nl80211Attr::WiphyFragThreshold`]
    /// - [`Nl80211Attr::WiphyRtsThreshold`]
    ///
    /// Other attributes determining channel width supported (e.g. for monitor mode). However, for setting the channel,
    /// see [`Nl80211Command::SetChannel`] instead. The support here is for backward compatibility only.
    SetWiphy = nl80211_commands::NL80211_CMD_SET_WIPHY as u8,
    /// Newly created wiphy, response to get request or rename notification.
    ///
    /// Has attributes [`Nl80211Attr::Wiphy`] and [`Nl80211Attr::WiphyName`]
    NewWiphy = nl80211_commands::NL80211_CMD_NEW_WIPHY as u8,
    /// Wiphy deleted. Has attributes [`Nl80211Attr::Wiphy`] and [`Nl80211Attr::WiphyName`].
    DelWiphy = nl80211_commands::NL80211_CMD_DEL_WIPHY as u8,
    /// Request an interface's configuration
    ///
    /// Either a dump request for all interfaces or a specific get with a single [`Nl80211Attr::Ifindex`] is supported.
    GetInterface = nl80211_commands::NL80211_CMD_GET_INTERFACE as u8,
    /// Set type of a virtual interface, requires [`Nl80211Attr::Ifindex`] and [`Nl80211Attr::Iftype`]
    SetInterface = nl80211_commands::NL80211_CMD_SET_INTERFACE as u8,
    /// Newly created virtual interface or response to [`Nl80211Command::GetInterface`].
    ///
    /// Has [`Nl80211Attr::Ifindex`], [`Nl80211Attr::Wiphy`], and [`Nl80211Attr::Iftype`]
    /// attributes.
    ///
    /// Can also be sent from user space to request creation of a new virtual interface, then requires attributes
    /// [`Nl80211Attr::Wiphy`], [`Nl80211Attr::Iftype`], and [`Nl80211Attr::Ifname`].
    NewInterface = nl80211_commands::NL80211_CMD_NEW_INTERFACE as u8,
    /// Virtual interface was deleted, has attributes [`Nl80211Attr::Ifindex`] and [`Nl80211Attr::Wiphy`].
    ///
    /// Can also be sent from user space to request deletion of a virtual interface, then requires attribute
    /// [`Nl80211Attr::Ifindex`].
    ///
    /// If multiple BSSID advertisements are enabled using [`Nl80211Attr::MbssidConfig`], [`Nl80211Attr::MbssidElems`], and
    /// if this command is used for the transmitting interface, then all the non-transmitting interfaces are deleted as well.
    DelInterface = nl80211_commands::NL80211_CMD_DEL_INTERFACE as u8,
    /// Get sequence counter information for a key specified by [`Nl80211Attr::KeyIdx`] and/or [`Nl80211Attr::Mac`].
    ///
    /// [`Nl80211Attr::Mac`] presents peer's MLD address for MLO pairwise key. For MLO group key, the link is
    /// identified by [`Nl80211Attr::MloLinkId`].
    GetKey = nl80211_commands::NL80211_CMD_GET_KEY as u8,
    /// Set key attributes [`Nl80211Attr::KeyDefault`] or [`Nl80211Attr::KeyDefaultMgmt`].
    ///
    /// For MLO connection, the link to set default key is identified by [`Nl80211Attr::MloLinkId`].
    SetKey = nl80211_commands::NL80211_CMD_SET_KEY as u8,
    /// Add a key with given [`Nl80211Attr::KeyData`], [`Nl80211Attr::KeyIdx`], [`Nl80211Attr::Mac`],
    /// [`Nl80211Attr::KeyCipher`], and [`Nl80211Attr::KeySeq`] attributes.
    ///
    /// [`Nl80211Attr::Mac`] represents peer's MLD address for MLO pairwise key. The link to add MLO group key is identified
    /// by [`Nl80211Attr::MloLinkId`].
    NewKey = nl80211_commands::NL80211_CMD_NEW_KEY as u8,
    /// Delete a key identified by [`Nl80211Attr::KeyIdx`] or [`Nl80211Attr::Mac`].
    ///
    /// [`Nl80211Attr::Mac`] represents peer's MLD address for MLO pairwise key. The link to delete group key is identified
    /// by [`Nl80211Attr::MloLinkId`].
    DelKey = nl80211_commands::NL80211_CMD_DEL_KEY as u8,
    /// (Not used)
    GetBeacon = nl80211_commands::NL80211_CMD_GET_BEACON as u8,
    /// Change the beacon on an access point interface using the [`Nl80211Attr::BeaconHead`] and [`Nl80211Attr::BeaconTail`] attributes.
    ///
    /// For drivers that generate the beacon and probe responses internally, the following attributes must be provided: [`Nl80211Attr::Ie`],
    /// [`Nl80211Attr::IeProbeResp`] and [`Nl80211Attr::IeAssocResp`].
    SetBeacon = nl80211_commands::NL80211_CMD_SET_BEACON as u8,
    /// Start AP operation on an AP interface, parameters are like for [`Nl80211Command::SetBeacon`], and additionally parameters that
    /// do not change are used.
    ///
    /// These include:
    /// - [`Nl80211Attr::BeaconInterval`]
    /// - [`Nl80211Attr::DtimPeriod`]
    /// - [`Nl80211Attr::Ssid`]
    /// - [`Nl80211Attr::HiddenSsid`]
    /// - [`Nl80211Attr::CipherSuitesPairwise`]
    /// - [`Nl80211Attr::CipherSuiteGroup`]
    /// - [`Nl80211Attr::WpaVersions`]
    /// - [`Nl80211Attr::AkmSuites`]
    /// - [`Nl80211Attr::Privacy`]
    /// - [`Nl80211Attr::AuthType`]
    /// - [`Nl80211Attr::InactivityTimeout`]
    /// - [`Nl80211Attr::AclPolicy`]
    /// - [`Nl80211Attr::MacAddrs`]
    ///
    /// The channel to use can be set on the interface or be given using the [`Nl80211Attr::WiphyFreq`],
    /// [`Nl80211Attr::WiphyFreqOffset`], and the attributes determining channel width.
    StartAp = nl80211_commands::NL80211_CMD_START_AP as u8,
    /// Old alias for [`Nl80211Command::StartAp`]
    // TODO: Deprecate?
    NewBeacon = nl80211_commands::NL80211_CMD_NEW_BEACON as u8,
    /// Stop AP operation on the given interface
    StopAp = nl80211_commands::NL80211_CMD_STOP_AP as u8,
    /// Old alias for [`Nl80211Command::StopAp`]
    // TODO: Deprecate?
    DelBeacon = nl80211_commands::NL80211_CMD_DEL_BEACON as u8,
    /// Get station attributes for station identified by [`Nl80211Attr::Mac`] on the interface identified by [`Nl80211Attr::Ifindex`]
    GetStation = nl80211_commands::NL80211_CMD_GET_STATION as u8,
    /// Set station attributes for station identified by [`Nl80211Attr::Mac`] on the interface identified by [`Nl80211Attr::Ifindex`]
    SetStation = nl80211_commands::NL80211_CMD_SET_STATION as u8,
    /// Add a station with given attributes to the interface identified by [`Nl80211Attr::Ifindex`]
    NewStation = nl80211_commands::NL80211_CMD_NEW_STATION as u8,
    /// Remove a station identified by [`Nl80211Attr::Mac`] or, if no MAC address given, all stations on the interface
    /// identified by [`Nl80211Attr::Ifindex`].
    ///
    /// For MLD station, MLD address is used in [`Nl80211Attr::Mac`].
    ///
    /// [`Nl80211Attr::MgmtSubtype`], and [`Nl80211Attr::ReasonCode`] can optionally be used to specify which type of disconnection
    /// indication should be sent to the station (Deauthentication or Disassociation frame and reason code for that frame).
    ///
    /// [`Nl80211Attr::MloLinkId`] can be used optionally to remove stations connected and using at least that link as one of its links.
    DelStation = nl80211_commands::NL80211_CMD_DEL_STATION as u8,
    /// Get mesh path attributes for mesh path to destination [`Nl80211Attr::Mac`] on the interface identified by [`Nl80211Attr::Ifindex`].
    GetMpath = nl80211_commands::NL80211_CMD_GET_MPATH as u8,
    /// Set mesh path attributes for mesh path to destination [`Nl80211Attr::Mac`] on the interface identified by [`Nl80211Attr::Ifindex`].
    SetMpath = nl80211_commands::NL80211_CMD_SET_MPATH as u8,
    /// Create a new mesh path for the destination given by [`Nl80211Attr::Mac`] via [`Nl80211Attr::MpathNextHop`].
    NewMpath = nl80211_commands::NL80211_CMD_NEW_MPATH as u8,
    /// Delete a mesh path to the destination given by [`Nl80211Attr::Mac`].
    DelMpath = nl80211_commands::NL80211_CMD_DEL_MPATH as u8,
    /// Set BSS attributes for BSS identified by [`Nl80211Attr::Ifindex`].
    SetBss = nl80211_commands::NL80211_CMD_SET_BSS as u8,
    /// Set current regulatory domain.
    ///
    /// CRDA sends this command after being queried by the kernel. CRDA replies by sending a regulatory
    /// domain structure which consists of [`Nl80211Attr::RegAlpha2`] set to our current alpha2 if it found a match.
    /// It also provides [`Nl80211RegRuleAttr::Flags`], and a set of regulatory rules.
    ///
    /// Each regulatory rule is a nested set of attributes given by [`Nl80211RegRuleAttr::FreqRangeStart`]/[`Nl80211RegRuleAttr::FreqRangeEnd`]
    /// and [`Nl80211RegRuleAttr::FreqRangeMaxBw`] with an attached power rule given by [`Nl80211RegRuleAttr::PowerRuleMaxAntGain`]
    /// and [`Nl80211RegRuleAttr::PowerRuleMaxEirp`].
    SetReg = nl80211_commands::NL80211_CMD_SET_REG as u8,
    /// Ask the wireless core to set the regulatory domain to the specified ISO/IEC 3166-1 alpha2 country code.
    ///
    /// The core will store this as a valid request and then query user space for it.
    ReqSetReg = nl80211_commands::NL80211_CMD_REQ_SET_REG as u8,
    /// Get mesh networking properties for the interface identified by [`Nl80211Attr::Ifindex`].
    GetMeshConfig = nl80211_commands::NL80211_CMD_GET_MESH_CONFIG as u8,
    /// Set mesh networking properties for the interface identified by [`Nl80211Attr::Ifindex`].
    SetMeshConfig = nl80211_commands::NL80211_CMD_SET_MESH_CONFIG as u8,
    /// Set extra IEs for management frames.
    ///
    /// The interface is identified with [`Nl80211Attr::Ifindex`] and the management frame subtype with [`Nl80211Attr::MgmtSubtype`].
    /// The extra IE data to be added to the end of the specified management frame is specified with [`Nl80211Attr::Ie`].
    ///
    /// If the command succeeds, the requested data will be added to all specified management frames generated by kernel/firmware/driver.
    ///
    /// Note: This command has been removed and it is only reserved at this point to avoid re-using existing command number. The
    /// functionality this command was planned for has been provided with cleaner design with the option to specify additional IEs in
    /// [`Nl80211Command::TriggerScan`], [`Nl80211Command::Authenticate`], [`Nl80211Command::Associate`], [`Nl80211Command::Deauthenticate`],
    /// and [`Nl80211Command::Disassociate`].
    // TODO: Deprecate?
    SetMgmtExtraIe = nl80211_commands::NL80211_CMD_SET_MGMT_EXTRA_IE as u8,
    /// Ask the wireless core to send us its currently set regulatory domain.
    ///
    /// If [`Nl80211Attr::Wiphy`] is specified and the device has a private regulatory domain, it will be returned. Otherwise, the
    /// global regdomain will be returned.
    ///
    /// A device will have a private regulatory domain if it uses the `regulatory_hint()` API. Even when a private regdomain is
    /// used the channel information will still be mended according to further hints from the regulatory core to help with compliance.
    ///
    /// A dump version of this API is now available which will returns the global regdomain as well as
    /// all private regdomains of present wiphys (for those that have it). If a wiphy is self-managed
    /// ([`Nl80211Attr::WiphySelfManagedReg`], then its private regdomain is the only valid one for it.
    /// The regulatory core is not used to help with compliance in this case.
    GetReg = nl80211_commands::NL80211_CMD_GET_REG as u8,
    /// Get scan results.
    GetScan = nl80211_commands::NL80211_CMD_GET_SCAN as u8,
    /// Trigger a new scan with the given parameters.
    ///
    /// [`Nl80211Attr::TxNoCckRate`] is used to decide whether to send the probe requests at CCK rate or not.
    ///
    /// [`Nl80211Attr::Bssid`] can be used to specify a BSSID to scan for; if not included, the wildcard BSSID will be used.
    TriggerScan = nl80211_commands::NL80211_CMD_TRIGGER_SCAN as u8,
    /// Scan notification (as a reply to [`Nl80211Command::GetScan`] and on the "scan" multicast group).
    NewScanResults = nl80211_commands::NL80211_CMD_NEW_SCAN_RESULTS as u8,
    /// Scan was aborted, for unspecified reasons, partial scan results may be available.
    ScanAborted = nl80211_commands::NL80211_CMD_SCAN_ABORTED as u8,
    /// Indicates to user space the regulatory domain has been changed and provides details of the request
    /// information that caused the change such as:
    /// - Who initiated the regulatory request ([`Nl80211Attr::RegInitiator`])
    /// - The wiphy index ([`Nl80211Attr::RegAlpha2`]) on which the request was made from if the initiator was
    ///   `NL80211_REGDOM_SET_BY_COUNTRY_IE` or `NL80211_REGDOM_SET_BY_DRIVER`
    /// - The type of regulatory domain set ([`Nl80211Attr::RegType`])
    /// - If the type of regulatory domain is `NL80211_REG_TYPE_COUNTRY` the alpha2 to which we have moved
    ///   on to ([`Nl80211Attr::RegAlpha2`])
    // TODO: enum nl80211_reg_initiator
    // TODO: enum nl80211_reg_type
    RegChange = nl80211_commands::NL80211_CMD_REG_CHANGE as u8,
    /// Authentication request and notification.
    ///
    /// This command is used both as a command (request to authenticate) and as an event on the "mlme" multicast group,
    /// indicating completion of the authentication process.
    ///
    /// When used as a command:
    /// - [`Nl80211Attr::Ifindex`] is used to identify the interface
    /// - [`Nl80211Attr::Mac`] is used to specify PeerSTAAddress (and BSSID in case of station mode)
    /// - [`Nl80211Attr::Ssid`] is used to specify the SSID (mainly for association, but is included in authentication request
    ///   too to help BSS selection. [`Nl80211Attr::WiphyFreq`]
    /// - [`Nl80211Attr::WiphyFreqOffset`] are used to specify the frequency of the channel in MHz.
    /// - [`Nl80211Attr::AuthType`] is used to specify the authentication type
    /// - [`Nl80211Attr::Ie`] is used to define IEs (VendorSpecificInfo, but also including RSN IE and FT IEs) to be added to the frame.
    ///
    /// When used as an event, this reports reception of an Authentication frame in station and IBSS modes when the local MLME processed
    /// the frame, i.e., it was for the local STA and was received in correct state. This is similar to MLME-AUTHENTICATE.confirm primitive
    /// in the MLME SAP interface (kernel providing MLME, user space SME). The included [`Nl80211Attr::Frame`] attribute contains the management
    /// frame (including both the header and frame body, but not FCS). This event is also used to indicate if the authentication attempt timed out.
    /// In that case the [`Nl80211Attr::Frame`] attribute is replaced with a [`Nl80211Attr::TimedOut`] (and [`Nl80211Attr::Mac`] to indicate which
    /// pending authentication timed out).
    Authenticate = nl80211_commands::NL80211_CMD_AUTHENTICATE as u8,
    /// Association request and notification; like [`Nl80211Command::Authenticate`] but for Association and Reassociation (similar to
    /// MLME-ASSOCIATE.request, MLME-REASSOCIATE.request, MLME-ASSOCIATE.confirm or MLME-REASSOCIATE.confirm primitives).
    ///
    /// The [`Nl80211Attr::PrevBssid`] attribute is used to specify whether the request is for the initial
    /// association to an ESS (that attribute not included) or for reassociation within the ESS (that attribute is included).
    Associate = nl80211_commands::NL80211_CMD_ASSOCIATE as u8,
    /// Deauthentication request and notification; like [`Nl80211Command::Authenticate`] but for Deauthentication
    /// frames (similar to MLME-DEAUTHENTICATION.request and MLME-DEAUTHENTICATE.indication primitives).
    Deauthenticate = nl80211_commands::NL80211_CMD_DEAUTHENTICATE as u8,
    /// Disassociation request and notification; like [`Nl80211Command::Authenticate`] but for Disassociation frames
    /// (similar to MLME-DISASSOCIATE.request and MLME-DISASSOCIATE.indication primitives).
    Disassociate = nl80211_commands::NL80211_CMD_DISASSOCIATE as u8,
    /// Notification of a locally detected Michael MIC (part of TKIP) failure; sent on the "mlme" multicast group
    ///
    /// The event includes:
    /// - [`Nl80211Attr::Mac`] to describe the source MAC address of the frame with invalid MIC
    /// - [`Nl80211Attr::KeyType`] to show the key type
    /// - [`Nl80211Attr::KeyIdx`] to indicate the key identifier
    /// - [`Nl80211Attr::KeySeq`] to indicate the TSC value of the frame
    ///
    /// This event matches with MLME-MICHAELMICFAILURE.indication() primitive
    MichaelMicFailure = nl80211_commands::NL80211_CMD_MICHAEL_MIC_FAILURE as u8,
    /// Indicates to user space that an AP beacon has been found while world roaming thus enabling active scan or
    /// any mode of operation that initiates TX (beacons) on a channel where we would not have been able to do either before.
    ///
    /// As an example, if you are world roaming (regulatory domain set to world or if your driver is using a custom world roaming
    /// regulatory domain) and while doing a passive scan on the 5 GHz band you find an AP there (if not on a DFS channel),
    /// you will now be able to actively scan for that AP or use AP mode on your card on that same channel.
    ///
    /// Note that this will never be used for channels 1-11 on the 2 GHz band as they are always enabled world wide.
    ///
    /// This beacon hint is only sent if your device had either disabled active scanning or beaconing on a channel. We send to user space
    /// the wiphy on which we removed a restriction from ([`Nl80211Attr::Wiphy`]) and the channel on which this occurred before
    /// ([`Nl80211Attr::FreqBefore`]) and after ([`Nl80211Attr::FreqAfter`]) the beacon hint was processed.
    RegBeaconHint = nl80211_commands::NL80211_CMD_REG_BEACON_HINT as u8,
    /// Join a new IBSS -- given at least an [`Nl80211Attr::Ssid`] and a FREQ attribute (for the initial frequency if no peer can be found)
    /// and optionally a [`Nl80211Attr::Mac`] (as BSSID) and [`Nl80211Attr::FreqFixed`] attribute if those should be fixed rather
    /// than automatically determined.
    ///
    /// Can only be executed on a network interface that is UP, and fixed BSSID/FREQ may be rejected. Another optional parameter
    /// is the beacon interval, given in the [`Nl80211Attr::BeaconInterval`] attribute, which if not given defaults to 100 TU (102.4ms).
    JoinIbss = nl80211_commands::NL80211_CMD_JOIN_IBSS as u8,
    /// Leave the IBSS
    ///
    /// No special arguments, the IBSS is determined by the network interface.
    LeaveIbss = nl80211_commands::NL80211_CMD_LEAVE_IBSS as u8,
    /// Testmode command, takes a wiphy (or ifindex) attribute to identify the device, and the [`Nl80211Attr::Testdata`]
    /// blob attribute to pass through to the driver.
    Testmode = nl80211_commands::NL80211_CMD_TESTMODE as u8,
    /// Connection request and notification
    ///
    /// This command requests to connect to a specified network but without separating authentication and association steps.
    ///
    /// For this, you need to specify the SSID in a [`Nl80211Attr::Ssid`] attribute, and can optionally specify:
    /// - The association IEs in [`Nl80211Attr::Ie`]
    /// - [`Nl80211Attr::AuthType`]
    /// - [`Nl80211Attr::UseMfp`]
    /// - [`Nl80211Attr::Mac`]
    /// - [`Nl80211Attr::WiphyFreq`],
    /// - [`Nl80211Attr::WiphyFreqOffset`]
    /// - [`Nl80211Attr::ControlPort`]
    /// - [`Nl80211Attr::ControlPortEthertype`]
    /// - [`Nl80211Attr::ControlPortNoEncrypt`],
    /// - [`Nl80211Attr::ControlPortOverNl80211`]
    /// - [`Nl80211Attr::MacHint`]
    /// - [`Nl80211Attr::WiphyFreqHint`]
    ///
    /// If included, [`Nl80211Attr::Mac`] and [`Nl80211Attr::WiphyFreq`] are restrictions on BSS selection, i.e., they effectively
    /// prevent roaming within the ESS. [`Nl80211Attr::MacHint`] and [`Nl80211Attr::WiphyFreqHint`] can be included to provide a
    /// recommendation of the initial BSS while allowing the driver to roam to other BSSes within the ESS and also to ignore this
    /// recommendation if the indicated BSS is not ideal. Only one set of BSSID, frequency parameters is used (i.e., either the enforcing
    /// [`Nl80211Attr::Mac`], [`Nl80211Attr::WiphyFreq`] or the less strict [`Nl80211Attr::MacHint`] and [`Nl80211Attr::WiphyFreqHint`].
    ///
    /// Driver shall not modify the IEs specified through [`Nl80211Attr::Ie`] if [`Nl80211Attr::Mac`] is included. However, if
    /// [`Nl80211Attr::MacHint`] is included, these IEs through [`Nl80211Attr::Ie`] are specified by the user space based on the
    /// best possible BSS selected. Thus, if the driver ends up selecting a different BSS, it can modify these IEs accordingly (e.g.
    /// user space asks the driver to perform PMKSA caching with BSS1 and the driver ends up selecting BSS2 with different PMKSA cache entry;
    /// RSNIE has to get updated with the apt PMKID).
    ///
    /// [`Nl80211Attr::PrevBssid`] can be used to request a reassociation within the ESS in case the device is already associated and
    /// an association with a different BSS is desired.
    ///
    /// Background scan period can optionally be specified in [`Nl80211Attr::BgScanPeriod`]. If not specified, default background scan
    /// configuration in driver is used and if period value is 0, background scan will be disabled. This attribute is ignored if driver
    /// does not support roam scan.
    ///
    /// It is also sent as an event, with the BSSID and response IEs when the connection is established or failed to be established.
    /// This can be determined by the [`Nl80211Attr::StatusCode`] attribute (0 = success, non-zero = failure).
    /// If [`Nl80211Attr::TimedOut`] is included in the event, the connection attempt failed due to not being able to initiate
    /// authentication/association or not receiving a response from the AP. Non-zero [`Nl80211Attr::StatusCode`] value is indicated
    /// in that case as well to remain backwards compatible.
    Connect = nl80211_commands::NL80211_CMD_CONNECT as u8,
    /// Notification indicating the card/driver roamed by itself.
    ///
    /// When a security association was established on an 802.1X network using fast transition, this event should be followed by an
    /// [`Nl80211Command::PortAuthorized`] event.
    ///
    /// Following a [`Nl80211Command::Roam`] event user space can issue [`Nl80211Command::GetScan`] in order to obtain the
    /// scan information for the new BSS the card/driver roamed to.
    Roam = nl80211_commands::NL80211_CMD_ROAM as u8,
    /// Drop a given connection
    ///
    /// Also used to notify user space that a connection was dropped by the AP or due to other reasons, for this the
    /// [`Nl80211Attr::DisconnectedByAp`] and [`Nl80211Attr::ReasonCode`] attributes are used.
    Disconnect = nl80211_commands::NL80211_CMD_DISCONNECT as u8,
    /// Set a wiphy's network namespace
    ///
    /// Note that all devices associated with this wiphy must be down and will follow.
    SetWiphyNetns = nl80211_commands::NL80211_CMD_SET_WIPHY_NETNS as u8,
    /// Get survey results, e.g. channel occupation or noise level
    GetSurvey = nl80211_commands::NL80211_CMD_GET_SURVEY as u8,
    /// Survey data notification (as a reply to [`Nl80211Command::GetSurvey`] and on the "scan" multicast group)
    NewSurveyResults = nl80211_commands::NL80211_CMD_NEW_SURVEY_RESULTS as u8,
    /// Add a PMKSA cache entry using [`Nl80211Attr::Mac`] (for the BSSID), [`Nl80211Attr::Pmkid`], and
    /// optionally [`Nl80211Attr::Pmk`] (PMK is used for PTKSA derivation in case of FILS shared key offload)
    /// or using [`Nl80211Attr::Ssid`], [`Nl80211Attr::FilsCacheId`], [`Nl80211Attr::Pmkid`], and
    /// [`Nl80211Attr::Pmk`] in case of FILS authentication where [`Nl80211Attr::FilsCacheId`] is the identifier
    /// advertised by a FILS capable AP identifying the scope of PMKSA in an ESS.
    SetPmksa = nl80211_commands::NL80211_CMD_SET_PMKSA as u8,
    /// Delete a PMKSA cache entry, using [`Nl80211Attr::Mac`] (for the BSSID) and [`Nl80211Attr::Pmkid`]
    /// or using [`Nl80211Attr::Ssid`], [`Nl80211Attr::FilsCacheId`], and [`Nl80211Attr::Pmkid`] in case
    /// of FILS authentication.
    ///
    /// Additionally in case of SAE offload and OWE offloads PMKSA entry can be deleted using [`Nl80211Attr::Ssid`].
    DelPmksa = nl80211_commands::NL80211_CMD_DEL_PMKSA as u8,
    /// Flush all PMKSA cache entries.
    FlushPmksa = nl80211_commands::NL80211_CMD_FLUSH_PMKSA as u8,
    /// Request to remain awake on the specified channel for the specified amount of time.
    ///
    /// This can be used to do off-channel operations like transmit a Public Action frame and wait for
    /// a response while being associated to an AP on another channel.
    ///
    /// [`Nl80211Attr::Ifindex`] is used to specify which interface (and thus radio) is used. [`Nl80211Attr::WiphyFreq`]
    /// is used to specify the frequency for the operation. [`Nl80211Attr::Duration`] is used to specify the
    /// duration in milliseconds to remain on the channel.
    ///
    /// This command is also used as an event to notify when the requested duration starts (it may take a while for
    /// the driver to schedule this time due to other concurrent needs for the radio).
    ///
    /// When called, this operation returns a cookie ([`Nl80211Attr::Cookie`]) that will be included with any
    /// events pertaining to this request; the cookie is also used to cancel the request.
    RemainOnChannel = nl80211_commands::NL80211_CMD_REMAIN_ON_CHANNEL as u8,
    /// This command can be used to cancel a pending remain-on-channel duration if the desired operation has been
    /// completed prior to expiration of the originally requested duration.
    ///
    /// [`Nl80211Attr::Wiphy`] or [`Nl80211Attr::Ifindex`] is used to specify the radio. The [`Nl80211Attr::Cookie`]
    /// attribute must be given as well to uniquely identify the request.
    ///
    /// This command is also used as an event to notify when a requested remain-on-channel duration has expired.
    CancelRemainOnChannel = nl80211_commands::NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL as u8,
    /// Set the mask of rates to be used in TX rate selection.
    ///
    /// [`Nl80211Attr::Ifindex`] is used to specify the interface and [`Nl80211Attr::TxRates`] the set of allowed rates.
    SetTxBitrateMask = nl80211_commands::NL80211_CMD_SET_TX_BITRATE_MASK as u8,
    /// Register for receiving certain management frames (via [`Nl80211Command::Frame`]) for processing in user space.
    ///
    /// This command requires an interface index, a frame type attribute (optional for backward compatibility reasons,
    /// if not given assumes action frames) and a match attribute containing the first few bytes of the frame that should
    /// match, e.g. a single byte for only a category match or four bytes for vendor frames including the OUI.
    ///
    /// The registration cannot be dropped, but is removed automatically when the netlink socket is closed. Multiple registrations
    /// can be made.
    ///
    /// The [`Nl80211Attr::ReceiveMulticast`] flag attribute can be given if [`Nl80211ExtFeatureIndex::MulticastRegistrations`]
    /// is available, in which case the registration can also be modified to include/exclude the flag, rather than requiring
    /// unregistration to change it.
    RegisterFrame = nl80211_commands::NL80211_CMD_REGISTER_FRAME as u8,
    /// Alias for [`Nl80211Command::RegisterFrame`] for backward compatibility.
    RegisterAction = nl80211_commands::NL80211_CMD_REGISTER_ACTION as u8,
    /// Management frame TX request and RX notification.
    ///
    /// This command is used both as a request to transmit a management frame and as an event indicating reception
    /// of a frame that was not processed in kernel code, but is for us (i.e., which may need to be processed in a
    /// user space application).
    ///
    /// [`Nl80211Attr::Frame`] is used to specify the frame contents (including header). [`Nl80211Attr::WiphyFreq`]
    /// is used to indicate on which channel the frame is to be transmitted or was received.
    ///
    /// If this channel is not the current channel (remain-on-channel or the operational channel) the device will switch
    /// to the given channel and transmit the frame, optionally waiting for a response for the time specified using
    /// [`Nl80211Attr::Duration`].
    ///
    /// When called, this operation returns a cookie ([`Nl80211Attr::Cookie`]) that will be included with the TX status
    /// event pertaining to the TX request.
    ///
    /// [`Nl80211Attr::TxNoCckRate`] is used to decide whether to send the management frames at CCK rate or not in 2 GHz band.
    ///
    /// [`Nl80211Attr::CsaCOffsetsTx`] is an array of offsets to CSA counters which will be updated to the current value.
    /// This attribute is used during CSA period.
    ///
    /// For TX on an MLD, the frequency can be omitted and the link ID be specified ([`Nl80211Attr::MloLinkId`]),
    /// or if transmitting to a known peer MLD (with MLD addresses in the frame) both can be omitted and the link
    /// will be selected by lower layers.
    ///
    /// For RX notification, [`Nl80211Attr::RxHwTimestamp`] may be included to indicate the frame RX timestamp and
    /// [`Nl80211Attr::TxHwTimestamp`] may be included to indicate the ACK TX timestamp.
    Frame = nl80211_commands::NL80211_CMD_FRAME as u8,
    /// Alias for [`Nl80211Command::Frame`] for backward compatibility.
    Action = nl80211_commands::NL80211_CMD_ACTION as u8,
    /// Report TX status of a management frame transmitted with [`Nl80211Command::Frame`].
    ///
    /// [`Nl80211Attr::Cookie`] identifies the TX command and [`Nl80211Attr::Frame`] includes the contents of the frame.
    ///
    /// [`Nl80211Attr::Ack`] flag is included if the recipient acknowledged the frame.
    ///
    /// [`Nl80211Attr::TxHwTimestamp`] may be included to indicate the TX timestamp and [`Nl80211Attr::RxHwTimestamp`]
    /// may be included to indicate the ACK RX timestamp.
    FrameTxStatus = nl80211_commands::NL80211_CMD_FRAME_TX_STATUS as u8,
    /// Alias for [`Nl80211Command::FrameTxStatus`] for backward compatibility.
    ActionTxStatus = nl80211_commands::NL80211_CMD_ACTION_TX_STATUS as u8,
    /// Set powersave, using [`Nl80211Attr::PsState`].
    SetPowerSave = nl80211_commands::NL80211_CMD_SET_POWER_SAVE as u8,
    /// Get powersave status in [`Nl80211Attr::PsState`].
    GetPowerSave = nl80211_commands::NL80211_CMD_GET_POWER_SAVE as u8,
    /// Connection quality monitor configuration
    ///
    /// This command is used to configure connection quality monitoring notification trigger levels.
    SetCqm = nl80211_commands::NL80211_CMD_SET_CQM as u8,
    /// Connection quality monitor notification.
    ///
    /// This command is used as an event to indicate the that a trigger level was reached.
    NotifyCqm = nl80211_commands::NL80211_CMD_NOTIFY_CQM as u8,
    /// Set the channel (using [`Nl80211Attr::WiphyFreq`] and the attributes determining channel width) the given
    /// interface (identified by [`Nl80211Attr::Ifindex`]) shall operate on.
    ///
    /// In case multiple channels are supported by the device, the mechanism with which it switches channels is implementation-defined.
    ///
    /// When a monitor interface is given, it can only switch channel while no other interfaces are operating to avoid disturbing
    /// the operation of any other interfaces, and other interfaces will again take precedence when they are used.
    SetChannel = nl80211_commands::NL80211_CMD_SET_CHANNEL as u8,
    /// Set the MAC address of the peer on a WDS interface (no longer supported).
    // TODO: Deprecate?
    SetWdsPeer = nl80211_commands::NL80211_CMD_SET_WDS_PEER as u8,
    /// When an off-channel TX was requested, this command may be used with the corresponding cookie to cancel the wait
    /// time if it is known that it is no longer necessary.
    ///
    /// This command is also sent as an event whenever the driver has completed the off-channel wait time.
    FrameWaitCancel = nl80211_commands::NL80211_CMD_FRAME_WAIT_CANCEL as u8,
    /// Join a mesh.
    ///
    /// The mesh ID must be given, and initial mesh config parameters may be given.
    JoinMesh = nl80211_commands::NL80211_CMD_JOIN_MESH as u8,
    /// Leave the mesh network.
    ///
    /// No special arguments, the network is determined by the network interface.
    LeaveMesh = nl80211_commands::NL80211_CMD_LEAVE_MESH as u8,
    /// Unprotected deauthentication frame notification.
    ///
    /// This event is used to indicate that an unprotected deauthentication frame was dropped when MFP is in use.
    UnprotDeauthenticate = nl80211_commands::NL80211_CMD_UNPROT_DEAUTHENTICATE as u8,
    /// Unprotected disassociation frame notification.
    ///
    /// This event is used to indicate that an unprotected disassociation frame was dropped when MFP is in use.
    UnprotDisassociate = nl80211_commands::NL80211_CMD_UNPROT_DISASSOCIATE as u8,
    /// Notification on the reception of a beacon or probe response from a compatible mesh peer.
    ///
    /// This is only sent while no station information (`sta_info`) exists for the new peer candidate and when
    /// `NL80211_MESH_SETUP_USERSPACE_AUTH`, `NL80211_MESH_SETUP_USERSPACE_AMPE`, or `NL80211_MESH_SETUP_USERSPACE_MPM` is set.
    ///
    /// On reception of this notification, user space may decide to create a new station ([`Nl80211Command::NewStation`]).
    ///
    /// To stop this notification from reoccurring, the user space authentication daemon may want to create the
    /// new station with the AUTHENTICATED flag unset and maybe change it later depending on the authentication result.
    // TODO: enum nl80211_mesh_setup_params
    NewPeerCandidate = nl80211_commands::NL80211_CMD_NEW_PEER_CANDIDATE as u8,
    /// Get Wake-on-Wireless-LAN (WoWLAN) settings.
    GetWowlan = nl80211_commands::NL80211_CMD_GET_WOWLAN as u8,
    /// Set Wake-on-Wireless-LAN (WoWLAN) settings.
    ///
    /// Since wireless is more complex than wired ethernet, it supports various triggers. These triggers can be
    /// configured through this command with the [`Nl80211Attr::WowlanTriggers`] attribute. For more background information,
    /// see [here](https://wireless.wiki.kernel.org/en/users/Documentation/WoWLAN).
    ///
    /// The [`Nl80211Command::SetWowlan`] command can also be used as a notification from the driver reporting the wakeup reason.
    /// In this case, the [`Nl80211Attr::WowlanTriggers`] attribute will contain the reason for the wakeup, if it was caused by wireless.
    /// If it is not present in the wakeup notification, the wireless device didn't cause the wakeup but reports that it was woken up.
    SetWowlan = nl80211_commands::NL80211_CMD_SET_WOWLAN as u8,
    /// Start a scheduled scan at certain intervals and certain number of cycles, as specified by [`Nl80211Attr::SchedScanPlans`].
    ///
    /// If [`Nl80211Attr::SchedScanPlans`] is not specified and only [`Nl80211Attr::SchedScanInterval`] is specified, scheduled scan
    /// will run in an infinite loop with the specified interval. These attributes are mutually exclusive, i.e.
    /// [`Nl80211Attr::SchedScanInterval`] must not be passed if [`Nl80211Attr::SchedScanPlans`] is defined.
    ///
    ///  If for some reason scheduled scan is aborted by the driver, all scan plans are canceled (including scan plans that did
    /// not start yet).
    ///
    /// Like with normal scans, if SSIDs ([`Nl80211Attr::ScanSsids`] are passed, they are used in the probe requests.  For broadcast,
    /// a broadcast SSID must be passed (i.e. an empty string). If no SSID is passed, no probe requests are sent and a passive scan
    /// is performed.
    ///
    /// [`Nl80211Attr::ScanFrequencies`], if passed, define which channels should be scanned; if not passed, all channels allowed
    /// for the current regulatory domain are used.
    ///
    /// Extra IEs can also be passed from the user space by using the [`Nl80211Attr::Ie`] attribute.
    ///
    /// The first cycle of the scheduled scan can be delayed by [`Nl80211Attr::SchedScanDelay`] if supplied.
    ///
    /// If the device supports multiple concurrent scheduled scans, it will allow such when the caller provides the flag attribute
    /// [`Nl80211Attr::SchedScanMulti`] to indicate user-space support for it.
    StartSchedScan = nl80211_commands::NL80211_CMD_START_SCHED_SCAN as u8,
    /// Stop a scheduled scan.
    ///
    /// Returns -ENOENT if scheduled scan is not running.
    ///
    /// The caller may assume that as soon as the call returns, it is safe to start a new scheduled scan again.
    StopSchedScan = nl80211_commands::NL80211_CMD_STOP_SCHED_SCAN as u8,
    /// Indicates that there are scheduled scan results available.
    SchedScanResults = nl80211_commands::NL80211_CMD_SCHED_SCAN_RESULTS as u8,
    /// Indicates that the scheduled scan has stopped.
    ///
    /// The driver may issue this event at any time during a scheduled scan.
    ///
    /// One reason for stopping the scan is if the hardware does not support starting an association or a normal scan while running
    /// a scheduled scan. This event is also sent when the [`Nl80211Command::StopSchedScan`] command is received or when the interface
    /// is brought down while a scheduled scan was running.
    SchedScanStopped = nl80211_commands::NL80211_CMD_SCHED_SCAN_STOPPED as u8,
    /// This command is used to give the driver the necessary information for supporting GTK rekey offload.
    ///
    /// This feature is typically used during WoWLAN. The configuration data is contained in [`Nl80211Attr::RekeyData`]
    /// (which is nested and contains the data in sub-attributes).
    ///
    /// After rekeying occurs, this command may also be sent by the driver as an MLME event to inform user space of the new
    /// replay counter.
    SetRekeyOffload = nl80211_commands::NL80211_CMD_SET_REKEY_OFFLOAD as u8,
    /// This is used as an event to inform user space PMKSA caching candidates.
    PmksaCandidate = nl80211_commands::NL80211_CMD_PMKSA_CANDIDATE as u8,
    /// Perform a high-level TDLS command (e.g. link setup).
    ///
    /// In addition, this can be used as an event to request user space to take actions on TDLS links (set up a new link or
    /// tear down an existing one).
    ///
    /// In such events, [`Nl80211Attr::TdlsOperation`] indicates the requested operation, [`Nl80211Attr::Mac`] contains the
    /// peer MAC address, and [`Nl80211Attr::ReasonCode`] the reason code to be used (only with [`Nl80211TdlsOperation::Teardown`]).
    TdlsOper = nl80211_commands::NL80211_CMD_TDLS_OPER as u8,
    /// Send a TDLS management frame.
    ///
    /// The [`Nl80211Attr::TdlsAction`] attribute determines the type of frame to be sent. Public Action codes
    /// (802.11-2012 8.1.5.1) will be sent as 802.11 management frames, while TDLS action codes (802.11-2012 8.5.13.1)
    /// will be encapsulated and sent as data frames.
    ///
    /// The currently supported Public Action code is `WLAN_PUB_ACTION_TDLS_DISCOVER_RES` and the currently supported TDLS
    /// actions codes are given in `enum ieee80211_tdls_actioncode`.
    TdlsMgmt = nl80211_commands::NL80211_CMD_TDLS_MGMT as u8,
    /// Used by an application controlling an AP (or GO) interface (i.e. `hostapd`) to ask for unexpected frames to implement
    /// sending deauthentication to stations that send unexpected class 3 frames. Also used as the event sent by the kernel
    /// when such a frame is received.
    ///
    /// For the event, the [`Nl80211Attr::Mac`] attribute carries the transmit address (TA) and other attributes like the
    /// interface index are present.
    ///
    /// If used as the command, it must have an interface index and you can only unsubscribe from the event by closing the socket.
    /// Subscription is also for [`Nl80211Command::Unexpected4addrFrame`] events.
    UnexpectedFrame = nl80211_commands::NL80211_CMD_UNEXPECTED_FRAME as u8,
    /// Probe an associated station on an AP interface by sending a null data frame to it and reporting when the frame is acknowledged.
    ///
    /// This is used to allow timing out inactive clients.
    ///
    /// Uses [`Nl80211Attr::Ifindex`] and [`Nl80211Attr::Mac`].
    ///
    /// The command returns a direct reply with an [`Nl80211Attr::Cookie`] that is later used to match up the event with the request.
    ///
    /// The event includes the same data and has [`Nl80211Attr::Ack`] set if the frame was ACKed.
    ProbeClient = nl80211_commands::NL80211_CMD_PROBE_CLIENT as u8,
    /// Register this socket to receive beacons from other BSSes when any interfaces are in AP mode.
    ///
    /// This helps implement OLBC handling in `hostapd`.
    ///
    /// Beacons are reported in [`Nl80211Command::Frame`] messages.
    ///
    /// Note that per-wiphy only one application may register.
    RegisterBeacons = nl80211_commands::NL80211_CMD_REGISTER_BEACONS as u8,
    /// Sent as an event indicating that the associated station identified by [`Nl80211Attr::Mac`] sent a 4addr frame and wasn't
    /// already in a 4-addr VLAN.
    ///
    /// The event will be sent similarly to the [`Nl80211Command::UnexpectedFrame`] event, to the same listener.
    Unexpected4addrFrame = nl80211_commands::NL80211_CMD_UNEXPECTED_4ADDR_FRAME as u8,
    /// Sets a bitmap for the individual TIDs whether No Acknowledgement Policy should be applied.
    SetNoackMap = nl80211_commands::NL80211_CMD_SET_NOACK_MAP as u8,
    /// An AP or GO may decide to switch channels independently of the user space SME, send this event indicating [`Nl80211Attr::Ifindex`]
    /// is now on [`Nl80211Attr::WiphyFreq`] and the attributes determining channel width.
    ///
    /// This indication may also be sent when a remotely-initiated switch (e.g., when a STA receives a CSA from the remote AP) is completed.
    ChSwitchNotify = nl80211_commands::NL80211_CMD_CH_SWITCH_NOTIFY as u8,
    /// Start the given P2P Device, identified by its [`Nl80211Attr::Wdev`] identifier. It must have been created with [`Nl80211Command::NewInterface`]
    /// previously.
    ///
    /// After it has been started, the P2P Device can be used for P2P operations, e.g. remain-on-channel and public action frame TX.
    StartP2pDevice = nl80211_commands::NL80211_CMD_START_P2P_DEVICE as u8,
    /// Stop the given P2P Device, identified by its [`Nl80211Attr::Wdev`] identifier.
    StopP2pDevice = nl80211_commands::NL80211_CMD_STOP_P2P_DEVICE as u8,
    /// Connection request to an AP faile
    ///
    /// Used to notify user space that AP has rejected the connection request from a station, due to particular reason.
    /// [`Nl80211Attr::ConnFailedReason`] is used for this.
    ConnFailed = nl80211_commands::NL80211_CMD_CONN_FAILED as u8,
    /// Change the rate used to send multicast frames for [`Nl80211Iftype::Adhoc`] or [`Nl80211Iftype::MeshPoint`] virtual interface.
    SetMcastRate = nl80211_commands::NL80211_CMD_SET_MCAST_RATE as u8,
    /// Sets ACL for MAC address based access control.
    ///
    /// This is to be used with the drivers advertising the support of MAC address based access control.
    ///
    /// List of MAC addresses is passed in [`Nl80211Attr::MacAddrs`]  and ACL policy is passed in [`Nl80211Attr::AclPolicy`].
    ///
    /// Driver will enable ACL with this list, if it is not already done. The new list will replace any existing list. Driver
    /// will clear its ACL when the list of MAC addresses passed is empty. This command is used in AP/P2P GO mode. Driver has
    /// to make sure to clear its ACL list during [`Nl80211Command::StopAp`].
    SetMacAcl = nl80211_commands::NL80211_CMD_SET_MAC_ACL as u8,
    /// Start a channel availability check (CAC).
    ///
    /// Once radar is detected, the channel availability scan (CAC) has finished or was aborted, or a radar was detected,
    /// usermode will be notified with this event.
    ///
    /// This command is also used to notify user space about radars while operating on this channel. [`Nl80211Attr::RadarEvent`]
    /// is used to inform about the type of the event.
    RadarDetect = nl80211_commands::NL80211_CMD_RADAR_DETECT as u8,
    /// Get global `nl80211` protocol features, i.e. features for the `nl80211` protocol rather than device features.
    ///
    ///
    /// Returns the features in the [`Nl80211Attr::ProtocolFeatures`] bitmap.
    GetProtocolFeatures = nl80211_commands::NL80211_CMD_GET_PROTOCOL_FEATURES as u8,
    /// Pass down the most up-to-date Fast Transition (FT, 802.11r) Information Element to the WLAN driver.
    UpdateFtIes = nl80211_commands::NL80211_CMD_UPDATE_FT_IES as u8,
    /// Send a Fast Transition (FT, 802.11r) event from the WLAN driver to the supplicant.
    ///
    /// This will carry the target AP's MAC address along with the relevant Information Elements. This event
    /// is used to report received FT IEs (MDIE, FTIE, RSN IE, TIE, RICIE).
    FtEvent = nl80211_commands::NL80211_CMD_FT_EVENT as u8,
    /// Indicates user-space will start running a critical protocol that needs more reliability in the connection to complete.
    CritProtocolStart = nl80211_commands::NL80211_CMD_CRIT_PROTOCOL_START as u8,
    /// Indicates the connection reliability can return back to normal.
    CritProtocolStop = nl80211_commands::NL80211_CMD_CRIT_PROTOCOL_STOP as u8,
    /// Get currently supported coalesce rules.
    GetCoalesce = nl80211_commands::NL80211_CMD_GET_COALESCE as u8,
    /// Configure coalesce rules or clear existing rules.
    SetCoalesce = nl80211_commands::NL80211_CMD_SET_COALESCE as u8,
    /// Perform a channel switch by announcing the new channel information (Channel Switch Announcement - CSA) in the beacon
    /// for some time (as defined in the [`Nl80211Attr::ChSwitchCount`] parameter) and then change to the new channel.
    ///
    /// User space provides the new channel information (using [`Nl80211Attr::WiphyFreq`] and the attributes determining channel width).
    ///
    /// [`Nl80211Attr::ChSwitchBlockTx`] may be supplied to inform other station that transmission must be blocked until the channel
    /// switch is complete.
    ChannelSwitch = nl80211_commands::NL80211_CMD_CHANNEL_SWITCH as u8,
    /// Vendor-specified command/event.
    ///
    /// The command is specified by the [`Nl80211Attr::VendorId`] attribute and a sub-command in [`Nl80211Attr::VendorSubcmd`].
    /// Parameter(s) can be transported in [`Nl80211Attr::VendorData`].
    ///
    /// For feature advertisement, the [`Nl80211Attr::VendorData`] attribute is used in the wiphy data as a nested attribute
    /// containing descriptions (`struct nl80211_vendor_cmd_info`) of the supported vendor commands. This may also be sent as an
    /// event with the same attributes.
    Vendor = nl80211_commands::NL80211_CMD_VENDOR as u8,
    /// Set Interworking QoS mapping for IP DSCP values.
    ///
    /// The QoS mapping information is included in [`Nl80211Attr::QosMap`]. If that attribute is not included, QoS mapping is disabled.
    ///
    /// Since this QoS mapping is relevant for IP packets, it is only valid during an association. This is cleared on disassociation
    /// and AP restart.
    SetQosMap = nl80211_commands::NL80211_CMD_SET_QOS_MAP as u8,
    /// Ask the kernel to add a traffic stream for the given [`Nl80211Attr::Tsid`] and [`Nl80211Attr::Mac`]
    /// with [`Nl80211Attr::UserPrio`] and [`Nl80211Attr::AdmittedTime`] parameters.
    ///
    /// Note that the action frame handshake with the AP shall be handled by user space via the normal management
    /// RX/TX framework, this only sets up the TX TS in the driver/device. If the admitted time attribute is not
    /// added then the request just checks if a subsequent setup could be successful, the intent is to use this to
    /// avoid setting up a session with the AP when local restrictions would make that impossible. However, the
    /// subsequent "real" setup may still fail even if the check was successful.
    AddTxTs = nl80211_commands::NL80211_CMD_ADD_TX_TS as u8,
    /// Remove an existing TS with the [`Nl80211Attr::Tsid`] and [`Nl80211Attr::Mac`] parameters.
    ///
    /// It isn't necessary to call this before removing a station entry entirely, or before disassociating or similar,
    /// cleanup will happen in the driver/device in this case.
    DelTxTs = nl80211_commands::NL80211_CMD_DEL_TX_TS as u8,
    /// Get mesh path attributes for mesh proxy path to destination [`Nl80211Attr::Mac`] on the interface identified by [`Nl80211Attr::Ifindex`].
    GetMpp = nl80211_commands::NL80211_CMD_GET_MPP as u8,
    /// Join the OCB network.
    ///
    /// The center frequency and bandwidth of a channel must be given.
    JoinOcb = nl80211_commands::NL80211_CMD_JOIN_OCB as u8,
    /// Leave the OCB network.
    ///
    /// No special arguments, the network is determined by the network interface.
    LeaveOcb = nl80211_commands::NL80211_CMD_LEAVE_OCB as u8,
    /// Notify that a channel switch has been started on an interface, regardless of the initiator (i.e. whether it was requested
    /// from a remote device or initiated on our own).
    ///
    /// It indicates that [`Nl80211Attr::Ifindex`] will be on [`Nl80211Attr::WiphyFreq`] after [`Nl80211Attr::ChSwitchCount`] TBTTs.
    ///
    /// The user space may decide to react to this indication by requesting other interfaces to change channel as well.
    ChSwitchStartedNotify = nl80211_commands::NL80211_CMD_CH_SWITCH_STARTED_NOTIFY as u8,
    /// Start channel-switching with a TDLS peer, identified by the [`Nl80211Attr::Mac`] parameter.
    ///
    /// A target channel is provided via [`Nl80211Attr::WiphyFreq`] and other attributes determining channel width/type.
    /// The target operating class is given via [`Nl80211Attr::OperClass`].
    ///
    /// The driver is responsible for continually initiating channel-switching operations and returning to the base channel for
    /// communication with the AP.
    TdlsChannelSwitch = nl80211_commands::NL80211_CMD_TDLS_CHANNEL_SWITCH as u8,
    /// Stop channel-switching with a TDLS peer given by [`Nl80211Attr::Mac`].
    ///
    /// Both peers must be on the base channel when this command completes.
    TdlsCancelChannelSwitch = nl80211_commands::NL80211_CMD_TDLS_CANCEL_CHANNEL_SWITCH as u8,
    /// Similar to [`Nl80211Command::RegChange`], but used as an event to indicate changes for devices with wiphy-specific regdom management.
    WiphyRegChange = nl80211_commands::NL80211_CMD_WIPHY_REG_CHANGE as u8,
    /// Stop an ongoing scan. Returns -ENOENT if a scan is not running.
    ///
    /// The driver indicates the status of the scan through `cfg80211_scan_done()`.
    AbortScan = nl80211_commands::NL80211_CMD_ABORT_SCAN as u8,
    /// Start NAN operation, identified by its [`Nl80211Attr::Wdev`] interface.
    ///
    /// This interface must have been previously created with [`Nl80211Command::NewInterface`]. After it has been started,
    /// the NAN interface will create or join a cluster.
    ///
    /// This command must have a valid [`Nl80211Attr::NanMasterPref`] attribute and optional [`Nl80211Attr::Bands`] attributes.
    /// If [`Nl80211Attr::Bands`] is omitted or set to 0, it means don't-care and the device will decide what to use.
    ///
    /// After this command, NAN functions can be added.
    StartNan = nl80211_commands::NL80211_CMD_START_NAN as u8,
    /// Stop the NAN operation, identified by its [`Nl80211Attr::Wdev`] interface.
    StopNan = nl80211_commands::NL80211_CMD_STOP_NAN as u8,
    /// Add a NAN function.
    ///
    /// The function is defined with [`Nl80211Attr::NanFunc`] nested attribute.
    ///
    /// When called, this operation returns the strictly positive and unique instance ID ([`Nl80211Attr::NanFuncInstId`)
    /// and a cookie ([`Nl80211Attr::Cookie`]) of the function upon success.
    ///
    /// Since instance ID's can be re-used, this cookie is the right way to identify the function. This will avoid races
    /// when a termination event is handled by the user space after it has already added a new function that got the same
    /// instance ID from the kernel as the one which just terminated.
    ///
    /// This cookie may be used in NAN events even before the command returns, so user space shouldn't process NAN events
    /// until it processes the response to this command. Look at [`Nl80211Attr::SocketOwner`] as well.
    AddNanFunction = nl80211_commands::NL80211_CMD_ADD_NAN_FUNCTION as u8,
    /// Delete a NAN function by cookie.
    ///
    /// This command is also used as a notification sent when a NAN function is terminated. This will contain a
    /// [`Nl80211NanFuncAttributes::InstanceId`] and [`Nl80211Attr::Cookie`] attributes.
    DelNanFunction = nl80211_commands::NL80211_CMD_DEL_NAN_FUNCTION as u8,
    /// Change current NAN configuration.
    ///
    /// NAN must be operational ([`Nl80211Command::StartNan`] was executed). It must contain at least one of the following attributes:
    /// [`Nl80211Attr::NanMasterPref`], [`Nl80211Attr::Bands`].
    ///
    /// If [`Nl80211Attr::Bands`] is omitted, the current configuration is not changed. If it is present but set to zero,
    /// the configuration is changed to don't-care (i.e. the device can decide what to do).
    ChangeNanConfig = nl80211_commands::NL80211_CMD_CHANGE_NAN_CONFIG as u8,
    /// Notification sent when a match is reported.
    ///
    /// This will contain a [`Nl80211Attr::NanMatch`] nested attribute and [`Nl80211Attr::Cookie`].
    NanMatch = nl80211_commands::NL80211_CMD_NAN_MATCH as u8,
    /// Configure if this AP should perform multicast to unicast conversion.
    ///
    /// When enabled, all multicast packets with ethertype ARP, IPv4 or IPv6 (possibly within an 802.1Q header)
    /// will be sent out to each station once with the destination (multicast) MAC address replaced by the station's
    /// MAC address.
    ///
    /// Note that this may break certain expectations of the receiver, e.g. the ability to drop unicast IP packets
    /// encapsulated in multicast L2 frames, or the ability to not send destination unreachable messages in such cases.
    ///
    /// This can only be toggled per BSS. Configure this on an interface of type [`Nl80211Iftype::Ap`].
    /// It applies to all its VLAN interfaces ([`Nl80211Iftype::ApVlan`]), except for those in 4addr (WDS) mode.
    ///
    /// If [`Nl80211Attr::MulticastToUnicastEnabled`] is not present with this command, the feature is disabled.
    SetMulticastToUnicast = nl80211_commands::NL80211_CMD_SET_MULTICAST_TO_UNICAST as u8,
    /// Update one or more connect parameters for subsequent roaming cases if the driver or firmware uses internal BSS selection.
    ///
    /// This command can be issued only while connected and it does not result in a change for the current association. Currently,
    /// only the [`Nl80211Attr::Ie`] data is used and updated with this command.
    UpdateConnectParams = nl80211_commands::NL80211_CMD_UPDATE_CONNECT_PARAMS as u8,
    /// For offloaded 4-Way handshake, set the PMK or PMK-R0 for the given authenticator address (specified with
    /// [`Nl80211Attr::Mac`]).
    ///
    /// When [`Nl80211Attr::Pmkr0Name`] is set, [`Nl80211Attr::Pmk`] specifies the PMK-R0, otherwise it specifies the PMK.
    SetPmk = nl80211_commands::NL80211_CMD_SET_PMK as u8,
    /// For offloaded 4-Way handshake, delete the previously configured PMK for the authenticator address identified by [`Nl80211Attr::Mac`].
    DelPmk = nl80211_commands::NL80211_CMD_DEL_PMK as u8,
    /// Control Port (e.g. PAE) frame TX request and RX notification.
    ///
    /// This command is used both as a request to transmit a control port frame and as a notification that a control
    /// port frame has been received. [`Nl80211Attr::Frame`] is used to specify the frame contents. The frame is the
    /// raw EAPoL data, without Ethernet or 802.11 headers.
    ///
    /// For an MLD transmitter, the [`Nl80211Attr::MloLinkId`] may be given and its effect will depend on the destination:
    /// If the destination is known to be an MLD, this will be used as a hint to select the link to transmit the frame on.
    /// If the destination is not an MLD, this will select both the link to transmit on and the source address will be set
    /// to the link address of that link.
    ///
    /// When used as an event indication [`Nl80211Attr::ControlPortEthertype`], [`Nl80211Attr::ControlPortNoEncrypt`],
    /// and [`Nl80211Attr::Mac`] are added indicating the protocol type of the received frame; whether the frame was
    /// received unencrypted and the MAC address of the peer respectively.
    PortAuthorized = nl80211_commands::NL80211_CMD_PORT_AUTHORIZED as u8,
    /// Request that the regdb firmware file is reloaded.
    ReloadRegdb = nl80211_commands::NL80211_CMD_RELOAD_REGDB as u8,
    /// This interface is exclusively defined for host drivers that do not define separate commands for authentication and
    /// association, but rely on user space for the authentication to happen. This interface acts both as the event request
    /// (driver to user space) to trigger the authentication and command response (user space to driver) to indicate the
    /// authentication status.
    ///
    /// User space uses the [`Nl80211Command::Connect`] command to the host driver to trigger a connection. The host driver
    /// selects a BSS and further uses this interface to offload only the authentication part to the user space.
    /// Authentication frames are passed between the driver and user space through the [`Nl80211Command::Frame`] interface.
    /// Host driver proceeds further with the association after getting successful authentication status. User space
    /// indicates the authentication status through [`Nl80211Attr::StatusCode`] attribute in [`Nl80211Command::ExternalAuth`]
    /// command interface.
    ///
    /// Host driver sends MLD address of the AP with [`Nl80211Attr::MldAddr`] in [`Nl80211Command::ExternalAuth`] event to
    /// indicate user space to enable MLO during the authentication offload in STA mode while connecting to MLD APs.
    /// Host driver should check [`Nl80211Attr::MloSupport`] flag capability in [`Nl80211Command::Connect`] to know whether
    /// the user space supports enabling MLO during the authentication offload or not. User space should enable MLO during
    /// the authentication only when it receives the AP MLD address in authentication offload request. User space shouldn't
    /// enable MLO when the authentication offload request doesn't indicate the AP MLD address even if the AP is MLO capable.
    /// User space should use [`Nl80211Attr::MldAddr`] as peer's MLD address and interface address identified by [`Nl80211Attr::Ifindex`]
    /// as self MLD address. User space and host driver to use MLD addresses in RA, TA and BSSID fields of the frames between them,
    /// and host driver translates the MLD addresses to/from link addresses based on the link chosen for the authentication.
    ///
    /// Host driver reports this status on an authentication failure to the user space through the connect result as the user
    /// space would have initiated the connection through the connect request.
    ExternalAuth = nl80211_commands::NL80211_CMD_EXTERNAL_AUTH as u8,
    /// An event that notify station's HT opmode or VHT opmode changes using any of [`Nl80211Attr::SmpsMode`],
    /// [`Nl80211Attr::ChannelWidth`], [`Nl80211Attr::Nss`] attributes with its address (specified in [`Nl80211Attr::Mac`]).
    StaOpmodeChanged = nl80211_commands::NL80211_CMD_STA_OPMODE_CHANGED as u8,
    /// Control Port (e.g. PAE) frame TX request and RX notification.
    ///
    /// This command is used both as a request to transmit a control port frame and as a notification that a
    /// control port frame has been received. [`Nl80211Attr::Frame`] is used to specify the frame contents.
    /// The frame is the raw EAPoL data, without Ethernet or 802.11 headers.
    ///
    /// For an MLD transmitter, the [`Nl80211Attr::MloLinkId`] may be given and its effect will depend on the destination:
    /// If the destination is known to be an MLD, this will be used as a hint to select the link to transmit  the frame on.
    /// If the destination is not an MLD, this will select both  the link to transmit on and the source address will be set to
    /// the link address of that link.
    ///
    ///
    /// When used as an event indication [`Nl80211Attr::ControlPortEthertype`], [`Nl80211Attr::ControlPortNoEncrypt`], and [`Nl80211Attr::Mac`]
    /// are added indicating the protocol type of the received frame; whether the frame was received unencrypted and the MAC address
    /// of the peer respectively.
    ControlPortFrame = nl80211_commands::NL80211_CMD_CONTROL_PORT_FRAME as u8,
    /// Retrieve FTM responder statistics, in the [`Nl80211Attr::FtmResponderStats`] attribute.
    GetFtmResponderStats = nl80211_commands::NL80211_CMD_GET_FTM_RESPONDER_STATS as u8,
    /// Start a (set of) peer measurement(s) with the given parameters, which are encapsulated in the nested
    /// [`Nl80211Attr::PeerMeasurements`] attribute.
    ///
    /// Optionally, MAC address randomization may be enabled and configured by specifying the
    /// [`Nl80211Attr::Mac`] and [`Nl80211Attr::MacMask`] attributes.
    ///
    /// If a timeout is requested, use the [`Nl80211Attr::Timeout`] attribute.
    ///
    /// A `u64` cookie for further [`Nl80211Attr::Cookie`] use is returned in the netlink extended ack message.
    ///
    /// To cancel a measurement, close the socket that requested it.
    ///
    /// Measurement results are reported to the socket that requested the measurement using [`Nl80211Command::PeerMeasurementResult`]
    /// when they become available, so applications must ensure a large enough socket buffer size.
    ///
    /// Depending on driver support it may or may not be possible to start multiple concurrent measurements.
    PeerMeasurementStart = nl80211_commands::NL80211_CMD_PEER_MEASUREMENT_START as u8,
    /// This command number is used for the result notification from the driver to the requesting socket.
    PeerMeasurementResult = nl80211_commands::NL80211_CMD_PEER_MEASUREMENT_RESULT as u8,
    /// Notification only, indicating that the measurement completed, using the measurement cookie ([`Nl80211Attr::Cookie`]).
    PeerMeasurementComplete = nl80211_commands::NL80211_CMD_PEER_MEASUREMENT_COMPLETE as u8,
    /// Notify the kernel that a radar signal was detected and reported by a neighboring device on the channel
    /// indicated by [`Nl80211Attr::WiphyFreq`] and other attributes determining the width and type.
    NotifyRadar = nl80211_commands::NL80211_CMD_NOTIFY_RADAR as u8,
    /// This interface allows the host driver to offload OWE processing to user space.
    ///
    /// This intends to support OWE AKM by the host drivers that implement SME but rely on the user space for
    /// the cryptographic/DH IE processing in AP mode.
    UpdateOweInfo = nl80211_commands::NL80211_CMD_UPDATE_OWE_INFO as u8,
    /// The requirement for mesh link metric refreshing is that from one mesh point we be able to send some data
    /// frames to other mesh points which are not currently selected as a primary traffic path, but which are only one
    /// hop away. The absence of the primary path to the chosen node makes it necessary to apply some form of marking
    /// on a chosen packet stream so that the packets can be properly steered to the selected node for testing, and not by the
    /// regular mesh path lookup. Further, the packets must be of type data so that the rate control (often embedded in firmware)
    /// is used for rate selection.
    ///
    /// Here attribute [`Nl80211Attr::Mac`] is used to specify connected mesh peer MAC address and
    /// [`Nl80211Attr::Frame`] is used to specify the frame content. The frame is Ethernet data.
    ProbeMeshLink = nl80211_commands::NL80211_CMD_PROBE_MESH_LINK as u8,
    /// Data frame TID specific configuration is passed using [`Nl80211Attr::TidConfig`] attribute.
    SetTidConfig = nl80211_commands::NL80211_CMD_SET_TID_CONFIG as u8,
    /// Unprotected or incorrectly protected Beacon frame.
    ///
    /// This event is used to indicate that a received Beacon frame was dropped because it did not include
    /// a valid MME MIC while beacon protection was enabled (BIGTK configured in station mode).
    UnprotBeacon = nl80211_commands::NL80211_CMD_UNPROT_BEACON as u8,
    /// Report TX status of a control port frame transmitted with [`Nl80211Command::ControlPortFrame`].
    ///
    /// [`Nl80211Attr::Cookie`] identifies the TX command and [`Nl80211Attr::Frame`] includes the contents
    /// of the frame. [`Nl80211Attr::Ack`] flag is included if the recipient acknowledged the frame.
    ControlPortFrameTxStatus = nl80211_commands::NL80211_CMD_CONTROL_PORT_FRAME_TX_STATUS as u8,
    /// SAR power limitation configuration is passed using [`Nl80211Attr::SarSpec`].
    /// [`Nl80211Attr::Wiphy`] is used to specify the wiphy index to be applied to.
    SetSarSpecs = nl80211_commands::NL80211_CMD_SET_SAR_SPECS as u8,
    /// This notification is sent out whenever `mac80211` or driver detects a BSS color collision.
    ObssColorCollision = nl80211_commands::NL80211_CMD_OBSS_COLOR_COLLISION as u8,
    /// This command is used to indicate that user space wants to change the BSS color.
    ColorChangeRequest = nl80211_commands::NL80211_CMD_COLOR_CHANGE_REQUEST as u8,
    /// Notify user space that a color change has started.
    ColorChangeStarted = nl80211_commands::NL80211_CMD_COLOR_CHANGE_STARTED as u8,
    /// Notify user space that the color change has been aborted.
    ColorChangeAborted = nl80211_commands::NL80211_CMD_COLOR_CHANGE_ABORTED as u8,
    /// Notify user space that the color change has completed.
    ColorChangeCompleted = nl80211_commands::NL80211_CMD_COLOR_CHANGE_COMPLETED as u8,
    ///  Set FILS AAD data to the driver using:
    /// - [`Nl80211Attr::Mac`] for STA MAC address
    /// - [`Nl80211Attr::FilsKek`] for KEK
    /// - [`Nl80211Attr::FilsNonces`] for FILS Nonces (STA Nonce 16 bytes followed by AP Nonce 16 bytes)
    SetFilsAad = nl80211_commands::NL80211_CMD_SET_FILS_AAD as u8,
    /// Notification about an association temporal rejection with comeback.
    ///
    /// The event includes [`Nl80211Attr::Mac`] to describe the BSSID address of the AP and [`Nl80211Attr::Timeout`]
    /// to specify the timeout value.
    AssocComeback = nl80211_commands::NL80211_CMD_ASSOC_COMEBACK as u8,
    /// Add a new link to an interface.
    ///
    /// The [`Nl80211Attr::MloLinkId`] attribute is used for the new link.
    AddLink = nl80211_commands::NL80211_CMD_ADD_LINK as u8,
    /// Remove a link from an interface.
    ///
    /// This may come without [`Nl80211Attr::MloLinkId`] as an easy way to remove all links in preparation
    /// for e.g. roaming to a regular (non-MLO) AP.
    RemoveLink = nl80211_commands::NL80211_CMD_REMOVE_LINK as u8,
    /// Add a link to an MLD station.
    AddLinkSta = nl80211_commands::NL80211_CMD_ADD_LINK_STA as u8,
    /// Modify a link of an MLD station.
    ModifyLinkSta = nl80211_commands::NL80211_CMD_MODIFY_LINK_STA as u8,
    /// Remove a link of an MLD station.
    RemoveLinkSta = nl80211_commands::NL80211_CMD_REMOVE_LINK_STA as u8,
    /// Enable/disable HW timestamping of timing measurement and fine timing measurement frames.
    ///
    /// If [`Nl80211Attr::Mac`] is included, enable/disable HW timestamping only for frames to/from the
    /// specified MAC address. Otherwise enable/disable HW timestamping for all TM/FTM frames (including
    /// ones that were enabled with specific MAC address).
    ///
    /// If [`Nl80211Attr::HwTimestampEnabled`] is not included, disable HW timestamping.
    ///
    /// The number of peers that HW timestamping can be enabled for concurrently is indicated by
    /// [`Nl80211Attr::MaxHwTimestampPeers`].
    SetHwTimestamp = nl80211_commands::NL80211_CMD_SET_HW_TIMESTAMP as u8,
    /// Notify user space about the removal of STA MLD setup links due to AP MLD removing the corresponding
    /// affiliated APs with Multi-Link reconfiguration.
    ///
    ///[`Nl80211Attr::MloLinks`] is used to provide information about the removed STA MLD setup links.
    LinksRemoved = nl80211_commands::NL80211_CMD_LINKS_REMOVED as u8,
    /// Set the TID to Link Mapping for a non-AP MLD station.
    ///
    /// The [`Nl80211Attr::MloTtlmDlink`] and [`Nl80211Attr::MloTtlmUlink`] attributes are used to specify the
    /// TID to Link mapping for downlink/uplink traffic.
    SetTidToLinkMapping = nl80211_commands::NL80211_CMD_SET_TID_TO_LINK_MAPPING as u8,
    /// For a non-AP MLD station, request to add/remove links to/from the association.
    ///
    /// To indicate link reconfiguration request results from the driver, this command is also
    /// used as an event to notify user space about the added links information. For notifying the removed
    /// links information, the existing [`Nl80211Command::LinksRemoved`] command is used.
    ///
    /// This command is also used to notify user space about newly added links for the current connection
    /// in case of AP-initiated link recommendation requests, received via a BTM (BSS Transition Management) request
    /// or a link reconfig notify frame, where the driver handles the link recommendation offload.
    AssocMloReconf = nl80211_commands::NL80211_CMD_ASSOC_MLO_RECONF as u8,
    /// EPCS configuration for a station.
    ///
    /// Used by user space to control EPCS configuration. Used to notify user space on the current state of EPCS.
    EpcsCfg = nl80211_commands::NL80211_CMD_EPCS_CFG as u8,
    /// This command is used to notify user space about the next NAN Discovery Window (DW). User space may use it
    /// to prepare frames to be sent in the next DW.
    ///
    /// [`Nl80211Attr::WiphyFreq`] is used to indicate the frequency of the next DW. SDF transmission should
    /// be requested with [`Nl80211Command::Frame`] and the device/driver shall take care of the actual transmission
    /// timing.
    ///
    /// This notification is only sent to the NAN interface owning socket (see [`Nl80211Attr::SocketOwner`] flag).
    NanNextDwNotification = nl80211_commands::NL80211_CMD_NAN_NEXT_DW_NOTIFICATION as u8,
    /// This command is used to notify user space that the NAN new cluster has been joined.
    /// The cluster ID is indicated by [`Nl80211Attr::Mac`].
    NanClusterJoined = nl80211_commands::NL80211_CMD_NAN_CLUSTER_JOINED as u8,
    /// Once any incumbent signal is detected on the operating channel in 6 GHz band, userspace is notified with the
    /// signal interference bitmap using [`Nl80211Attr::IncumbentSignalInterferenceBitmap`].
    ///
    /// The current channel definition is also sent.
    IncumbentSignalDetect = nl80211_commands::NL80211_CMD_INCUMBENT_SIGNAL_DETECT as u8,
    /// Set the local NAN schedule.
    ///
    /// NAN must be operational ([`Nl80211Command::StartNan`] was executed).
    ///
    /// Must contain [`Nl80211Attr::NanTimeSlots`] and [`Nl80211Attr::NanAvailBlob`], but [`Nl80211Attr::NanChannel`]
    /// is optional (for example in case of a channel removal, that channel won't be provided).
    ///
    /// If [`Nl80211Attr::NanSchedDeferred`] is set, the command is a request from the device to perform an announced
    /// schedule update. See [`Nl80211Attr::NanSchedDeferred`] for more details. If not set, the schedule should be
    /// applied immediately.
    NanSetLocalSched = nl80211_commands::NL80211_CMD_NAN_SET_LOCAL_SCHED as u8,
    /// Event sent to user space to notify that a deferred local NAN schedule update (requested with
    /// [`Nl80211Command::NanSetLocalSched`] and [`Nl80211Attr::NanSchedDeferred`]) has been completed.
    ///
    /// The presence of [`Nl80211Attr::NanSchedUpdateSuccess`] indicates that the update was successful.
    NanSchedUpdateDone = nl80211_commands::NL80211_CMD_NAN_SCHED_UPDATE_DONE as u8,
    /// Set the peer NAN schedule.
    ///
    /// NAN must be operational ([`Nl80211Command::StartNan`] was executed).
    ///
    /// Required attributes:
    /// - %NL80211_ATTR_MAC (peer NMI address)
    /// - %NL80211_ATTR_NAN_COMMITTED_DW
    ///
    /// Optionally, the full schedule can be provided by including all of:
    /// - %NL80211_ATTR_NAN_SEQ_ID
    /// - %NL80211_ATTR_NAN_CHANNEL (one or more)
    /// - %NL80211_ATTR_NAN_PEER_MAPS (see `enum nl80211_nan_peer_map_attrs`)
    /// If any of these three optional attributes is provided, all three must be provided.
    ///
    /// Each peer channel must be compatible with at least one local channel set by [`Nl80211Command::NanSetLocalSched`].
    /// Different maps must not contain compatible channels.
    ///
    /// For single-radio devices (n_radio <= 1), different maps must not schedule the same time slot, as the device
    /// cannot operate on multiple channels simultaneously.
    ///
    /// When updating an existing peer schedule, the full new schedule must be provided - partial updates are not supported.
    /// The new schedule will completely replace the previous one.
    ///
    /// The peer schedule is automatically removed when the NMI station is removed.
    // TODO: enum nl80211_nan_peer_map_attrs
    NanSetPeerSched = nl80211_commands::NL80211_CMD_NAN_SET_PEER_SCHED as u8,
    /// Notification from the driver to user space with the updated ULW blob of the device.
    ///
    /// User space can use this blob to attach to frames sent to peers.
    ///
    /// This notification contains [`Nl80211Attr::NanUlw`] with the ULW blob.
    NanUlwUpdate = nl80211_commands::NL80211_CMD_NAN_ULW_UPDATE as u8,
    /// Notification to indicate that a NAN channel has been evacuated due to resource conflicts with other interfaces.
    ///
    /// This can happen when another interface sharing the channel resource with NAN needs to move to a different channel
    /// (e.g., channel switch or link switch on a BSS interface).
    ///
    /// The notification contains [`Nl80211Attr::NanChannel`] attribute identifying the evacuated channel.
    ///
    /// User space may reconfigure the local schedule in response to this notification.
    NanChannelEvac = nl80211_commands::NL80211_CMD_NAN_CHANNEL_EVAC as u8,
    // v7.2+
    /// Start PD operation, identified by its [`Nl80211Attr::Wdev`] interface.
    ///
    /// This interface must have been previously created with [`Nl80211Command::NewInterface`].
    StartPd = nl80211_commands::NL80211_CMD_START_PD as u8,
    /// Stop the PD operation, identified by its [`Nl80211Attr::Wdev`] interface.
    StopPd = nl80211_commands::NL80211_CMD_STOP_PD as u8,
}
impl neli::consts::genl::Cmd for Nl80211Command {}

/// `nl80211` netlink attributes (`enum nl80211_attrs`)
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211Attr {
    // Unspecified attribute to catch errors.
    Unspec = nl80211_attrs::NL80211_ATTR_UNSPEC as u16,
    /// Index of wiphy to operate on.
    ///
    /// See `/sys/class/ieee80211/<phyname>/index`.
    Wiphy = nl80211_attrs::NL80211_ATTR_WIPHY as u16,
    /// Wiphy name.
    ///
    /// Can be used for renaming.
    WiphyName = nl80211_attrs::NL80211_ATTR_WIPHY_NAME as u16,
    /// Network interface index of the device to operate on.
    Ifindex = nl80211_attrs::NL80211_ATTR_IFINDEX as u16,
    /// Network interface name.
    Ifname = nl80211_attrs::NL80211_ATTR_IFNAME as u16,
    /// Type of virtual interface (see [`Nl80211Iftype`]).
    Iftype = nl80211_attrs::NL80211_ATTR_IFTYPE as u16,
    /// MAC address (various uses).
    Mac = nl80211_attrs::NL80211_ATTR_MAC as u16,
    /// Temporal key data.
    ///
    /// For TKIP this consists of 16 bytes encryption key followed by 8 bytes
    /// each for TX and RX MIC keys.
    KeyData = nl80211_attrs::NL80211_ATTR_KEY_DATA as u16,
    /// Key ID (`u8`, 0-3).
    KeyIdx = nl80211_attrs::NL80211_ATTR_KEY_IDX as u16,
    /// Key cipher suite (`u32`, as defined by IEEE 802.11 section 7.3.2.25.1, e.g. `0x000FAC04`).
    KeyCipher = nl80211_attrs::NL80211_ATTR_KEY_CIPHER as u16,
    /// Transmit key sequence number (IV/PN) for TKIP and CCMP keys, each six bytes in little endian.
    KeySeq = nl80211_attrs::NL80211_ATTR_KEY_SEQ as u16,
    /// Flag attribute indicating the key is default key.
    KeyDefault = nl80211_attrs::NL80211_ATTR_KEY_DEFAULT as u16,
    /// Beacon interval in TU.
    BeaconInterval = nl80211_attrs::NL80211_ATTR_BEACON_INTERVAL as u16,
    /// DTIM period for beaconing.
    DtimPeriod = nl80211_attrs::NL80211_ATTR_DTIM_PERIOD as u16,
    /// Portion of the beacon before the TIM IE.
    BeaconHead = nl80211_attrs::NL80211_ATTR_BEACON_HEAD as u16,
    /// Portion of the beacon after the TIM IE.
    BeaconTail = nl80211_attrs::NL80211_ATTR_BEACON_TAIL as u16,
    /// Association ID for the station (`u16`).
    StaAid = nl80211_attrs::NL80211_ATTR_STA_AID as u16,
    /// Flags, nested element with NLA_FLAG attributes of [`Nl80211StaFlags`].
    ///
    /// Deprecated, use [`Nl80211Attr::StaFlags2`].
    // TODO: Deprecate?
    StaFlags = nl80211_attrs::NL80211_ATTR_STA_FLAGS as u16,
    /// Listen interval as defined by IEEE 802.11 7.3.1.6 (`u16`).
    StaListenInterval = nl80211_attrs::NL80211_ATTR_STA_LISTEN_INTERVAL as u16,
    /// Supported rates.
    ///
    /// Array of supported rates as defined by IEEE 802.11 7.3.2.2
    /// but without the length restriction (at most [`NL80211_MAX_SUPP_RATES`]).
    StaSupportedRates = nl80211_attrs::NL80211_ATTR_STA_SUPPORTED_RATES as u16,
    /// Interface index of VLAN interface to move station to, or the AP interface the station was originally added to.
    StaVlan = nl80211_attrs::NL80211_ATTR_STA_VLAN as u16,
    /// Information about a station
    ///
    /// Part of station info given for [`Nl80211Command::GetStation`], nested attribute containing info as possible.
    ///
    /// See [`Nl80211StaInfo`].
    StaInfo = nl80211_attrs::NL80211_ATTR_STA_INFO as u16,
    /// Information about an operating bands, consisting of a nested array.
    WiphyBands = nl80211_attrs::NL80211_ATTR_WIPHY_BANDS as u16,
    /// Flags. Nested element with NLA_FLAG attributes of [`Nl80211MntrFlags`].
    MntrFlags = nl80211_attrs::NL80211_ATTR_MNTR_FLAGS as u16,
    /// Mesh ID (1-32 bytes).
    MeshId = nl80211_attrs::NL80211_ATTR_MESH_ID as u16,
    /// Action to perform on the mesh peer link (see `enum nl80211_plink_action`).
    // TODO: nl80211_plink_action
    StaPlinkAction = nl80211_attrs::NL80211_ATTR_STA_PLINK_ACTION as u16,
    /// MAC address of the next hop for a mesh path.
    MpathNextHop = nl80211_attrs::NL80211_ATTR_MPATH_NEXT_HOP as u16,
    /// Information about a mesh path.
    ///
    /// Part of mesh path info given for [`Nl80211Command::GetMpath`] nested attribute described at `enum nl80211_mpath_info`.
    // TODO: nl80211_mpath_info
    MpathInfo = nl80211_attrs::NL80211_ATTR_MPATH_INFO as u16,
    /// Whether CTS protection is enabled (`u8`, 0 or 1).
    BssCtsProt = nl80211_attrs::NL80211_ATTR_BSS_CTS_PROT as u16,
    /// Whether short preamble is enabled (`u8`, 0 or 1).
    BssShortPreamble = nl80211_attrs::NL80211_ATTR_BSS_SHORT_PREAMBLE as u16,
    /// Whether short slot time enabled (`u8`, 0 or 1).
    BssShortSlotTime = nl80211_attrs::NL80211_ATTR_BSS_SHORT_SLOT_TIME as u16,
    /// HT Capability information element (from association request when used with [`Nl80211Command::NewStation`]).
    HtCapability = nl80211_attrs::NL80211_ATTR_HT_CAPABILITY as u16,
    /// Nested attribute containing all supported interface types, each a flag attribute with the number of the interface mode.
    SupportedIftypes = nl80211_attrs::NL80211_ATTR_SUPPORTED_IFTYPES as u16,
    /// An ISO-3166-alpha2 country code for which the current regulatory domain should be set to or is already set to.
    /// For example, 'CR', for Costa Rica.
    ///
    /// This attribute is used by the kernel to query the CRDA to retrieve one regulatory domain. This attribute can also be
    /// used by user space to query the kernel for the currently set regulatory domain.
    ///
    /// We chose an alpha2 as that is also used by the IEEE-802.11 country information element to identify a country.
    /// Users can also simply ask the wireless core to set regulatory domain to a specific alpha2.
    RegAlpha2 = nl80211_attrs::NL80211_ATTR_REG_ALPHA2 as u16,
    /// A nested array of regulatory domain regulatory rules.
    RegRules = nl80211_attrs::NL80211_ATTR_REG_RULES as u16,
    /// Mesh configuration parameters.
    ///
    /// A nested attribute containing attributes from `enum nl80211_meshconf_params`.
    // TODO: nl80211_meshconf_params
    MeshConfig = nl80211_attrs::NL80211_ATTR_MESH_CONFIG as u16,
    /// Basic rates
    ///
    /// Array of basic rates in format defined by IEEE 802.11 7.3.2.2 but without the length restriction
    /// (at most [`NL80211_MAX_SUPP_RATES`]).
    BssBasicRates = nl80211_attrs::NL80211_ATTR_BSS_BASIC_RATES as u16,
    /// A nested array of TX queue parameters.
    WiphyTxqParams = nl80211_attrs::NL80211_ATTR_WIPHY_TXQ_PARAMS as u16,
    /// Frequency of the selected channel in MHz.
    ///
    /// Defines the channel together with the (deprecated) [`Nl80211Attr::WiphyChannelType`]
    /// attribute or the attributes [`Nl80211Attr::WiphyChannelType`] and if needed
    /// [`Nl80211Attr::CenterFreq1`] and [`Nl80211Attr::CenterFreq2`]
    WiphyFreq = nl80211_attrs::NL80211_ATTR_WIPHY_FREQ as u16,
    /// Included with [`Nl80211Attr::WiphyFreq`] if HT20 or HT40 are to be used
    /// (i.e., HT disabled if not included):
    ///
    /// - [`Nl80211ChannelType::NoHt`]: HT not allowed (i.e., same as not including this attribute)
    /// - [`Nl80211ChannelType::Ht20`]: HT20 only
    /// - [`Nl80211ChannelType::Ht40Minus`]: secondary channel is below the primary channel
    /// - [`Nl80211ChannelType::Ht40Plus`]: secondary channel is above the primary channel
    ///
    /// This attribute is now deprecated.
    WiphyChannelType = nl80211_attrs::NL80211_ATTR_WIPHY_CHANNEL_TYPE as u16,
    /// Flag attribute indicating the key is the default management key.
    KeyDefaultMgmt = nl80211_attrs::NL80211_ATTR_KEY_DEFAULT_MGMT as u16,
    /// Management frame subtype for [`Nl80211Command::SetMgmtExtraIe`].
    MgmtSubtype = nl80211_attrs::NL80211_ATTR_MGMT_SUBTYPE as u16,
    /// Information element(s) data (used, e.g., with [`Nl80211Command::SetMgmtExtraIe`]).
    Ie = nl80211_attrs::NL80211_ATTR_IE as u16,
    /// Number of SSIDs you can scan with a single scan request, a wiphy attribute.
    MaxNumScanSsids = nl80211_attrs::NL80211_ATTR_MAX_NUM_SCAN_SSIDS as u16,
    /// Nested attribute of frequencies (in MHz).
    ScanFrequencies = nl80211_attrs::NL80211_ATTR_SCAN_FREQUENCIES as u16,
    /// Nested attribute with SSIDs.
    ///
    /// Leave out for passive scanning and include a zero-length SSID (wildcard) for wildcard scan
    ScanSsids = nl80211_attrs::NL80211_ATTR_SCAN_SSIDS as u16,
    /// Used to indicate consistent snapshots for dumps.
    ///
    /// This number increases whenever the object list being dumped changes, and as such user space can verify that it has
    /// obtained a complete and consistent snapshot by verifying that all dump messages contain the same generation number.
    /// If it changed then the list changed and the dump should be repeated completely from scratch.
    Generation = nl80211_attrs::NL80211_ATTR_GENERATION as u16,
    /// Scan result BSS.
    Bss = nl80211_attrs::NL80211_ATTR_BSS as u16,
    /// Indicates who requested the regulatory domain currently in effect.
    ///
    /// This could be any of [`Nl80211RegInitiator`].
    RegInitiator = nl80211_attrs::NL80211_ATTR_REG_INITIATOR as u16,
    /// Indicates the type of the regulatory domain currently set.
    ///
    /// This can be one of the [`Nl80211RegType`].
    RegType = nl80211_attrs::NL80211_ATTR_REG_TYPE as u16,
    /// Wiphy attribute that specifies an array of command numbers (i.e. a mapping index to command number)
    /// that the driver for the given wiphy supports.
    SupportedCommands = nl80211_attrs::NL80211_ATTR_SUPPORTED_COMMANDS as u16,
    /// Frame data (binary attribute), including frame header and body, but not FCS.
    ///
    /// Used, for example, with [`Nl80211Command::Authenticate`] and [`Nl80211Command::Associate`] events
    Frame = nl80211_attrs::NL80211_ATTR_FRAME as u16,
    /// SSID (binary attribute, 0..32 octets)
    Ssid = nl80211_attrs::NL80211_ATTR_SSID as u16,
    /// AuthenticationType, see [`Nl80211AuthType`]. Represented as a `u32`.
    AuthType = nl80211_attrs::NL80211_ATTR_AUTH_TYPE as u16,
    /// Reason code for [`Nl80211Command::Deauthenticate`] and [`Nl80211Command::Disassociate`] (`u16`).
    ReasonCode = nl80211_attrs::NL80211_ATTR_REASON_CODE as u16,
    /// Key Type, see [`Nl80211KeyType`]. Represented as a `u32`.
    KeyType = nl80211_attrs::NL80211_ATTR_KEY_TYPE as u16,
    /// Maximum length of information elements that can be added to a scan request.
    MaxScanIeLen = nl80211_attrs::NL80211_ATTR_MAX_SCAN_IE_LEN as u16,
    /// A set of `u32` values indicating the supported cipher suites.
    CipherSuites = nl80211_attrs::NL80211_ATTR_CIPHER_SUITES as u16,
    /// A channel which has suffered a regulatory change due to considerations from a beacon hint.
    ///
    /// This attribute reflects the state of the channel *before* the beacon hint processing.
    /// This attribute consists of a nested attribute containing [`Nl80211FrequencyAttr`]
    FreqBefore = nl80211_attrs::NL80211_ATTR_FREQ_BEFORE as u16,
    /// A channel which has suffered a regulatory change due to considerations from a beacon hint.
    ///
    /// This attribute reflects the state of the channel *after* the beacon hint processing.
    /// This attribute consists of a nested attribute containing [`Nl80211FrequencyAttr`]
    FreqAfter = nl80211_attrs::NL80211_ATTR_FREQ_AFTER as u16,
    /// A flag indicating the IBSS should not try to look for other networks on different channels.
    FreqFixed = nl80211_attrs::NL80211_ATTR_FREQ_FIXED as u16,
    /// TX retry limit for frames whose length is less than or equal to the RTS threshold.
    ///
    /// Allowed range: 1..255 (`u8`). This is dot11ShortRetryLimit.
    WiphyRetryShort = nl80211_attrs::NL80211_ATTR_WIPHY_RETRY_SHORT as u16,
    /// TX retry limit for frames whose length is greater than the RTS threshold.
    ///
    /// Allowed range: 1..255 (`u8`). This is dot11LongRetryLimit.
    WiphyRetryLong = nl80211_attrs::NL80211_ATTR_WIPHY_RETRY_LONG as u16,
    /// Fragmentation threshold, i.e., maximum length in octets for frames.
    ///
    /// Allowed range: 256..8000 (`u8`). Disable fragmentation with -1 (`u32`, i.e. 4_294_967_295).
    /// This is dot11FragmentationThreshold.
    // TODO: Verify
    WiphyFragThreshold = nl80211_attrs::NL80211_ATTR_WIPHY_FRAG_THRESHOLD as u16,
    /// RTS threshold (TX frames with length larger than or equal to this use RTS/CTS handshake).
    ///
    /// Allowed range: 0..65536 (`u32`). Disable with -1 (`u32`, i.e. 4_294_967_295). This is dot11RTSThreshold.
    WiphyRtsThreshold = nl80211_attrs::NL80211_ATTR_WIPHY_RTS_THRESHOLD as u16,
    /// A flag indicating than an operation timed out.
    ///
    /// This is used, e.g., with [`Nl80211Command::Authenticate`] event.
    TimedOut = nl80211_attrs::NL80211_ATTR_TIMED_OUT as u16,
    /// Whether management frame protection (IEEE 802.11w, MFP) is used for the association ([`Nl80211Mfp`], represented as a `u32`).
    ///
    /// This attribute can be used with [`Nl80211Command::Associate`] and [`Nl80211Command::Connect`] requests.
    ///
    /// [`Nl80211Mfp::Optional`] is not allowed for [`Nl80211Command::Associate`] since user space SME is expected
    /// and hence, it must have decided whether to use management frame protection or not.
    ///
    /// Setting [`Nl80211Mfp::Optional`] with a [`Nl80211Command::Connect`] request will let the driver
    /// (or the firmware) decide whether to use MFP or not.
    UseMfp = nl80211_attrs::NL80211_ATTR_USE_MFP as u16,
    /// Attribute containing a `struct nl80211_sta_flag_update`.
    StaFlags2 = nl80211_attrs::NL80211_ATTR_STA_FLAGS2 as u16,
    /// A flag indicating whether user space controls IEEE 802.1X port, i.e., sets/clears [`Nl80211StaFlags::Authorized`],
    /// in station mode.
    ///
    /// If the flag is included in [`Nl80211Command::Associate`] request, the driver will assume that the port is
    /// unauthorized until authorized by user space. Otherwise, port is marked authorized by default in station mode.
    ControlPort = nl80211_attrs::NL80211_ATTR_CONTROL_PORT as u16,
    /// Testmode data blob, passed through to the driver.
    ///
    /// We recommend using nested, driver-specific attributes within this.
    Testdata = nl80211_attrs::NL80211_ATTR_TESTDATA as u16,
    /// Flag attribute, used with `connect()`, indicating that protected APs should be used.
    ///
    /// This is also used with [`Nl80211Command::NewBeacon`] to indicate that the BSS is to use protection.
    Privacy = nl80211_attrs::NL80211_ATTR_PRIVACY as u16,
    /// A flag indicating that the [`Nl80211Command::Disconnect`] event was due to the AP disconnecting
    /// the station, and not due to a local disconnect request.
    DisconnectedByAp = nl80211_attrs::NL80211_ATTR_DISCONNECTED_BY_AP as u16,
    /// StatusCode for the [`Nl80211Command::Connect`] event (`u16`).
    StatusCode = nl80211_attrs::NL80211_ATTR_STATUS_CODE as u16,
    /// For crypto settings for connect or other commands, indicates which pairwise cipher suites are used.
    CipherSuitesPairwise = nl80211_attrs::NL80211_ATTR_CIPHER_SUITES_PAIRWISE as u16,
    /// For crypto settings for connect or other commands, indicates which group cipher suite is used.
    CipherSuiteGroup = nl80211_attrs::NL80211_ATTR_CIPHER_SUITE_GROUP as u16,
    /// Used with [`Nl80211Command::Connect`], [`Nl80211Command::Associate`], and [`Nl80211Command::NewBeacon`]
    /// to indicate which WPA version(s) the AP we want to associate with is using.
    ///
    /// The value is a `u32` with flags from [`Nl80211WpaVersions`].
    WpaVersions = nl80211_attrs::NL80211_ATTR_WPA_VERSIONS as u16,
    /// Used with [`Nl80211Command::Connect`], [`Nl80211Command::Associate`], and [`Nl80211Command::NewBeacon`]
    /// to indicate which key management algorithm(s) to use (an array of `u32`).
    ///
    /// This attribute is also sent in response to [`Nl80211Command::GetWiphy`], indicating the supported AKM suites,
    /// intended for specific drivers which implement SME and have constraints on which AKMs are supported and also
    /// the cases where an AKM support is offloaded to the driver/firmware. If there is no such notification from the driver,
    /// user space should assume the driver supports all the AKM suites.
    AkmSuites = nl80211_attrs::NL80211_ATTR_AKM_SUITES as u16,
    /// (Re)association request information elements as sent by card, for [`Nl80211Command::Roam`] and successful
    /// [`Nl80211Command::Connect`] events.
    ReqIe = nl80211_attrs::NL80211_ATTR_REQ_IE as u16,
    /// (Re)association response information elements as sent by peer, for [`Nl80211Command::Roam`] and successful
    /// [`Nl80211Command::Connect`] events.
    RespIe = nl80211_attrs::NL80211_ATTR_RESP_IE as u16,
    /// Previous BSSID, to be used in [`Nl80211Command::Associate`] and [`Nl80211Command::Connect`] commands to
    /// specify a request to reassociate within an ESS.
    ///
    /// Rephrased, use Reassociate Request frame (with the value of this attribute in the current AP address field)
    /// instead of Association Request frame which is used for the initial association to an ESS.
    PrevBssid = nl80211_attrs::NL80211_ATTR_PREV_BSSID as u16,
    /// Key information in a nested attribute with [`Nl80211KeyMode`] sub-attributes.
    Key = nl80211_attrs::NL80211_ATTR_KEY as u16,
    /// Array of keys for static WEP keys for [`Nl80211Command::Connect`] and [`Nl80211Command::JoinIbss`].
    ///
    /// Key information is in a nested attribute each with [`Nl80211KeyMode`] sub-attributes.
    Keys = nl80211_attrs::NL80211_ATTR_KEYS as u16,
    /// Process ID of a network namespace.
    Pid = nl80211_attrs::NL80211_ATTR_PID as u16,
    /// Use 4-address frames on a virtual interface.
    _4Addr = nl80211_attrs::NL80211_ATTR_4ADDR as u16,
    /// Survey information about a channel, part of the survey response for [`Nl80211Command::GetSurvey`].
    ///
    /// Nested attribute containing info as possible.
    ///
    /// See [`Nl80211SurveyInfo`].
    SurveyInfo = nl80211_attrs::NL80211_ATTR_SURVEY_INFO as u16,
    /// PMK material for PMKSA caching.
    Pmkid = nl80211_attrs::NL80211_ATTR_PMKID as u16,
    /// Maximum number of PMKIDs a firmware can cache, a wiphy attribute.
    MaxNumPmkids = nl80211_attrs::NL80211_ATTR_MAX_NUM_PMKIDS as u16,
    /// Duration of an operation in milliseconds (`u32`).
    Duration = nl80211_attrs::NL80211_ATTR_DURATION as u16,
    /// Generic 64-bit cookie to identify objects.
    Cookie = nl80211_attrs::NL80211_ATTR_COOKIE as u16,
    /// Coverage Class as defined by IEEE 802.11 section 7.3.2.9.
    ///
    /// This is dot11CoverageClass (`u8`).
    WiphyCoverageClass = nl80211_attrs::NL80211_ATTR_WIPHY_COVERAGE_CLASS as u16,
    /// Nested set of attributes (`enum nl80211_tx_rate_attributes`) describing TX rates per band.
    ///
    /// The [`Nl80211Band`] value is used as the index (`nla_type()` of the nested data).
    /// If a band is not included, it will be configured to allow all rates based on negotiated supported
    /// rates information.
    ///
    /// This attribute is used with [`Nl80211Command::SetTxBitrateMask`] and with starting AP,
    /// and joining mesh networks (not IBSS yet). In the latter case, it must specify just a
    /// single bitrate, which is to be used for the beacon.
    ///
    /// The driver must also specify support for this with the extended features
    /// `NL80211_EXT_FEATURE_BEACON_RATE_LEGACY`, `NL80211_EXT_FEATURE_BEACON_RATE_HT`,
    /// `NL80211_EXT_FEATURE_BEACON_RATE_VHT`, `NL80211_EXT_FEATURE_BEACON_RATE_HE` and
    /// `NL80211_EXT_FEATURE_BEACON_RATE_EHT`.
    // TODO: enum nl80211_tx_rate_attributes
    // TODO: enum nl80211_ext_feature_index
    TxRates = nl80211_attrs::NL80211_ATTR_TX_RATES as u16,
    /// A binary attribute which typically must contain at least one byte.
    ///
    /// Currently used with [`Nl80211Command::RegisterFrame`].
    FrameMatch = nl80211_attrs::NL80211_ATTR_FRAME_MATCH as u16,
    /// Flag attribute indicating that the frame was acknowledged by the recipient.
    Ack = nl80211_attrs::NL80211_ATTR_ACK as u16,
    /// Powersave state, using `enum nl80211_ps_state` values.
    // TODO: enum nl80211_ps_state
    PsState = nl80211_attrs::NL80211_ATTR_PS_STATE as u16,
    /// Connection quality monitor (CQM) configuration in a nested attribute with `enum nl80211_attr_cqm` sub-attributes.
    // TODO: enum nl80211_attr_cqm
    Cqm = nl80211_attrs::NL80211_ATTR_CQM as u16,
    /// Flag attribute to indicate that a command is requesting a local authentication/association state change without
    /// invoking actual management frame exchange.
    ///
    /// This can be used with [`Nl80211Command::Authenticate`], [`Nl80211Command::Deauthenticate`], [`Nl80211Command::Disassociate`].
    LocalStateChange = nl80211_attrs::NL80211_ATTR_LOCAL_STATE_CHANGE as u16,
    /// (AP mode) Do not forward traffic between stations connected to this BSS.
    ApIsolate = nl80211_attrs::NL80211_ATTR_AP_ISOLATE as u16,
    /// Transmit power setting type.
    ///
    /// See `enum nl80211_tx_power_setting` for possible values.
    // TODO: enum nl80211_tx_power_settings
    WiphyTxPowerSetting = nl80211_attrs::NL80211_ATTR_WIPHY_TX_POWER_SETTING as u16,
    /// Transmit power level in signed mBm units.
    ///
    /// This is used in association with [`Nl80211Attr::WiphyTxPowerSetting`] for non-automatic settings.
    WiphyTxPowerLevel = nl80211_attrs::NL80211_ATTR_WIPHY_TX_POWER_LEVEL as u16,
    /// Wiphy capability attribute, which is a nested attribute of [`Nl80211Attr::FrameType`] attributes,
    /// containing information about which frame types can be transmitted with [`Nl80211Command::Frame`].
    TxFrameTypes = nl80211_attrs::NL80211_ATTR_TX_FRAME_TYPES as u16,
    /// Wiphy capability attribute, which is a nested attribute of [`Nl80211Attr::FrameType`] attributes,
    /// containing information about which frame types can be registered for RX.
    RxFrameTypes = nl80211_attrs::NL80211_ATTR_RX_FRAME_TYPES as u16,
    /// A `u16` indicating the frame type/subtype for the [`Nl80211Command::RegisterFrame`] command.
    FrameType = nl80211_attrs::NL80211_ATTR_FRAME_TYPE as u16,
    /// A 16-bit value indicating the ethertype that will be used for key negotiation.
    ///
    /// It can be specified with the associate and connect commands. If it is not specified,
    /// the value defaults to `0x888E` (PAE, 802.1X).
    ///
    /// This attribute is also used as a flag in the wiphy information to indicate that protocols other than PAE are supported.
    ControlPortEthertype = nl80211_attrs::NL80211_ATTR_CONTROL_PORT_ETHERTYPE as u16,
    /// When included along with [`Nl80211Attr::ControlPortEthertype`], indicates that the custom ethertype frames
    /// used for key negotiation must not be encrypted.
    ControlPortNoEncrypt = nl80211_attrs::NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT as u16,
    /// The device supports IBSS RSN, which mostly means support for per-station GTKs.
    SupportIbssRsn = nl80211_attrs::NL80211_ATTR_SUPPORT_IBSS_RSN as u16,
    /// Bitmap of allowed antennas for transmitting.
    ///
    /// This can be used to mask out antennas which are not attached or should not be
    /// used for transmitting. If an antenna is not selected in this bitmap the hardware
    /// is not allowed to transmit on this antenna.
    ///
    /// Each bit represents one antenna, starting with antenna 1 at the first bit.
    ///
    /// Depending on which antennas are selected in the bitmap, 802.11n drivers can derive
    /// which chainmasks to use (if all antennas belonging to a particular chain are disabled
    /// this chain should be disabled) and if a chain has diversity antennas whether diversity
    /// should be used or not.
    ///
    /// HT capabilities (STBC, TX Beamforming, Antenna selection) can be derived from the
    /// available chains after applying the antenna mask. Non-802.11n drivers can derive
    /// whether to use diversity or not.
    ///
    /// Drivers may reject configurations or RX/TX mask combinations they cannot support by
    /// returning -EINVAL.
    WiphyAntennaTx = nl80211_attrs::NL80211_ATTR_WIPHY_ANTENNA_TX as u16,
    /// Bitmap of allowed antennas for receiving.
    ///
    /// This can be used to mask out antennas which are not attached or should not be used for receiving.
    /// If an antenna is not selected in this bitmap the hardware should not be configured to receive
    /// on this antenna.
    ///
    /// For a more detailed description see [`Nl80211Attr::WiphyAntennaTx`].
    WiphyAntennaRx = nl80211_attrs::NL80211_ATTR_WIPHY_ANTENNA_RX as u16,
    /// Multicast TX rate (in 100 Kbps) for IBSS.
    McastRate = nl80211_attrs::NL80211_ATTR_MCAST_RATE as u16,
    /// For management frame TX, the frame may be transmitted on another channel when the channel
    /// given doesn't match the current channel.
    ///
    /// If the current channel doesn't match and this flag isn't set, the frame will be rejected.
    ///
    /// This is also used as an `nl80211` capability flag.
    OffchannelTxOk = nl80211_attrs::NL80211_ATTR_OFFCHANNEL_TX_OK as u16,
    /// HT operation mode (`u16`).
    BssHtOpmode = nl80211_attrs::NL80211_ATTR_BSS_HT_OPMODE as u16,
    /// A nested attribute containing flags attributes, specifying what a key should be set as default as.
    ///
    /// See `enum nl80211_key_default_types`.
    // TODO: enum nl80211_key_default_types
    KeyDefaultTypes = nl80211_attrs::NL80211_ATTR_KEY_DEFAULT_TYPES as u16,
    /// Device attribute that specifies the maximum duration that can be requested with the
    /// remain-on-channel operation, in milliseconds, `u32`.
    MaxRemainOnChannelDuration = nl80211_attrs::NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION as u16,
    /// Optional mesh setup parameters.
    ///
    /// These cannot be changed once the mesh is active.
    MeshSetup = nl80211_attrs::NL80211_ATTR_MESH_SETUP as u16,
    /// Bitmap of antennas which are available for configuration as TX antennas via [`Nl80211Attr::WiphyAntennaTx`].
    WiphyAntennaAvailTx = nl80211_attrs::NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX as u16,
    /// Bitmap of antennas which are available for configuration as RX antennas via [`Nl80211Attr::WiphyAntennaRx`].
    WiphyAntennaAvailRx = nl80211_attrs::NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX as u16,
    /// Currently, this means the underlying driver allows Authentication frames in a mesh to be passed
    /// to user space for processing via the `NL80211_MESH_SETUP_USERSPACE_AUTH` flag.
    // TODO: enum nl80211_mesh_setup_params
    SupportMeshAuth = nl80211_attrs::NL80211_ATTR_SUPPORT_MESH_AUTH as u16,
    /// The state of a mesh peer link as defined in `enum nl80211_plink_state`.
    ///
    /// Used when user space is driving the peer link management state machine.
    ///
    /// `NL80211_MESH_SETUP_USERSPACE_AMPE` or `NL80211_MESH_SETUP_USERSPACE_MPM` must be enabled.
    // TODO: enum nl80211_mesh_setup_params
    StaPlinkState = nl80211_attrs::NL80211_ATTR_STA_PLINK_STATE as u16,
    /// Used by [`Nl80211Command::SetWowlan`] to indicate which WoW triggers should be enabled.
    ///
    /// This is also used by [`Nl80211Command::GetWowlan`] to get the currently enabled WoWLAN triggers.
    WowlanTriggers = nl80211_attrs::NL80211_ATTR_WOWLAN_TRIGGERS as u16,
    /// Indicates, as part of the wiphy capabilities, the supported WoWLAN triggers
    WowlanTriggersSupported = nl80211_attrs::NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED as u16,
    /// Interval between scheduled scan cycles, in milliseconds.
    SchedScanInterval = nl80211_attrs::NL80211_ATTR_SCHED_SCAN_INTERVAL as u16,
    /// Nested attribute listing the supported interface combinations.
    ///
    /// In each nested item, it contains attributes defined in `enum nl80211_if_combination_attrs`.
    ///
    /// If the wiphy uses multiple radios ([`Nl80211Attr::WiphyRadios`] is set), this attribute
    /// contains the interface combinations of the first radio.
    ///
    /// See [`Nl80211Attr::WiphyInterfaceCombinations`] for the global wiphy combinations for the sum of all radios.
    InterfaceCombinations = nl80211_attrs::NL80211_ATTR_INTERFACE_COMBINATIONS as u16,
    /// Nested attribute (just like [`Nl80211Attr::SupportedIftypes`]) containing the interface types that
    /// are managed in software: interfaces of these types aren't subject to any restrictions in their number or combinations.
    SoftwareIftypes = nl80211_attrs::NL80211_ATTR_SOFTWARE_IFTYPES as u16,
    /// Nested attribute containing the information necessary for GTK rekeying in the device.
    ///
    /// See `enum nl80211_rekey_data`.
    // TODO: enum nl80211_rekey_data
    RekeyData = nl80211_attrs::NL80211_ATTR_REKEY_DATA as u16,
    /// Number of SSIDs you can scan with a single scheduled scan request, a wiphy attribute.
    MaxNumSchedScanSsids = nl80211_attrs::NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS as u16,
    /// Maximum length of information elements that can be added to a scheduled scan request.
    MaxSchedScanIeLen = nl80211_attrs::NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN as u16,
    /// Rates to be advertised as supported in scan.
    ///
    /// Nested array attribute containing an entry for each band, with the entry being a list of supported rates
    /// as defined by IEEE 802.11 7.3.2.2 but without the length restriction (at most [`NL80211_MAX_SUPP_RATES`]).
    ScanSuppRates = nl80211_attrs::NL80211_ATTR_SCAN_SUPP_RATES as u16,
    /// Indicates whether SSID is to be hidden from Beacon and Probe Response (when response to wildcard Probe Request).
    ///
    /// See `enum nl80211_hidden_ssid`, represented as a `u32`.
    // TODO: enum nl80211_hidden_ssid
    HiddenSsid = nl80211_attrs::NL80211_ATTR_HIDDEN_SSID as u16,
    /// Information element(s) for Probe Response frame.
    ///
    /// This is used with [`Nl80211Command::NewBeacon`] and [`Nl80211Command::SetBeacon`] to provide extra IEs (e.g., WPS/P2P IE)
    /// into Probe Response frames when the driver (or firmware) replies to Probe Request frames.
    IeProbeResp = nl80211_attrs::NL80211_ATTR_IE_PROBE_RESP as u16,
    /// Information element(s) for (Re)Association Response frame.
    ///
    /// This is used with [`Nl80211Command::NewBeacon`] and [`Nl80211Command::SetBeacon`] to provide extra IEs (e.g., WPS/P2P IE)
    /// into (Re)Association Response frames when the driver (or firmware) replies to (Re)Association Request frames.
    IeAssocResp = nl80211_attrs::NL80211_ATTR_IE_ASSOC_RESP as u16,
    /// Nested attribute containing the Wireless Multimedia Extensions (WME) configuration of the station.
    ///
    /// See `enum nl80211_sta_wme_attr`.
    // TODO: enum nl80211_sta_wme_attr
    StaWme = nl80211_attrs::NL80211_ATTR_STA_WME as u16,
    /// The device supports UAPSD when working as AP.
    SupportApUapsd = nl80211_attrs::NL80211_ATTR_SUPPORT_AP_UAPSD as u16,
    /// Indicates whether the firmware is capable of roaming to another AP in the same ESS if the signal lever is low.
    RoamSupport = nl80211_attrs::NL80211_ATTR_ROAM_SUPPORT as u16,
    /// Nested attribute with one or more sets of attributes to match during scheduled scans.
    /// Only BSSs that match any of the sets will be reported.
    ///
    /// These are pass-thru filter rules. For a match to succeed, the BSS must match all attributes of a set.
    ///
    /// Since not every hardware supports matching all types of attributes, there is no guarantee that the reported BSSs are
    /// fully complying with the match sets and userspace needs to be able to ignore them by itself. Thus, the implementation
    /// is somewhat hardware-dependent, but this is only an optimization and the userspace application needs to handle all the
    /// non-filtered results anyway.
    ///
    /// If the match attributes don't make sense when combined with the values passed in [`Nl80211Attr::ScanSsids`]
    /// (e.g. if an SSID is included in the probe request, but the match attributes will never let it go through),
    /// -EINVAL may be returned.
    ///
    /// If omitted, no filtering is done.
    SchedScanMatch = nl80211_attrs::NL80211_ATTR_SCHED_SCAN_MATCH as u16,
    /// Maximum number of sets that can be used with [`Nl80211Attr::SchedScanMatch`], a wiphy attribute.
    MaxMatchSets = nl80211_attrs::NL80211_ATTR_MAX_MATCH_SETS as u16,
    /// Nested attribute containing the PMKSA caching candidate information.
    ///
    /// See `enum nl80211_pmksa_candidate_attr`.
    // TODO: enum nl80211_pmksa_candidate_attr
    PmksaCandidate = nl80211_attrs::NL80211_ATTR_PMKSA_CANDIDATE as u16,
    /// Indicates whether to use CCK rate or not for management frame transmission.
    ///
    /// In order to avoid P2P probe/action frames are being transmitted at CCK rate in 2 GHz band, user space
    /// applications use this attribute.
    ///
    /// This attribute is used with [`Nl80211Command::TriggerScan`] and [`Nl80211Command::Frame`] commands.
    TxNoCckRate = nl80211_attrs::NL80211_ATTR_TX_NO_CCK_RATE as u16,
    /// Low level TDLS action code (e.g. link setup request, link setup confirm, link teardown, etc.).
    ///
    /// Values are described in the TDLS (802.11z) specification.
    TdlsAction = nl80211_attrs::NL80211_ATTR_TDLS_ACTION as u16,
    /// Non-zero token for uniquely identifying a TDLS conversation between two devices.
    TdlsDialogToken = nl80211_attrs::NL80211_ATTR_TDLS_DIALOG_TOKEN as u16,
    /// High level TDLS operation; see [`Nl80211TdlsOperation`], represented as a `u8`.
    TdlsOperation = nl80211_attrs::NL80211_ATTR_TDLS_OPERATION as u16,
    /// A flag indicating the device can operate as a TDLS peer STA.
    TdlsSupport = nl80211_attrs::NL80211_ATTR_TDLS_SUPPORT as u16,
    /// The TDLS discovery/setup and teardown procedures should be performed by sending TDLS packets via
    /// [`Nl80211Command::TdlsMgmt`]. Otherwise, [`Nl80211Command::TdlsOper`] should be used for asking
    /// the driver to perform a TDLS operation.
    TdlsExternalSetup = nl80211_attrs::NL80211_ATTR_TDLS_EXTERNAL_SETUP as u16,
    /// This `u32` attribute may be listed for devices that have AP support to indicate that they have the
    /// AP SME integrated with support for the features listed in this attribute.
    ///
    /// See `enum nl80211_ap_sme_features`.
    // TODO: enum nl80211_ap_sme_features
    DeviceApSme = nl80211_attrs::NL80211_ATTR_DEVICE_AP_SME as u16,
    /// Used with [`Nl80211Command::Frame`]. This tells the driver to not wait for an acknowledgement.
    ///
    /// Note that due to this, it will also not give a status callback nor return a cookie. This is mostly
    /// useful for probe responses to save airtime.
    DontWaitForAck = nl80211_attrs::NL80211_ATTR_DONT_WAIT_FOR_ACK as u16,
    /// This `u32` attribute contains flags from `enum nl80211_feature_flags` and is advertised in wiphy information.
    FeatureFlags = nl80211_attrs::NL80211_ATTR_FEATURE_FLAGS as u16,
    /// Indicates that the HW responds to probe requests while operating in AP-mode.
    ///
    /// This attribute holds a bitmap of the supported protocols for offloading.
    ///
    /// See `enum nl80211_probe_resp_offload_support_attr`.
    // TODO: enum nl80211_probe_resp_offload_support_attr
    ProbeRespOffload = nl80211_attrs::NL80211_ATTR_PROBE_RESP_OFFLOAD as u16,
    /// Probe Response template data.
    ///
    /// Contains the entire Probe Response frame. The DA field in the 802.11 header is zero-ed out, to be filled by the FW.
    ProbeResp = nl80211_attrs::NL80211_ATTR_PROBE_RESP as u16,
    /// Region for regulatory rules which this country abides to when initiating radiation on DFS channels.
    ///
    /// A country maps to one DFS region.
    DfsRegion = nl80211_attrs::NL80211_ATTR_DFS_REGION as u16,
    /// Force HT capable interfaces to disable this feature during association.
    ///
    /// This is a flag attribute. Currently only supported in `mac80211` drivers.
    DisableHt = nl80211_attrs::NL80211_ATTR_DISABLE_HT as u16,
    /// Specify which bits of the [`Nl80211Attr::HtCapability`] to which attention should be paid.
    ///
    /// Currently, only `mac80211` NICs support this feature.
    ///
    /// The values that may be configured are:
    /// - MCS rates
    /// - MAX-AMSDU
    /// - HT-20-40
    /// - HT_CAP_SGI_40
    /// - AMPDU density
    /// - AMPDU factor
    ///
    /// All values are treated as suggestions and may be ignored by the driver as required. The actual values
    /// may be seen in the station debugfs ht_caps file (e.g. `/sys/kernel/debug/ieee80211/<wiphy>/netdev\:<vif>/stations/ht_caps`).
    HtCapabilityMask = nl80211_attrs::NL80211_ATTR_HT_CAPABILITY_MASK as u16,
    /// This `u16` bitmap that contains the No Ack Policy of up to 16 TIDs.
    NoackMap = nl80211_attrs::NL80211_ATTR_NOACK_MAP as u16,
    /// Timeout value in seconds.
    ///
    /// This can be used by the drivers which has MLME in firmware and do not have support to report
    /// per-station TX/RX activity to free up the station entry from the list.
    ///
    /// This needs to be used when the driver advertises the capability to timeout the stations.
    InactivityTimeout = nl80211_attrs::NL80211_ATTR_INACTIVITY_TIMEOUT as u16,
    /// Signal strength in dBm (as a 32-bit int).
    ///
    /// This attribute is (depending on the driver capabilities) added to received frames indicated with
    /// [`Nl80211Command::Frame`].
    RxSignalDbm = nl80211_attrs::NL80211_ATTR_RX_SIGNAL_DBM as u16,
    /// Background scan period in seconds or 0 to disable background scan.
    BgScanPeriod = nl80211_attrs::NL80211_ATTR_BG_SCAN_PERIOD as u16,
    /// Wireless device identifier, used for pseudo-devices that don't have a netdev (`u64`).
    Wdev = nl80211_attrs::NL80211_ATTR_WDEV as u16,
    /// Type of regulatory hint passed from user space.
    ///
    /// If unset it is assumed the hint comes directly from a user. If set, code could specify exactly
    /// what type of source was used to provide the hint.
    ///
    /// For the different types of allowed user regulatory hints see `enum nl80211_user_reg_hint_type`.
    // TODO: enum nl80211_user_reg_hint_type
    UserRegHintType = nl80211_attrs::NL80211_ATTR_USER_REG_HINT_TYPE as u16,
    /// The reason for which AP has rejected the connection request from a station.
    ///
    /// See `enum nl80211_connect_failed_reason`.
    // TODO: enum nl80211_connect_failed_reason
    ConnFailedReason = nl80211_attrs::NL80211_ATTR_CONN_FAILED_REASON as u16,
    /// Fields and elements in Authentication frames.
    ///
    /// This contains the authentication frame body (non-IE and IE data), excluding the Authentication
    /// algorithm number, i.e., starting at the Authentication transaction sequence number field. It is used
    /// with authentication algorithms that need special fields to be added into the frames (SAE and FILS).
    ///
    /// Currently, only the SAE cases use the initial two fields (Authentication transaction
    /// sequence number and Status code). However, those fields are included in the attribute data
    /// for all authentication algorithms to keep the attribute definition consistent.
    AuthData = nl80211_attrs::NL80211_ATTR_AUTH_DATA as u16,
    /// VHT Capability information element (from Association Request when used with [`Nl80211Command::NewStation`]).
    VhtCapability = nl80211_attrs::NL80211_ATTR_VHT_CAPABILITY as u16,
    /// Scan request control flags (`u32`).
    // TODO: Add reference to scan flags enum nl80211_scan_flags
    ScanFlags = nl80211_attrs::NL80211_ATTR_SCAN_FLAGS as u16,
    /// A `u32` attribute containing one of the values of [`Nl80211ChanWidth`], describing the channel width.
    ///
    /// See [`Nl80211ChanWidth`].
    ChannelWidth = nl80211_attrs::NL80211_ATTR_CHANNEL_WIDTH as u16,
    /// Center frequency of the first part of the channel, used for anything but 20 MHz bandwidth.
    ///
    /// In S1G this is the operating channel center frequency.
    CenterFreq1 = nl80211_attrs::NL80211_ATTR_CENTER_FREQ1 as u16,
    /// Center frequency of the second part of the channel, only used for 80+80 MHz bandwidth.
    CenterFreq2 = nl80211_attrs::NL80211_ATTR_CENTER_FREQ2 as u16,
    /// P2P GO Client Traffic Window (`u8`).
    ///
    /// Used with the [`Nl80211Command::StartAp`] and [`Nl80211Command::SetBss`] commands
    P2pCtwindow = nl80211_attrs::NL80211_ATTR_P2P_CTWINDOW as u16,
    /// P2P GO opportunistic PS (`u8`).
    ///
    /// Used with the [`Nl80211Command::StartAp`] and [`Nl80211Command::SetBss`] commands
    ///
    /// This can have the values 0 or 1. If not given in [`Nl80211Command::StartAp`], 0 is assumed.
    /// If not given in [`Nl80211Command::SetBss`], no change is made.
    P2pOppps = nl80211_attrs::NL80211_ATTR_P2P_OPPPS as u16,
    /// Local mesh STA link-specific power mode defined in `enum nl80211_mesh_power_mode`.
    // TODO: enum nl80211_mesh_power_mode
    LocalMeshPowerMode = nl80211_attrs::NL80211_ATTR_LOCAL_MESH_POWER_MODE as u16,
    /// ACL policy, carried in a `u32` attribute.
    ///
    /// See `enum nl80211_acl_policy`.
    // TODO: enum nl80211_acl_policy
    AclPolicy = nl80211_attrs::NL80211_ATTR_ACL_POLICY as u16,
    /// Array of nested MAC addresses, used for MAC ACL.
    MacAddrs = nl80211_attrs::NL80211_ATTR_MAC_ADDRS as u16,
    /// `u32` attribute to advertise the maximum number of MAC addresses that a device can
    /// support for MAC ACL.
    MacAclMax = nl80211_attrs::NL80211_ATTR_MAC_ACL_MAX as u16,
    /// Type of radar event for notification to user space, contains a value of `enum nl80211_radar_event` (`u32`).
    // TODO: enum nl80211_radar_event
    RadarEvent = nl80211_attrs::NL80211_ATTR_RADAR_EVENT as u16,
    /// 802.11 extended capabilities that the kernel driver has and handles.
    ///
    /// The format is the same as the IE contents. See 802.11-2012 8.4.2.29 for more information.
    ExtCapa = nl80211_attrs::NL80211_ATTR_EXT_CAPA as u16,
    /// Extended capabilities that the kernel driver has set in the [`Nl80211Attr::ExtCapa`] value, for multibit fields.
    ExtCapaMask = nl80211_attrs::NL80211_ATTR_EXT_CAPA_MASK as u16,
    /// Station capabilities (`u16`) are advertised to the driver, e.g., to enable TDLS power save (PU-APSD).
    StaCapability = nl80211_attrs::NL80211_ATTR_STA_CAPABILITY as u16,
    /// Station extended capabilities are advertised to the driver, e.g., to enable TDLS off channel operations and PU-APSD.
    StaExtCapability = nl80211_attrs::NL80211_ATTR_STA_EXT_CAPABILITY as u16,
    /// Global `nl80211` feature flags. The attribute is a `u32`.
    ///
    /// See `enum nl80211_protocol_features`.
    // TODO: enum nl80211_protocol_features
    ProtocolFeatures = nl80211_attrs::NL80211_ATTR_PROTOCOL_FEATURES as u16,
    /// Flag attribute indicating user space supports receiving the data for a single wiphy split across multiple messages,
    /// given with wiphy dump message.
    SplitWiphyDump = nl80211_attrs::NL80211_ATTR_SPLIT_WIPHY_DUMP as u16,
    /// Force VHT capable interfaces to disable this feature during association.
    ///
    /// This is a flag attribute. Currently only supported in `mac80211` drivers.
    DisableVht = nl80211_attrs::NL80211_ATTR_DISABLE_VHT as u16,
    /// Specify which bits of the [`Nl80211Attr::VhtCapability`] to which attention should be paid.
    ///
    /// Currently, only `mac80211` NICs support this feature.
    ///
    /// All values are treated as suggestions and may be ignored by the driver as required.
    /// The actual values may be seen in the station debugfs vht_caps file.
    VhtCapabilityMask = nl80211_attrs::NL80211_ATTR_VHT_CAPABILITY_MASK as u16,
    /// Mobility Domain Identifier.
    Mdid = nl80211_attrs::NL80211_ATTR_MDID as u16,
    /// Resource Information Container Information Element.
    IeRic = nl80211_attrs::NL80211_ATTR_IE_RIC as u16,
    /// Critical protocol identifier requiring increased reliability (`u16`).
    ///
    /// See `enum nl80211_crit_proto_id`.
    // TODO: enum nl80211_crit_proto_id
    CritProtId = nl80211_attrs::NL80211_ATTR_CRIT_PROT_ID as u16,
    /// Duration in milliseconds in which the connection should have increased reliability (`u16`).
    MaxCritProtDuration = nl80211_attrs::NL80211_ATTR_MAX_CRIT_PROT_DURATION as u16,
    /// Association ID (AID) for the peer TDLS station (`u16`).
    ///
    /// This is similar to [`Nl80211Attr::StaAid`] but with a difference of being allowed to be used
    /// with the first [`Nl80211Command::SetStation`] command to update a TDLS peer STA entry.
    ///
    /// For S1G interfaces, this is limited to 1600 for the current `mac80211` implementation.
    PeerAid = nl80211_attrs::NL80211_ATTR_PEER_AID as u16,
    /// Coalesce rule information.
    CoalesceRule = nl80211_attrs::NL80211_ATTR_COALESCE_RULE as u16,
    /// `u32` attribute specifying the number of TBTT's until the channel switch event.
    ChSwitchCount = nl80211_attrs::NL80211_ATTR_CH_SWITCH_COUNT as u16,
    /// Flag attribute specifying that transmission must be blocked on the current channel
    /// (before the channel switch operation).
    ///
    /// Also included in the channel switch started event if quiet was requested by the AP.
    ChSwitchBlockTx = nl80211_attrs::NL80211_ATTR_CH_SWITCH_BLOCK_TX as u16,
    /// Nested set of attributes containing the IE information for the time while performing a channel switch.
    CsaIes = nl80211_attrs::NL80211_ATTR_CSA_IES as u16,
    /// An array of offsets (`u16`) to the channel switch or color change counters in the beacons tail
    /// ([`Nl80211Attr::BeaconTail`]).
    CntdwnOffsBeacon = nl80211_attrs::NL80211_ATTR_CNTDWN_OFFS_BEACON as u16,
    /// An array of offsets (`u16`) to the channel switch or color change counters in the probe response
    /// ([`Nl80211Attr::ProbeResp`]).
    CntdwnOffsPresp = nl80211_attrs::NL80211_ATTR_CNTDWN_OFFS_PRESP as u16,
    /// Flags for `nl80211_send_mgmt()` (`u32`). As specified in the `enum nl80211_rxmgmt_flags`.
    // TODO: enum nl80211_rxmgmt_flags
    RxmgmtFlags = nl80211_attrs::NL80211_ATTR_RXMGMT_FLAGS as u16,
    /// Array of supported channels.
    StaSupportedChannels = nl80211_attrs::NL80211_ATTR_STA_SUPPORTED_CHANNELS as u16,
    /// Array of supported operating classes.
    StaSupportedOperClasses = nl80211_attrs::NL80211_ATTR_STA_SUPPORTED_OPER_CLASSES as u16,
    /// A flag indicating whether user space controls DFS operation in IBSS mode.
    ///
    /// If the flag is included in [`Nl80211Command::JoinIbss`] request, the driver will allow
    /// use of DFS channels and reports radar events to user space.
    ///
    /// User space is required to react to radar events, e.g. initiate a channel switch or
    /// leave the IBSS network.
    HandleDfs = nl80211_attrs::NL80211_ATTR_HANDLE_DFS as u16,
    /// A flag indicating that the device supports 5 MHz channel bandwidth.
    // TODO: Deprecate? Support was removed in v7.0/v7.1
    Support5Mhz = nl80211_attrs::NL80211_ATTR_SUPPORT_5_MHZ as u16,
    /// A flag indicating that the device supports 10 MHz channel bandwidth.
    // TODO: Deprecate? Support was removed in v7.0/v7.1
    Support10Mhz = nl80211_attrs::NL80211_ATTR_SUPPORT_10_MHZ as u16,
    /// Operating mode field from Operating Mode Notification Element based on
    /// Association Request when used with [`Nl80211Command::NewStation`] or
    /// [`Nl80211Command::SetStation`] (only when `NL80211_FEATURE_FULL_AP_CLIENT_STATE`
    /// is supported or with TDLS).
    ///
    /// `u8` attribute.
    // TODO: enum nl80211_feature_flags
    OpmodeNotif = nl80211_attrs::NL80211_ATTR_OPMODE_NOTIF as u16,
    /// The vendor ID, either a 24-bit OUI or, if [`NL80211_VENDOR_ID_IS_LINUX`] is set,
    /// a special Linux ID (not used yet)
    VendorId = nl80211_attrs::NL80211_ATTR_VENDOR_ID as u16,
    /// Vendor sub-command.
    VendorSubcmd = nl80211_attrs::NL80211_ATTR_VENDOR_SUBCMD as u16,
    /// Data for the vendor command, if any; this attribute is also used for vendor command feature advertisement.
    VendorData = nl80211_attrs::NL80211_ATTR_VENDOR_DATA as u16,
    /// Used for event list advertising in the wiphy info, containing a nested array of possible events.
    VendorEvents = nl80211_attrs::NL80211_ATTR_VENDOR_EVENTS as u16,
    /// IP DSCP mapping for Interworking QoS mapping.
    ///
    /// This data is in the format defined for the payload of the QoS Map Set information element in
    /// IEEE Std 802.11-2012, 8.4.2.97.
    QosMap = nl80211_attrs::NL80211_ATTR_QOS_MAP as u16,
    /// MAC address recommendation as initial BSS.
    MacHint = nl80211_attrs::NL80211_ATTR_MAC_HINT as u16,
    /// Frequency of the recommended initial BSS.
    WiphyFreqHint = nl80211_attrs::NL80211_ATTR_WIPHY_FREQ_HINT as u16,
    /// Device attribute that indicates how many associated stations are supported in AP mode (including P2P GO); `u32`.
    ///
    /// Since drivers may not have a fixed limit on the maximum number (e.g. other concurrent
    /// operations may affect this), drivers are allowed to advertise values that cannot always
    /// be met. In such cases, an attempt to add a new station entry with [`Nl80211Command::NewStation`]
    /// may fail.
    MaxApAssocSta = nl80211_attrs::NL80211_ATTR_MAX_AP_ASSOC_STA as u16,
    /// Flags for TDLS peer capabilities (`u32`).
    ///
    /// As specified in the `enum nl80211_tdls_peer_capability`.
    // TODO: enum nl80211_tdls_peer_capability
    TdlsPeerCapability = nl80211_attrs::NL80211_ATTR_TDLS_PEER_CAPABILITY as u16,
    /// Flag attribute.
    ///
    /// If set during interface creation, then the new interface will be owned by
    /// the netlink socket that created it and will be destroyed when the socket is closed.
    ///
    /// If set during scheduled scan start, then the new scan request will be owned by the netlink socket
    /// that created it and the scheduled scan will be stopped when the socket is closed.
    ///
    /// If set during configuration of regulatory indoor operation, then the regulatory indoor
    /// configuration would be owned by the netlink socket that configured the indoor setting,
    /// and the indoor operation would be cleared when the socket is closed.
    ///
    /// If set during NAN interface creation, the interface will be destroyed if the socket is
    /// closed just like any other interface. Moreover, NAN notifications will be sent in unicast
    /// to that socket. Without this attribute, the notifications will be sent to the [`NL80211_MULTICAST_GROUP_NAN`]
    /// multicast group.
    ///
    /// If set during [`Nl80211Command::Associate`] or [`Nl80211Command::Connect`], the station will
    /// deauthenticate when the socket is closed.
    ///
    /// If set during [`Nl80211Command::JoinIbss`], the IBSS will be automatically torn down when the socket is closed.
    ///
    /// If set during [`Nl80211Command::JoinMesh`], the mesh setup will be automatically torn down when the socket is closed.
    ///
    /// If set during [`Nl80211Command::StartAp`], the AP will be automatically disabled when the socket is closed.
    SocketOwner = nl80211_attrs::NL80211_ATTR_SOCKET_OWNER as u16,
    /// An array of CSA counter offsets (`u16`) which should be updated when the frame is transmitted.
    CsaCOffsetsTx = nl80211_attrs::NL80211_ATTR_CSA_C_OFFSETS_TX as u16,
    /// `u8` attribute used to advertise the maximum supported number of CSA counters.
    MaxCsaCounters = nl80211_attrs::NL80211_ATTR_MAX_CSA_COUNTERS as u16,
    /// Flag attribute indicating the current end is the TDLS link initiator.
    TdlsInitiator = nl80211_attrs::NL80211_ATTR_TDLS_INITIATOR as u16,
    /// Flag for indicating whether the current connection shall support Radio Resource Measurements (802.11k).
    ///
    /// This attribute can be used with [`Nl80211Command::Associate`] and [`Nl80211Command::Connect`] requests.
    ///
    /// User space applications are expected to use this flag only if the underlying device supports
    /// these minimal RRM features: `NL80211_FEATURE_DS_PARAM_SET_IE_IN_PROBES` and `NL80211_FEATURE_QUIET`.
    /// Or, if global RRM is supported, see `NL80211_EXT_FEATURE_RRM`.
    ///
    /// If this flag is used, driver must add the Power Capabilities IE to the Association Request.
    /// In addition, it must also set the RRM capability flag in the Association Request's Capability
    /// Info field.
    // TODO: enum nl80211_feature_index
    // TODO: enum nl80211_ext_feature_index
    UseRrm = nl80211_attrs::NL80211_ATTR_USE_RRM as u16,
    /// Flag attribute used to enable ACK timeout estimation algorithm (dynack).
    ///
    /// In order to activate dynack `NL80211_FEATURE_ACKTO_ESTIMATION` feature flag must be set
    /// by lower drivers to indicate dynack capability.
    ///
    /// Dynack is automatically disabled setting valid value for coverage class.
    // TODO: enum nl80211_feature_flags
    WiphyDynAck = nl80211_attrs::NL80211_ATTR_WIPHY_DYN_ACK as u16,
    /// A TSID value (`u8`).
    Tsid = nl80211_attrs::NL80211_ATTR_TSID as u16,
    /// User priority value (`u8`).
    UserPrio = nl80211_attrs::NL80211_ATTR_USER_PRIO as u16,
    /// Admitted time in units of 32 microseconds (per second) (`u16`).
    AdmittedTime = nl80211_attrs::NL80211_ATTR_ADMITTED_TIME as u16,
    /// SMPS mode to use (AP mode).
    ///
    /// See `enum nl80211_smps_mode`.
    // TODO: enum nl80211_smps_mode
    SmpsMode = nl80211_attrs::NL80211_ATTR_SMPS_MODE as u16,
    /// Operating class.
    OperClass = nl80211_attrs::NL80211_ATTR_OPER_CLASS as u16,
    /// MAC address mask.
    MacMask = nl80211_attrs::NL80211_ATTR_MAC_MASK as u16,
    /// Flag attribute indicating this device is self-managing its regulatory information
    /// and any regulatory domain obtained from it is coming from the device's wiphy and
    /// not the global `cfg80211` regdomain.
    WiphySelfManagedReg = nl80211_attrs::NL80211_ATTR_WIPHY_SELF_MANAGED_REG as u16,
    /// Extended feature flags contained in a byte array.
    ///
    /// The feature flags are identified by their bit index (see `enum nl80211_ext_feature_index`).
    /// The bit index is ordered starting at the least-significant bit of the first byte in the array,
    /// i.e. bit index 0 is located at bit 0 of byte 0. bit index 25 would be located at bit 1 of byte 3
    /// (`u8` array).
    // TODO: enum nl80211_ext_feature_index
    ExtFeatures = nl80211_attrs::NL80211_ATTR_EXT_FEATURES as u16,
    /// Request overall radio statistics to be returned along with other survey data.
    ///
    /// If set, [`Nl80211Command::GetSurvey`] may return a survey entry without a channel indicating
    /// global radio statistics (only some values are valid and make sense).
    ///
    /// For devices that don't return such an entry even then, the information should be contained in
    /// the result as the sum of the respective counters over all channels.
    SurveyRadioStats = nl80211_attrs::NL80211_ATTR_SURVEY_RADIO_STATS as u16,
    /// File descriptor of a network namespace.
    NetnsFd = nl80211_attrs::NL80211_ATTR_NETNS_FD as u16,
    /// Delay before the first cycle of a scheduled scan is started.
    ///
    /// Alternatively, the delay before a WoWLAN net-detect scan is started, counting from the moment
    /// the system is suspended.
    ///
    /// This value is a `u32`, in seconds.
    SchedScanDelay = nl80211_attrs::NL80211_ATTR_SCHED_SCAN_DELAY as u16,
    /// Flag attribute, if set indicates that the device is operating in an indoor environment.
    RegIndoor = nl80211_attrs::NL80211_ATTR_REG_INDOOR as u16,
    /// Maximum number of scan plans for scheduled scan supported by the device (`u32`), a wiphy attribute.
    MaxNumSchedScanPlans = nl80211_attrs::NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS as u16,
    /// Maximum interval (in seconds) for a scan plan (`u32`), a wiphy attribute.
    MaxScanPlanInterval = nl80211_attrs::NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL as u16,
    /// Maximum number of iterations in a scan plan (`u32`), a wiphy attribute.
    MaxScanPlanIterations = nl80211_attrs::NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS as u16,
    /// Maximum number of scan plans for scheduled scan supported by the device (`u32`), a wiphy attribute.
    SchedScanPlans = nl80211_attrs::NL80211_ATTR_SCHED_SCAN_PLANS as u16,
    /// Flag attribute. If set it means operate in a PBSS.
    ///
    /// Specified in [`Nl80211Command::Connect`] to request connecting to a PCP, and in [`Nl80211Command::StartAp`]
    /// to start a PCP instead of AP.
    ///
    /// Relevant for DMG networks only.
    Pbss = nl80211_attrs::NL80211_ATTR_PBSS as u16,
    /// Nested attribute for driver supporting the BSS selection feature.
    ///
    /// When used with [`Nl80211Command::GetWiphy`] it contains attributes according `enum nl80211_bss_select_attr`
    /// to indicate what BSS selection behaviours are supported.
    ///
    /// When used with [`Nl80211Command::Connect`], it contains the behaviour-specific attribute containing
    /// the parameters for BSS selection to be done by driver and/or firmware.
    // TODO: enum nl80211_bss_select_attrs
    BssSelect = nl80211_attrs::NL80211_ATTR_BSS_SELECT as u16,
    /// Whether P2P power save (PS) mechanism supported or not.
    ///
    /// `u8`, one of the values of `enum nl80211_sta_p2p_ps_status`.
    // TODO: enum nl80211_sta_p2p_ps_status
    StaSupportP2pPs = nl80211_attrs::NL80211_ATTR_STA_SUPPORT_P2P_PS as u16,
    /// Attribute used for padding for 64-bit alignment.
    Pad = nl80211_attrs::NL80211_ATTR_PAD as u16,
    /// Nested attribute of the following attributes to specify the extended capabilities and
    /// other interface-type specific capabilities per interface type:
    /// - [`Nl80211Attr::Iftype`]
    /// - [`Nl80211Attr::ExtCapa`]
    /// - [`Nl80211Attr::ExtCapaMask`]
    ///
    /// For MLO, [`Nl80211Attr::EmlCapability`] and [`Nl80211Attr::MldCapaAndOps`] are present.
    IftypeExtCapa = nl80211_attrs::NL80211_ATTR_IFTYPE_EXT_CAPA as u16,
    /// Array of 24 bytes that defines a MU-MIMO groupID for monitor mode.
    ///
    /// The first 8 bytes are a mask that defines the membership in each group (there are 64 groups,
    /// group 0 and 63 are reserved), each bit represents a group and set to 1 for being a member in
    /// that group and 0 for not being a member.
    ///
    /// The remaining 16 bytes define the position in each group, 2 bits for each group (smaller group
    /// numbers represented on most significant bits and bigger group numbers on least significant bits.)
    ///
    /// This attribute is used only if all interfaces are in monitor mode.
    ///
    /// Set this attribute in order to monitor packets using the given MU-MIMO groupID data. To turn off this
    /// feature set all the bits of the groupID to zero.
    MuMimoGroupData = nl80211_attrs::NL80211_ATTR_MU_MIMO_GROUP_DATA as u16,
    /// MAC address for the sniffer to follow when using MU-MIMO air sniffer.
    ///
    /// To turn that feature off set an invalid MAC address (e.g. `FF:FF:FF:FF:FF:FF`).
    MuMimoFollowMacAddr = nl80211_attrs::NL80211_ATTR_MU_MIMO_FOLLOW_MAC_ADDR as u16,
    /// The time at which the scan was actually started (`u64`).
    ///
    /// The time is the time synchronization function (TSF) of the BSS the interface that requested the scan
    /// is connected to (if available, otherwise this attribute must not be included).
    ScanStartTimeTsf = nl80211_attrs::NL80211_ATTR_SCAN_START_TIME_TSF as u16,
    /// The BSS according to which [`Nl80211Attr::ScanStartTimeTsf`] is set.
    ScanStartTimeTsfBssid = nl80211_attrs::NL80211_ATTR_SCAN_START_TIME_TSF_BSSID as u16,
    /// Measurement duration in TUs (`u16`).
    ///
    /// If [`Nl80211Attr::MeasurementDurationMandatory`] is not set, this is the maximum measurement duration
    /// allowed.
    ///
    /// This attribute is used with measurement requests. It can also be used with [`Nl80211Command::TriggerScan`]
    /// if the scan is used for beacon report radio measurement.
    MeasurementDuration = nl80211_attrs::NL80211_ATTR_MEASUREMENT_DURATION as u16,
    /// Flag attribute that indicates that the duration specified with [`Nl80211Attr::MeasurementDuration`] is mandatory.
    ///
    /// If this flag is not set, the duration is the maximum duration and the actual measurement duration may be shorter.
    MeasurementDurationMandatory =
        nl80211_attrs::NL80211_ATTR_MEASUREMENT_DURATION_MANDATORY as u16,
    /// Association ID for the mesh peer (`u16`).
    ///
    /// This is used to pull the stored data for mesh peer in power save state.
    MeshPeerAid = nl80211_attrs::NL80211_ATTR_MESH_PEER_AID as u16,
    /// The master preference to be used by [`Nl80211Command::StartNan`] and optionally with
    /// [`Nl80211Command::ChangeNanConfig`].
    ///
    /// Its type is `u8` and it can't be 0. Also, values 1 and 255 are reserved for certification purposes and
    /// should not be used during a normal device operation.
    NanMasterPref = nl80211_attrs::NL80211_ATTR_NAN_MASTER_PREF as u16,
    /// Operating bands configuration.
    ///
    /// This is a `u32` bitmask as described in [`Nl80211Band`]. For instance, for [`Nl80211Band::Band2Ghz`], bit 0 would be set.
    ///
    /// This attribute is used with [`Nl80211Command::StartNan`] and [`Nl80211Command::ChangeNanConfig`], and it is optional.
    ///
    /// If no bands are set, it means don't care and the device will decide what to use.
    Bands = nl80211_attrs::NL80211_ATTR_BANDS as u16,
    /// A function that can be added to NAN.
    ///
    /// See `enum nl80211_nan_func_attributes` for description of this nested attribute.
    // TODO: enum nl80211_nan_func_attributes
    NanFunc = nl80211_attrs::NL80211_ATTR_NAN_FUNC as u16,
    /// Used to report a match.
    ///
    /// This is a nested attribute. See `enum nl80211_nan_match_attributes`.
    // TODO: enum nl80211_nan_match_attributes
    NanMatch = nl80211_attrs::NL80211_ATTR_NAN_MATCH as u16,
    /// KEK for FILS (Re)Association Request/Response frame protection.
    FilsKek = nl80211_attrs::NL80211_ATTR_FILS_KEK as u16,
    /// Nonces (part of AAD) for FILS (Re)Association Request/Response frame protection.
    ///
    /// This attribute contains the 16 octet STA Nonce followed by 16 octets of AP Nonce.
    FilsNonces = nl80211_attrs::NL80211_ATTR_FILS_NONCES as u16,
    /// Indicates whether or not multicast packets should be send out as unicast to all stations (flag attribute).
    MulticastToUnicastEnabled = nl80211_attrs::NL80211_ATTR_MULTICAST_TO_UNICAST_ENABLED as u16,
    /// The BSSID of the AP.
    ///
    /// Note that [`Nl80211Attr::Mac`] is also used in various commands/events for specifying the BSSID.
    Bssid = nl80211_attrs::NL80211_ATTR_BSSID as u16,
    /// Relative RSSI threshold by which other BSSs has to be better or slightly worse than the current connected
    /// BSS for them to be reported to user space.
    ///
    /// This will give an opportunity to user space to consider connecting to other matching BSSs which have better or
    /// slightly worse RSSI than the current connected BSS by using an offloaded operation to avoid unnecessary wakeups.
    SchedScanRelativeRssi = nl80211_attrs::NL80211_ATTR_SCHED_SCAN_RELATIVE_RSSI as u16,
    /// When present, the RSSI level for BSSs in the specified band is to be adjusted before doing
    /// [`Nl80211Attr::SchedScanRelativeRssi`] based comparison to figure out better BSSs.
    ///
    /// The attribute value is a packed structure value as specified by `struct nl80211_bss_select_rssi_adjust`.
    SchedScanRssiAdjust = nl80211_attrs::NL80211_ATTR_SCHED_SCAN_RSSI_ADJUST as u16,
    /// The reason for which an operation timed out.
    ///
    /// `u32` attribute with an `enum nl80211_timeout_reason` value. This is used, e.g., with [`Nl80211Command::Connect`] event.
    // TODO: enum nl80211_timeout_reason
    TimeoutReason = nl80211_attrs::NL80211_ATTR_TIMEOUT_REASON as u16,
    /// EAP Re-authentication Protocol (ERP) username part of NAI used to refer keys rRK and rIK.
    ///
    /// This is used with [`Nl80211Command::Connect`].
    FilsErpUsername = nl80211_attrs::NL80211_ATTR_FILS_ERP_USERNAME as u16,
    /// EAP Re-authentication Protocol (ERP) realm part of NAI specifying the domain name of the ER server.
    ///
    /// This is used with [`Nl80211Command::Connect`].
    FilsErpRealm = nl80211_attrs::NL80211_ATTR_FILS_ERP_REALM as u16,
    /// Unsigned 16-bit ERP next sequence number to use in ERP messages.
    ///
    /// This is used in generating the FILS wrapped data for FILS authentication and is used with [`Nl80211Command::Connect`].
    FilsErpNextSeqnum = nl80211_attrs::NL80211_ATTR_FILS_ERP_NEXT_SEQ_NUM as u16,
    /// ERP re-authentication Root Key (rRK) for the NAI specified by [`Nl80211Attr::FilsErpUsername`]
    /// and [`Nl80211Attr::FilsErpRealm`].
    ///
    /// This is used for generating rIK and rMSK from successful FILS authentication and is used with [`Nl80211Command::Connect`].
    FilsErpRrk = nl80211_attrs::NL80211_ATTR_FILS_ERP_RRK as u16,
    /// A 2-octet identifier advertised by a FILS AP identifying the scope of PMKSAs.
    ///
    /// This is used with [`Nl80211Command::SetPmksa`] and [`Nl80211Command::DelPmksa`].
    FilsCacheId = nl80211_attrs::NL80211_ATTR_FILS_CACHE_ID as u16,
    /// Attribute for passing PMK key material.
    ///
    /// Used with [`Nl80211Command::SetPmksa`] for the PMKSA identified by [`Nl80211Attr::Pmkid`].
    ///
    /// For [`Nl80211Command::Connect`] and [`Nl80211Command::StartAp`] it is used to provide PSK for offloading
    /// 4-way handshake for WPA/WPA2-PSK networks.
    ///
    /// For 802.1X authentication it is used with [`Nl80211Command::SetPmk`].
    ///
    /// For offloaded FT support this attribute specifies the PMK-R0 if [`Nl80211Attr::Pmkr0Name`] is included as well.
    Pmk = nl80211_attrs::NL80211_ATTR_PMK as u16,
    /// Flag attribute which user-space shall use to indicate that it supports multiple active scheduled scan requests.
    SchedScanMulti = nl80211_attrs::NL80211_ATTR_SCHED_SCAN_MULTI as u16,
    /// Indicates maximum number of scheduled scan request that may be active for the device (`u32`).
    SchedScanMaxReqs = nl80211_attrs::NL80211_ATTR_SCHED_SCAN_MAX_REQS as u16,
    /// Flag attribute which user-space can include in [`Nl80211Command::Connect`] to indicate that
    /// for 802.1X authentication it wants to use the supported offload of the 4-Way Handshake.
    Want1x4wayHs = nl80211_attrs::NL80211_ATTR_WANT_1X_4WAY_HS as u16,
    /// PMK-R0 Name for offloaded BSS Fast Transition (FT).
    Pmkr0Name = nl80211_attrs::NL80211_ATTR_PMKR0_NAME as u16,
    /// (Reserved)
    PortAuthorized = nl80211_attrs::NL80211_ATTR_PORT_AUTHORIZED as u16,
    /// Identify the requested external authentication operation (`u32` attribute with an `enum nl80211_external_auth_action` value).
    ///
    /// This is used with the [`Nl80211Command::ExternalAuth`] request event.
    // TODO: enum nl80211_external_auth_action
    ExternalAuthAction = nl80211_attrs::NL80211_ATTR_EXTERNAL_AUTH_ACTION as u16,
    /// Flag attribute indicating that the user space supports external authentication.
    ///
    /// This attribute shall be used with [`Nl80211Command::Connect`] and [`Nl80211Command::StartAp`] request.
    ///
    /// The driver may offload authentication processing to user space if this capability is indicated in the
    /// respective requests from the user space. (This flag attribute deprecated for [`Nl80211Command::StartAp`],
    /// use [`Nl80211Attr::ApSettingsFlags`])
    // TODO: Deprecate?
    ExternalAuthSupport = nl80211_attrs::NL80211_ATTR_EXTERNAL_AUTH_SUPPORT as u16,
    /// Station's new/updated RX NSS value notified using this `u8` attribute.
    ///
    /// This is used with [`Nl80211Command::StaOpmodeChanged`].
    Nss = nl80211_attrs::NL80211_ATTR_NSS as u16,
    /// Station's ack signal strength (`s32`).
    AckSignal = nl80211_attrs::NL80211_ATTR_ACK_SIGNAL as u16,
    /// A flag indicating whether control port frames (e.g. of type given in [`Nl80211Attr::ControlPortEthertype`])
    /// will be sent directly to the network interface or sent via the `nl80211` socket.
    ///
    /// If this attribute is missing, then legacy behavior of sending control port frames directly to the network
    /// interface is used. If the flag is included, then control port frames are sent over `nl80211` instead using
    /// [`Nl80211Command::ControlPortFrame`].
    ///
    /// If control port routing over `nl80211` is to be used, then user space must also
    /// use the [`Nl80211Attr::SocketOwner`] flag.
    ///
    /// When used with [`Nl80211Attr::ControlPortNoPreauth`], pre-auth frames are not forwarded over the control port.
    ControlPortOverNl80211 = nl80211_attrs::NL80211_ATTR_CONTROL_PORT_OVER_NL80211 as u16,
    /// TXQ statistics (nested attribute, see `enum nl80211_txq_stats`).
    // TODO: enum nl80211_txq_stats
    TxqStats = nl80211_attrs::NL80211_ATTR_TXQ_STATS as u16,
    /// Total packet limit for the TXQ queues for this phy.
    ///
    /// The smaller of this and the memory limit is enforced.
    TxqLimit = nl80211_attrs::NL80211_ATTR_TXQ_LIMIT as u16,
    /// Total memory limit (in bytes) for the TXQ queues for this phy.
    ///
    /// The smaller of this and the packet limit is enforced.
    TxqMemoryLimit = nl80211_attrs::NL80211_ATTR_TXQ_MEMORY_LIMIT as u16,
    /// TXQ scheduler quantum (bytes).
    ///
    /// Number of bytes a flow is assigned on each round of the DRR scheduler.
    TxqQuantum = nl80211_attrs::NL80211_ATTR_TXQ_QUANTUM as u16,
    /// HE Capability information element (from Association Request when used with [`Nl80211Command::NewStation`]).
    ///
    /// Can be set only if `NL80211_STA_FLAG_WME` is set (except for NAN, which uses WME anyway).
    // TODO: enum nl80211_sta_flags
    HeCapability = nl80211_attrs::NL80211_ATTR_HE_CAPABILITY as u16,
    /// Nested attribute which user-space can include in [`Nl80211Command::StartAp`] or [`Nl80211Command::SetBeacon`]
    /// for fine timing measurement (FTM) responder functionality and containing parameters as possible.
    ///
    /// See `enum nl80211_ftm_responder_attr`.
    // TODO: enum nl80211_ftm_responder_attr
    FtmResponder = nl80211_attrs::NL80211_ATTR_FTM_RESPONDER as u16,
    /// Nested attribute with FTM responder statistics.
    ///
    /// See `enum nl80211_ftm_responder_stats`.
    // TODO: enum nl80211_ftm_responder_stats
    FtmResponderStats = nl80211_attrs::NL80211_ATTR_FTM_RESPONDER_STATS as u16,
    /// Timeout for the given operation in milliseconds (`u32`), if the attribute is not given no timeout is requested.
    ///
    /// Note that 0 is an invalid value.
    Timeout = nl80211_attrs::NL80211_ATTR_TIMEOUT as u16,
    /// Peer measurements request (and result) data.
    ///
    /// Uses nested attributes specified in `enum nl80211_peer_measurement_attrs`.
    ///
    /// This is also used for capability advertisement in the wiphy information, with the appropriate sub-attributes.
    PeerMeasurements = nl80211_attrs::NL80211_ATTR_PEER_MEASUREMENTS as u16,
    /// Station's weight when scheduled by the airtime scheduler.
    AirtimeWeight = nl80211_attrs::NL80211_ATTR_AIRTIME_WEIGHT as u16,
    /// Transmit power setting type (`u8`) for station associated with the AP.
    ///
    /// See `enum nl80211_tx_power_setting` for possible values.
    // TODO: enum nl80211_tx_power_setting
    StaTxPowerSetting = nl80211_attrs::NL80211_ATTR_STA_TX_POWER_SETTING as u16,
    /// Transmit power level (`s16`) in dBm units. This allows to set TX power for a station.
    ///
    /// If this attribute is not included, the default per-interface TX power setting will be overriding.
    ///
    /// Driver should be picking up the lowest TX power, either TX power per-interface or per-station.
    StaTxPower = nl80211_attrs::NL80211_ATTR_STA_TX_POWER as u16,
    /// Attribute for passing SAE password material.
    ///
    /// It is used with [`Nl80211Command::Connect`] to provide password for offloading SAE authentication
    /// for WPA3-Personal networks.
    SaePassword = nl80211_attrs::NL80211_ATTR_SAE_PASSWORD as u16,
    /// Enable target wait time (TWT) responder support.
    TwtResponder = nl80211_attrs::NL80211_ATTR_TWT_RESPONDER as u16,
    /// Nested attribute for Overlapping BSS (OBSS) Packet Detection functionality.
    HeObssPd = nl80211_attrs::NL80211_ATTR_HE_OBSS_PD as u16,
    /// Bitmap that indicates the 2.16 GHz channel(s) that are allowed to be used for EDMG transmissions (`u8` attribute).
    ///
    /// Defined by IEEE P802.11ay/D4.0 section 9.4.2.251.
    WiphyEdmgChannels = nl80211_attrs::NL80211_ATTR_WIPHY_EDMG_CHANNELS as u16,
    /// Channel BW Configuration subfield encodes the allowed channel bandwidth configurations (`u8` attribute).
    ///
    /// Defined by IEEE P802.11ay/D4.0 section 9.4.2.251, Table 13.
    WiphyEdmgBwConfig = nl80211_attrs::NL80211_ATTR_WIPHY_EDMG_BW_CONFIG as u16,
    /// VLAN ID (1..4094) for the station and VLAN group key (`u16`).
    VlanId = nl80211_attrs::NL80211_ATTR_VLAN_ID as u16,
    /// Nested attribute for BSS Color Settings.
    HeBssColor = nl80211_attrs::NL80211_ATTR_HE_BSS_COLOR as u16,
    /// Nested array attribute, with each entry using attributes from `enum nl80211_iftype_akm_attributes`.
    ///
    /// This attribute is sent in a response to [`Nl80211Command::GetWiphy`], indicating supported authentication
    /// and key management (AKM) suites capability per interface. AKM suites advertised in [`Nl80211Attr::AkmSuites`]
    /// are default capabilities if AKM suites not advertised for a specific interface type.
    // TODO: enum nl80211_iftype_akm_attributes
    IftypeAkmSuites = nl80211_attrs::NL80211_ATTR_IFTYPE_AKM_SUITES as u16,
    /// TID specific configuration in a nested attribute with `enum nl80211_tid_config_attr` sub-attributes.
    ///
    /// On output (in wiphy attributes) it contains only the feature sub-attributes.
    // TODO: enum nl80211_tid_config_attr
    TidConfig = nl80211_attrs::NL80211_ATTR_TID_CONFIG as u16,
    /// Disable pre-auth frame RX on control port in order to forward/receive them as ordinary data frames.
    ControlPortNoPreauth = nl80211_attrs::NL80211_ATTR_CONTROL_PORT_NO_PREAUTH as u16,
    /// Maximum lifetime for PMKSA in seconds (`u32`, dot11RSNAConfigPMKReauthThreshold; 0 is not a valid value).
    ///
    /// An optional parameter configured through [`Nl80211Command::SetPmksa`].
    ///
    /// Drivers that trigger roaming need to know the lifetime of the configured PMKSA for triggering the
    /// full vs. PMKSA caching based authentication.
    ///
    /// This timeout helps authentication methods like SAE, where PMK is updated only by going through a full
    /// (new SAE) authentication instead of being updated during an association for EAP authentication.
    ///
    /// No new full authentication within the PMK expiry shall result in a disassociation at the end of the lifetime.
    PmkLifetime = nl80211_attrs::NL80211_ATTR_PMK_LIFETIME as u16,
    /// Reauthentication threshold time, in terms of percentage of [`Nl80211Attr::PmkLifetime`]
    /// (`u8`, dot11RSNAConfigPMKReauthThreshold, 1..100).
    ///
    /// This is an optional parameter configured through [`Nl80211Command::SetPmksa`].
    ///
    /// Requests the driver to trigger a full authentication roam (without PMKSA caching) after the reauthentication
    /// threshold time, but before the PMK lifetime has expired.
    ///
    /// Authentication methods like SAE must able to generate a new PMKSA entry without having to force
    /// a disconnection after the PMK timeout.
    ///
    /// If no roaming occurs between the reauth threshold and PMK expiration, disassociation is still forced.
    PmkReauthThreshold = nl80211_attrs::NL80211_ATTR_PMK_REAUTH_THRESHOLD as u16,
    /// Multicast flag for the [`Nl80211Command::RegisterFrame`] command, see the description there.
    ReceiveMulticast = nl80211_attrs::NL80211_ATTR_RECEIVE_MULTICAST as u16,
    /// Offset of the associated [`Nl80211Attr::WiphyFreq`] in positive KHz.
    ///
    /// Only valid when supplied with an [`Nl80211Attr::WiphyFreq`].
    WiphyFreqOffset = nl80211_attrs::NL80211_ATTR_WIPHY_FREQ_OFFSET as u16,
    /// Center frequency offset in KHz for the first channel segment specified in [`Nl80211Attr::CenterFreq1`].
    CenterFreq0Offset = nl80211_attrs::NL80211_ATTR_CENTER_FREQ1_OFFSET as u16,
    /// Nested attribute with KHz frequencies.
    ScanFreqKhz = nl80211_attrs::NL80211_ATTR_SCAN_FREQ_KHZ as u16,
    /// HE 6 GHz Band Capability IE (from Association Request when used with [`Nl80211Command::NewStation`]).
    He6GhzCapability = nl80211_attrs::NL80211_ATTR_HE_6GHZ_CAPABILITY as u16,
    /// Optional parameter to configure FILS discovery.
    ///
    /// It is a nested attribute, see `enum nl80211_fils_discovery_attributes`.
    /// User space should pass an empty nested attribute to disable this feature and delete the templates.
    // TODO: enum nl80211_fils_discovery_attributes
    FilsDiscovery = nl80211_attrs::NL80211_ATTR_FILS_DISCOVERY as u16,
    /// Optional parameter to configure unsolicited broadcast Probe Response.
    ///
    /// It is a nested attribute, see `enum nl80211_unsol_bcast_probe_resp_attributes`.
    /// User space should pass an empty nested attribute to disable this feature and delete the templates.
    // TODO: enum nl80211_unsol_bcast_probe_resp_attributes
    UnsolBcastProbeResp = nl80211_attrs::NL80211_ATTR_UNSOL_BCAST_PROBE_RESP as u16,
    /// S1G Capability IE (from Association Request when used with [`Nl80211Command::NewStation`])
    S1gCapability = nl80211_attrs::NL80211_ATTR_S1G_CAPABILITY as u16,
    /// S1G Capability IE override mask.
    ///
    /// Used with [`Nl80211Attr::S1gCapability`] in [`Nl80211Command::Associate`] or [`Nl80211Command::Connect`].
    S1gCapabilityMask = nl80211_attrs::NL80211_ATTR_S1G_CAPABILITY_MASK as u16,
    /// Indicates the mechanism(s) allowed for SAE PWE derivation in WPA3-Personal networks which
    /// are using SAE authentication.
    ///
    /// This is a `u8` attribute that encapsulates one of the values from `enum nl80211_sae_pwe_mechanism`.
    // TODO: enum nl80211_sae_pwe_mechanism
    SaePwe = nl80211_attrs::NL80211_ATTR_SAE_PWE as u16,
    /// Flag attribute, used with deauthentication and disassociation events to indicate that an
    /// immediate reconnect to the AP is desired.
    ReconnectRequested = nl80211_attrs::NL80211_ATTR_RECONNECT_REQUESTED as u16,
    /// SAR power limitation specification when used with [`Nl80211Command::SetSarSpecs`].
    ///
    /// The message contains fields of `nl80211_sar_attrs` which specifies the SAR type and related SAR specs.
    /// SAR specs contains array of `nl80211_sar_specs_attrs`.
    // TODO: nl80211_sar_attrs
    // TODO: nl80211_sar_specs_attrs
    SarSpec = nl80211_attrs::NL80211_ATTR_SAR_SPEC as u16,
    /// Force HE capable interfaces to disable this feature during association.
    ///
    /// This is a flag attribute. Currently only supported in `mac80211` drivers.
    DisableHe = nl80211_attrs::NL80211_ATTR_DISABLE_HE as u16,
    /// Bitmap of the `u64` BSS colors for the [`Nl80211Command::ObssColorCollision`] event.
    ObssColorBitmap = nl80211_attrs::NL80211_ATTR_OBSS_COLOR_BITMAP as u16,
    /// `u8` attribute specifying the number of TBTT's until the color switch event.
    ColorChangeCount = nl80211_attrs::NL80211_ATTR_COLOR_CHANGE_COUNT as u16,
    /// `u8` attribute specifying the color that we are switching to.
    ColorChangeColor = nl80211_attrs::NL80211_ATTR_COLOR_CHANGE_COLOR as u16,
    /// Nested set of attributes containing the IE information for the time while performing a color switch.
    ColorChangeElems = nl80211_attrs::NL80211_ATTR_COLOR_CHANGE_ELEMS as u16,
    /// Nested attribute for multiple BSSID advertisements (MBSSID) parameters in AP mode.
    ///
    /// Kernel uses this attribute to indicate the driver's support for MBSSID and enhanced multi-BSSID
    /// advertisements (EMA AP) to the user space. User space should use this attribute to configure per
    /// interface MBSSID parameters.
    ///
    /// See `enum nl80211_mbssid_config_attributes` for details.
    // TODO: enum nl80211_mbssid_config_attributes
    MbssidConfig = nl80211_attrs::NL80211_ATTR_MBSSID_CONFIG as u16,
    /// Nested parameter to pass multiple BSSID elements.
    ///
    /// Mandatory parameter for the transmitting interface to enable MBSSID.
    /// Optional for the non-transmitting interfaces.
    MbssidElems = nl80211_attrs::NL80211_ATTR_MBSSID_ELEMS as u16,
    /// Configure dedicated offchannel chain available for radar/CAC detection on some hardware.
    /// This chain can't be used to transmit or receive frames and it is bounded to a running wdev.
    ///
    /// Background radar/CAC detection allows to avoid the CAC downtime switching on a different channel
    /// during CAC detection on the selected radar channel.
    RadarBackground = nl80211_attrs::NL80211_ATTR_RADAR_BACKGROUND as u16,
    /// EHT Capability IE (from Association Request when used with [`Nl80211Command::NewStation`]).
    ///
    /// Can be set only if `NL80211_STA_FLAG_WME` is set.
    // TODO: enum nl80211_sta_flags
    ApSettingsFlags = nl80211_attrs::NL80211_ATTR_AP_SETTINGS_FLAGS as u16,
    /// EHT Capability IE (from Association Request when used with [`Nl80211Command::NewStation`]).
    ///
    /// Can be set only if `NL80211_STA_FLAG_WME` is set.
    // TODO: enum nl80211_sta_flag
    EhtCapability = nl80211_attrs::NL80211_ATTR_EHT_CAPABILITY as u16,
    /// Force EHT capable interfaces to disable this feature during association.
    ///
    /// This is a flag attribute. Currently only supported in `mac80211` drivers.
    DisableEht = nl80211_attrs::NL80211_ATTR_DISABLE_EHT as u16,
    /// A nested array of links, each containing some per-link information and a link ID.
    MloLinks = nl80211_attrs::NL80211_ATTR_MLO_LINKS as u16,
    /// A (`u8`) link ID for use with MLO, to be used with various commands that need a link ID to operate.
    MloLinkId = nl80211_attrs::NL80211_ATTR_MLO_LINK_ID as u16,
    /// An MLD address, used with various commands such as [`Nl80211Command::Authenticate`] and
    /// [`Nl80211Command::Associate`].
    MldAddr = nl80211_attrs::NL80211_ATTR_MLD_ADDR as u16,
    /// Flag attribute to indicate user space supports MLO connection.
    ///
    /// Used with [`Nl80211Command::Connect`]. If this attribute is not included in [`Nl80211Command::Connect`],
    /// drivers must not perform MLO connection.
    MloSupport = nl80211_attrs::NL80211_ATTR_MLO_SUPPORT as u16,
    /// Indicates maximum number of AKM suites allowed for [`Nl80211Command::Connect`],
    /// [`Nl80211Command::Associate`], and [`Nl80211Command::StartAp`] in [`Nl80211Command::GetWiphy`] response.
    ///
    /// `u16` attribute. If this attribute is not present user space shall consider maximum number of AKM suites allowed as
    /// [`NL80211_MAX_NR_AKM_SUITES`] which is the legacy maximum number prior to the introduction of this attribute.
    // TODO: Add this enum? (legacy)
    MaxNumAkmSuites = nl80211_attrs::NL80211_ATTR_MAX_NUM_AKM_SUITES as u16,
    /// EML Capability information (`u16`).
    EmlCapability = nl80211_attrs::NL80211_ATTR_EML_CAPABILITY as u16,
    /// MLD Capabilities and Operations (`u16`).
    MldCapaAndOps = nl80211_attrs::NL80211_ATTR_MLD_CAPA_AND_OPS as u16,
    /// Hardware timestamp for TX operation in nanoseconds (`u64`).
    ///
    /// This is the device clock timestamp so it will probably reset when the device is stopped or the firmware is reset.
    ///
    /// When used with [`Nl80211Command::FrameTxStatus`], indicates the frame TX timestamp.
    /// When used with [`Nl80211Command::Frame`] RX notification, indicates the ack TX timestamp.
    TxHwTimestamp = nl80211_attrs::NL80211_ATTR_TX_HW_TIMESTAMP as u16,
    /// Hardware timestamp for RX operation in nanoseconds (`u64`).
    ///
    /// This is the device clock timestamp so it will probably reset when the device is stopped or the firmware is reset.
    ///
    /// When used with [`Nl80211Command::FrameTxStatus`], indicates the ACK RX timestamp.
    /// When used with [`Nl80211Command::Frame`] RX notification, indicates the incoming frame RX timestamp.
    RxHwTimestamp = nl80211_attrs::NL80211_ATTR_RX_HW_TIMESTAMP as u16,
    /// Transition Disable bitmap, for subsequent (re)associations.
    TdBitmap = nl80211_attrs::NL80211_ATTR_TD_BITMAP as u16,
    /// Preamble puncturing bitmap (`u32`).
    ///
    /// Lowest bit corresponds to the lowest 20 MHz channel. Each bit set to 1 indicates that
    /// the sub-channel is punctured. Higher 16 bits are reserved.
    PunctBitmap = nl80211_attrs::NL80211_ATTR_PUNCT_BITMAP as u16,
    /// Maximum number of peers that HW timestamping can be enabled for concurrently (`u16`),
    /// a wiphy attribute.
    ///
    /// A value of `0xffff` indicates setting for all peers (i.e. not specifying an address with
    /// [`Nl80211Command::SetHwTimestamp`]) is supported.
    MaxHwTimestampPeers = nl80211_attrs::NL80211_ATTR_MAX_HW_TIMESTAMP_PEERS as u16,
    /// Indicates whether HW timestamping should be enabled or not (flag attribute).
    HwTimestampEnabled = nl80211_attrs::NL80211_ATTR_HW_TIMESTAMP_ENABLED as u16,
    /// Optional nested attribute for Reduced Neighbor Report (RNR) IEs.
    ///
    /// This attribute can be used only when `NL80211_MBSSID_CONFIG_ATTR_EMA` is enabled.
    ///
    /// User space is responsible for splitting the RNR into multiple elements such that
    /// each element excludes the non-transmitting profiles already included in the MBSSID element
    /// ([`Nl80211Attr::MbssidElems`]) at the same index.
    ///
    /// Each EMA beacon will be generated by adding MBSSID and RNR elements at the same index.
    /// If the user space includes more RNR elements than number of MBSSID elements then these will
    /// be added in every EMA beacon.
    // TODO: enum nl80211_mbssid_config_attributes
    EmaRnrElems = nl80211_attrs::NL80211_ATTR_EMA_RNR_ELEMS as u16,
    /// Unused. It was used to indicate that a link is disabled during association. However,
    /// the AP will send the information by including a TTLM in the Association Response.
    MloLinkDisabled = nl80211_attrs::NL80211_ATTR_MLO_LINK_DISABLED as u16,
    /// Include BSS usage data, i.e. include BSSes that can only be used in restricted scenarios
    /// and/or cannot be used at all.
    BssDumpIncludeUseData = nl80211_attrs::NL80211_ATTR_BSS_DUMP_INCLUDE_USE_DATA as u16,
    /// Binary attribute specifying the downlink TID to link mapping. The length is 8 * sizeof(`u16`).
    ///
    /// For each TID the link mapping is as defined in section 9.4.2.314 (TID-To-Link Mapping element)
    /// in Draft P802.11be_D4.0.
    MloTtlmDlink = nl80211_attrs::NL80211_ATTR_MLO_TTLM_DLINK as u16,
    /// Binary attribute specifying the uplink TID to link mapping. The length is 8 * sizeof(`u16`).
    ///
    /// For each TID the link mapping is as defined in section 9.4.2.314 (TID-To-Link Mapping element)
    /// in Draft P802.11be_D4.0.
    MloTtlmUlink = nl80211_attrs::NL80211_ATTR_MLO_TTLM_ULINK as u16,
    /// Flag attribute used with [`Nl80211Command::Associate`] indicating the SPP A-MSDUs are used on this connection.
    AssocSppAmsdu = nl80211_attrs::NL80211_ATTR_ASSOC_SPP_AMSDU as u16,
    /// Nested attribute describing physical radios belonging to this wiphy.
    ///
    /// See `enum nl80211_wiphy_radio_attrs`.
    // TODO: enum nl80211_wiphy_radio_attrs
    WiphyRadios = nl80211_attrs::NL80211_ATTR_WIPHY_RADIOS as u16,
    /// Nested attribute listing the supported interface combinations for all radios combined.
    ///
    /// In each nested item, it contains attributes defined in `enum nl80211_if_combination_attrs`.
    // TODO: enum nl80211_if_combination_attrs
    WiphyInterfaceCombinations = nl80211_attrs::NL80211_ATTR_WIPHY_INTERFACE_COMBINATIONS as u16,
    /// Bitmask of allowed radios (`u32`).
    ///
    /// A value of 0 means all radios.
    VifRadioMask = nl80211_attrs::NL80211_ATTR_VIF_RADIO_MASK as u16,
    /// Supported BSS Membership Selectors, array of supported selectors as defined by IEEE Std 802.11-2020 9.4.2.3,
    /// but without the length restriction (at most [`NL80211_MAX_SUPP_SELECTORS`]).
    ///
    /// This can be used to provide a list of selectors that are implemented by the supplicant.
    /// If not given, support for SAE H2E is assumed.
    SupportedSelectors = nl80211_attrs::NL80211_ATTR_SUPPORTED_SELECTORS as u16,
    /// A bitmask of the links requested to be removed from the MLO association (`u16`).
    MloReconfRemLinks = nl80211_attrs::NL80211_ATTR_MLO_RECONF_REM_LINKS as u16,
    /// Flag attribute indicating that EPCS is enabled for a station interface.
    Epcs = nl80211_attrs::NL80211_ATTR_EPCS as u16,
    // TODO: These changes will land in 7.2
    /// Extended MLD capabilities and operations.
    ///
    /// For association and link reconfiguration, indicates extra capabilities that userspace implements,
    /// currently only "BTM MLD Recommendation For Multiple APs Support".
    ///
    /// For wiphy information, additional flags that drivers will set, but this is informational only for userspace
    /// (it's not expected to set these.)
    // TODO: Changed to this from NL80211_ATTR_ASSOC_MLD_EXT_CAPA_OPS in v7.2. Add alias for this and others renamed
    ExtMldCapaAndOps = nl80211_attrs::NL80211_ATTR_EXT_MLD_CAPA_AND_OPS as u16,
    /// Integer attribute denoting the index of the radio of interest (`u8`).
    ///
    /// Internally a value of -1 is used to indicate that the radio ID is not given in user-space.
    /// This means that all the attributes are applicable to all the radios.
    ///
    /// If there is a radio index provided in user-space, the attributes will be applicable to that
    /// specific radio only. If the radio ID is greater thank the number of radios, error denoting
    /// invalid value is returned.
    WiphyRadioIndex = nl80211_attrs::NL80211_ATTR_WIPHY_RADIO_INDEX as u16,
    /// Integer attribute that represents the number of beacon intervals between each long beacon
    /// transmission for an S1G BSS with short beaconing enabled.
    ///
    /// This is a required attribute for initialising an S1G short beaconing BSS. When
    /// updating the short beacon data, this is not required. It has a minimum value of 2
    /// (i.e. 2 beacon intervals).
    S1gLongBeaconPeriod = nl80211_attrs::NL80211_ATTR_S1G_LONG_BEACON_PERIOD as u16,
    /// Nested attribute containing the short beacon head and tail used to set or update the short beacon templates.
    ///
    /// When bringing up a new interface, [`Nl80211Attr::S1gLongBeaconPeriod`] is required alongside this attribute.
    ///
    /// Refer to `enum nl80211_s1g_short_beacon_attrs` for the attribute definitions.
    // TODO: enum nl80211_s1g_short_beacon_attrs
    S1gShortBeacon = nl80211_attrs::NL80211_ATTR_S1G_SHORT_BEACON as u16,
    /// Nested attribute used with [`Nl80211Command::GetWiphy`] which indicates which BSS parameters can be modified.
    ///
    /// The attribute can also be used as flag attribute by user-space in [`Nl80211Command::SetBss`]
    /// to indicate that it wants strict checking on the BSS parameters to be modified.
    BssParam = nl80211_attrs::NL80211_ATTR_BSS_PARAM as u16,
    /// Nested attribute for extended NAN cluster configuration.
    ///
    /// This is used with [`Nl80211Command::StartNan`] and [`Nl80211Command::ChangeNanConfig`].
    ///
    /// See `enum nl80211_nan_conf_attributes` for details. This attribute is optional.
    // TODO: Nl80211NanConfAttributes
    NanConfig = nl80211_attrs::NL80211_ATTR_NAN_CONFIG as u16,
    /// Flag attribute indicating that a new NAN cluster has been created.
    ///
    /// This is used with [`Nl80211Command::NanClusterJoined`].
    NanNewCluster = nl80211_attrs::NL80211_ATTR_NAN_NEW_CLUSTER as u16,
    /// Nested attribute for NAN capabilities.
    ///
    /// This is used with [`Nl80211Command::GetWiphy`] to indicate the NAN capabilities supported by the driver.
    ///
    /// See `enum nl80211_nan_capabilities` for details.
    // TODO: Nl80211NanCapabilities
    NanCapabilities = nl80211_attrs::NL80211_ATTR_NAN_CAPABILITIES as u16,
    /// Flag attribute indicating that the S1G primary channel is 2 MHz wide, and the control
    /// channel designates the 1 MHz primary subchannel within that 2 MHz primary.
    S1gPrimary2Mhz = nl80211_attrs::NL80211_ATTR_S1G_PRIMARY_2MHZ as u16,
    // A flag attribute to indicate if the peer is an EPP STA.
    //
    // Used with [`Nl80211Command::NewSta`] and [`Nl80211Command::AddLinkSta`].
    EppPeer = nl80211_attrs::NL80211_ATTR_EPP_PEER as u16,
    // UHR Capability information element (from association request when used with [`Nl80211Command::NewStation`]).
    //
    // Can be set only if HE/EHT are also available.
    UhrCapability = nl80211_attrs::NL80211_ATTR_UHR_CAPABILITY as u16,
    // Force UHR capable interfaces to disable this feature during association.
    //
    // This is a flag attribute. Currently only supported in `mac80211` drivers.
    DisableUhr = nl80211_attrs::NL80211_ATTR_DISABLE_UHR as u16,
    // Attribute specifying the signal interference bitmap detected on the operating bandwidth for
    // [`Nl80211Command::IncumbentSignalDetect`].
    //
    // Each bit represents a 20 MHz segment, lowest bit corresponds to the lowest 20 MHz segment,
    // in the operating bandwidth where the interference is detected.
    //
    // Punctured sub-channels are included in the bitmap structure; however, since interference detection is
    // not performed on these sub-channels, their corresponding bits are consistently set to zero.
    IncumbentSignalInterferenceBitmap =
        nl80211_attrs::NL80211_ATTR_INCUMBENT_SIGNAL_INTERFERENCE_BITMAP as u16,
    // Full UHR Operation element, as it appears in association response etc., since it's abridged in the beacon.
    //
    // Used for [`Nl80211Command::StartAp`] etc.
    UhrOperation = nl80211_attrs::NL80211_ATTR_UHR_OPERATION as u16,
    /// This is a nested attribute. There can be multiple attributes of this type, each one represents a channel
    /// definition and consists of top-level attributes like [`Nl80211Attr::WiphyFreq`].
    ///
    /// When used with [`Nl80211Command::NanSetLocalSched`], it specifies the channel definitions on which the radio
    /// needs to operate during specific time slots. All of the channel definitions should be mutually incompatible.
    /// With this command, [`Nl80211Attr::NanChannelEntry`] and [`Nl80211Attr::NanRxNss`] are mandatory.
    ///
    /// When used with [`Nl80211Command::NanSetPeerSched`], it configures the peer NAN channels. In that case,
    /// the channel definitions can be compatible to each other, or even identical just with different RX NSS.
    /// With this command, [`Nl80211Attr::NanChannelEntry`] and [`Nl80211Attr::NanRxNss`] are mandatory.
    ///
    /// The number of channels should fit the current configuration of channels and the possible interface combinations.
    ///
    /// If an existing NAN channel is changed but the chandef isn't, the channel entry must also remain unchanged.
    ///
    /// When used with [`Nl80211Command::NanChannelEvac`], this identifies the channels that were evacuated.
    NanChannel = nl80211_attrs::NL80211_ATTR_NAN_CHANNEL as u16,
    /// A byte array of 6 bytes. Contains the Channel Entry as defined in Wi-Fi Aware (TM) 4.0 specification Table
    /// 100 (Channel Entry format for the NAN Availability attribute).
    NanChannelEntry = nl80211_attrs::NL80211_ATTR_NAN_CHANNEL_ENTRY as u16,
    /// An array of `u8` values and 32 cells. Each value maps a time slot to the chandef on which the radio should
    /// operate on in that time. `NL80211_NAN_SCHED_NOT_AVAIL_SLOT` indicates unscheduled.
    ///
    /// The chandef is represented using its index, where the index is the sequential number of the [`Nl80211Attr::NanChannel`]
    /// attribute within all the attributes of this type.
    ///
    /// Each slots spans over 16TUs, hence the entire schedule spans over 512TUs. Other slot durations and periods
    /// are currently not supported.
    NanTimeSlots = nl80211_attrs::NL80211_ATTR_NAN_TIME_SLOTS as u16,
    /// RX NSS used for a NAN channel (`u8`).
    ///
    /// This is used with [`Nl80211Attr::NanChannel`] when configuring NAN channels with [`Nl80211Command::NanSetLocalSched`]
    /// or [`Nl80211Command::NanSetPeerSched`].
    NanRxNss = nl80211_attrs::NL80211_ATTR_NAN_RX_NSS as u16,
    /// (Binary) The NAN Availability attribute blob, including the attribute header, as defined in Wi-Fi Aware (TM) 4.0
    /// specification Table 93 (NAN Availability attribute format).
    ///
    /// Required with [`Nl80211Command::NanSetLocalSched`] to provide the raw NAN Availability attribute.
    ///
    /// Used by the device to publish Schedule Update NAFs.
    NanAvailBlob = nl80211_attrs::NL80211_ATTR_NAN_AVAIL_BLOB as u16,
    /// Flag attribute used with [`Nl80211Command::NanSetLocalSched`].
    ///
    /// When present, the command is a request from the device to perform an announced schedule update. This means
    /// that it needs to send the updated NAN availability to the peers, and do the actual switch on the right time
    /// (i.e. at the end of the slot after the slot in which the updated NAN Availability was sent). Since the
    /// slots management is done in the device, the update to the peers needs to be sent by the device, so it knows
    /// the actual switch time.
    ///
    /// If the flag is not set, the schedule should be applied immediately.
    ///
    /// When this flag is set, the total number of NAN channels from both the old and new schedules must not exceed
    /// the allowed number of local NAN channels, because with deferred scheduling the old channels cannot be removed
    /// before adding the new ones to free up space.
    NanSchedDeferred = nl80211_attrs::NL80211_ATTR_NAN_SCHED_DEFERRED as u16,
    /// Flag attribute used with [`Nl80211Command::NanSchedUpdateDone`] to indicate that the deferred schedule update completed successfully.
    ///
    /// If this flag is not present, the update failed.
    NanSchedUpdateSuccess = nl80211_attrs::NL80211_ATTR_NAN_SCHED_UPDATE_SUCCESS as u16,
    /// The address of the NMI station to which this NDI station belongs.
    ///
    /// Used with [`Nl80211Command::NewStation`] when adding an NDI station.
    NanNmiMac = nl80211_attrs::NL80211_ATTR_NAN_NMI_MAC as u16,
    /// (Binary) The initial ULW(s) as published by the peer, as defined in the Wi-Fi Aware (TM) 4.0 specification Table 109
    /// (Unaligned Schedule attribute format).
    ///
    /// Used to configure the device with the initial ULW(s) of a peer, before the device starts tracking it.
    NanUlw = nl80211_attrs::NL80211_ATTR_NAN_ULW as u16,
    /// The committed DW as published by the peer (`u16`), as defined in the Wi-Fi Aware (TM) 4.0 specification Table 80
    /// (Committed DW Information field format).
    NanCommittedDw = nl80211_attrs::NL80211_ATTR_NAN_COMMITTED_DW as u16,
    /// The sequence ID of the peer schedule that [`Nl80211Command::NanSetPeerSched`] defines (`u8`).
    ///
    /// The device follows the sequence ID in the frames to identify newer schedules.
    ///
    /// Once a schedule with a higher sequence ID is received, the device may stop communicating with that peer until
    /// a new peer schedule with a matching sequence ID is received.
    NanSeqId = nl80211_attrs::NL80211_ATTR_NAN_SEQ_ID as u16,
    /// The maximum channel switch time, in microseconds (`u16`).
    NanMaxChanSwitchTime = nl80211_attrs::NL80211_ATTR_NAN_MAX_CHAN_SWITCH_TIME as u16,
    /// Nested array of peer schedule maps. Used with [`Nl80211Command::NanSetPeerSched`].
    ///
    /// Contains up to 2 entries, each containing nested attributes from `enum nl80211_nan_peer_map_attrs`.
    // TODO: enum nl80211_nan_peer_map_attrs
    NanPeerMaps = nl80211_attrs::NL80211_ATTR_NAN_PEER_MAPS as u16,
    // 7.2+ stuff
    /// Flag attribute, used only with the [`Nl80211Command::Connect`] event in SME-in-driver mode.
    ///
    /// The driver should set this flag to indicate that both the (Re)Association Request frame
    /// and the corresponding (Re)Association Response frame are transmitted encrypted over the air.
    /// Enhanced Privacy Protection (EPP), as defined in IEEE P802.11bi/D4.0, mandates this encryption.
    AssocEncrypted = nl80211_attrs::NL80211_ATTR_ASSOC_ENCRYPTED as u16,
    /// NPCA primary channel (`u32`)
    NpcaPrimaryFreq = nl80211_attrs::NL80211_ATTR_NPCA_PRIMARY_FREQ as u16,
    /// NPCA puncturing bitmap (`u32`)
    NpcaPunctBitmap = nl80211_attrs::NL80211_ATTR_NPCA_PUNCT_BITMAP as u16,
    /// Request flag for [`Nl80211Command::GetStation`] (dump mode only).
    ///
    /// When set on an MLD station, the dump produces two [`Nl80211Command::NewStation`] messages per station per dump call:
    /// 1. An aggregated-stats message whose top-level %NL80211_ATTR_STA_INFO contains MLO-combined statistics (same content as a dump withou this flag).
    ///
    /// 2. For each active link, a per-link message containing [`Nl80211Attr::MloLinks`] with a single link entry.
    ///    Each entry holds [`Nl80211Attr::MloLinkId`], the link-specific [`Nl80211Attr::Mac`], [`Nl80211Attr::StaInfo`] with per-link statistics
    ///    (see [`Nl80211StaInfo`]).
    ///
    /// The aggregated message always precedes the per-link messages for the same station within a dump sequence.
    //StaDumpLinkStats = nl80211_attrs::NL80211_ATTR_STA_DUMP_LINK_STATS as u16,
    StaDumpLinkStats = 367, // TODO: v7.3
}
impl neli::consts::genl::NlAttrType for Nl80211Attr {}

// TODO: Interface types may also be passed as attributes, but
//       presently there is not an ergonomic way to support
//       serializing attributes as any size other than u16
/// Virtual interface types (`enum nl80211_iftype`)
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211Iftype {
    /// Unspecified type, driver decides
    Unspecified = nl80211_iftype::NL80211_IFTYPE_UNSPECIFIED as u16,
    /// Independent BSS member
    Adhoc = nl80211_iftype::NL80211_IFTYPE_ADHOC as u16,
    /// Managed BSS member
    Station = nl80211_iftype::NL80211_IFTYPE_STATION as u16,
    /// Access point
    Ap = nl80211_iftype::NL80211_IFTYPE_AP as u16,
    /// VLAN interface for access points
    ///
    /// VLAN interfaces are a bit special in that they must always be tied to a pre-existing
    /// AP type interface.
    ApVlan = nl80211_iftype::NL80211_IFTYPE_AP_VLAN as u16,
    /// Wireless distribution interface
    Wds = nl80211_iftype::NL80211_IFTYPE_WDS as u16,
    /// Monitor interface receiving all frames
    Monitor = nl80211_iftype::NL80211_IFTYPE_MONITOR as u16,
    /// Mesh point
    MeshPoint = nl80211_iftype::NL80211_IFTYPE_MESH_POINT as u16,
    /// P2P client
    P2pClient = nl80211_iftype::NL80211_IFTYPE_P2P_CLIENT as u16,
    /// P2P group owner (GO)
    P2pGo = nl80211_iftype::NL80211_IFTYPE_P2P_GO as u16,
    /// P2P device interface type
    ///
    /// This is not a netdev and therefore can't be created in normal ways, use the [`Nl80211Command::StartP2pDevice`]
    /// and [`Nl80211Command::StopP2pDevice`] commands to create and destroy one
    P2pDevice = nl80211_iftype::NL80211_IFTYPE_P2P_DEVICE as u16,
    /// Outside Context of a BSS
    ///
    /// This mode corresponds to the MIB variable dot11OCBActivated=true
    Ocb = nl80211_iftype::NL80211_IFTYPE_OCB as u16,
    /// NAN device interface type (not a netdev)
    Nan = nl80211_iftype::NL80211_IFTYPE_NAN as u16,
    /// NAN data interface type (not a netdev)
    ///
    /// NAN data interfaces can only be brought up (`Iff::UP`) when a NAN interface already exists and
    /// NAN has been started (`Nl80211Command::StartNan`).
    NanData = nl80211_iftype::NL80211_IFTYPE_NAN_DATA as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211Iftype {}

impl_flags!(
    /// Station flags (`enum nl80211_sta_flags`)
    ///
    /// When a station is added to an AP interface, it is assumed to be already associated (and hence authenticated).
    pub Nl80211StaFlags: u32 {
        /// Station is authorized (802.1X)
        Authorized = 1 << nl80211_sta_flags::NL80211_STA_FLAG_AUTHORIZED as u32,
        /// Station is capable of receiving frames with short Barker preamble
        ShortPreamble = 1 << nl80211_sta_flags::NL80211_STA_FLAG_SHORT_PREAMBLE as u32,
        /// Station is WME/QoS capable
        Wme = 1 << nl80211_sta_flags::NL80211_STA_FLAG_WME as u32,
        /// Station uses management frame protection (MFP)
        Mfp = 1 << nl80211_sta_flags::NL80211_STA_FLAG_MFP as u32,
        /// Station is authenticated
        Authenticated = 1 << nl80211_sta_flags::NL80211_STA_FLAG_AUTHENTICATED as u32,
        /// Station is a TDLS peer -- this flag should only be used in managed mode (even in the flags mask).
        ///
        /// Note that the flag can't be changed, it is only valid while adding a station, and attempts to change
        /// it will silently be ignored (rather than rejected as errors.)
        TdlsPeer = 1 << nl80211_sta_flags::NL80211_STA_FLAG_TDLS_PEER as u32,
        /// Station is associated; used with drivers that support [`Nl80211Feature::FulApClientState`] to transition
        /// a previously added station into associated state
        Associated = 1 << nl80211_sta_flags::NL80211_STA_FLAG_ASSOCIATED as u32,
        /// Station supports SPP A-MSDUs
        SppAmsdu = 1 << nl80211_sta_flags::NL80211_STA_FLAG_SPP_AMSDU as u32,
    }
);

/// HE guard interval (`enum nl80211_he_gi`)
#[neli::neli_enum(serialized_type = "u8")]
pub enum Nl80211HeGi {
    /// 0.8 usec
    Gi08 = nl80211_he_gi::NL80211_RATE_INFO_HE_GI_0_8 as u8,
    /// 1.6 usec
    Gi16 = nl80211_he_gi::NL80211_RATE_INFO_HE_GI_1_6 as u8,
    /// 3.2 usec
    Gi32 = nl80211_he_gi::NL80211_RATE_INFO_HE_GI_3_2 as u8,
}

/// HE RU allocation values (`enum nl80211_he_ru_alloc`)
#[neli::neli_enum(serialized_type = "u8")]
pub enum Nl80211HeRuAlloc {
    /// 26-tone RU allocation
    Ru26 = nl80211_he_ru_alloc::NL80211_RATE_INFO_HE_RU_ALLOC_26 as u8,
    /// 52-tone RU allocation
    Ru52 = nl80211_he_ru_alloc::NL80211_RATE_INFO_HE_RU_ALLOC_52 as u8,
    /// 106-tone RU allocation
    Ru106 = nl80211_he_ru_alloc::NL80211_RATE_INFO_HE_RU_ALLOC_106 as u8,
    /// 242-tone RU allocation
    Ru242 = nl80211_he_ru_alloc::NL80211_RATE_INFO_HE_RU_ALLOC_242 as u8,
    /// 484-tone RU allocation
    Ru484 = nl80211_he_ru_alloc::NL80211_RATE_INFO_HE_RU_ALLOC_484 as u8,
    /// 996-tone RU allocation
    Ru996 = nl80211_he_ru_alloc::NL80211_RATE_INFO_HE_RU_ALLOC_996 as u8,
    /// 2x996-tone RU allocation
    Ru2x996 = nl80211_he_ru_alloc::NL80211_RATE_INFO_HE_RU_ALLOC_2x996 as u8,
}

/// EHT guard interval (`enum nl80211_eht_gi`)
#[neli::neli_enum(serialized_type = "u8")]
pub enum Nl80211EhtGi {
    /// 0.8 usec
    Gi08 = nl80211_eht_gi::NL80211_RATE_INFO_EHT_GI_0_8 as u8,
    /// 1.6 usec
    Gi16 = nl80211_eht_gi::NL80211_RATE_INFO_EHT_GI_1_6 as u8,
    /// 3.2 usec
    Gi32 = nl80211_eht_gi::NL80211_RATE_INFO_EHT_GI_3_2 as u8,
}

/// EHT RU allocation values (`enum nl80211_eht_ru_alloc`)
#[neli::neli_enum(serialized_type = "u8")]
pub enum Nl80211EhtRuAlloc {
    /// 26-tone RU allocation
    Ru26 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_26 as u8,
    /// 52-tone RU allocation
    Ru52 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_52 as u8,
    /// 52+26-tone RU allocation
    Ru52P26 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_52P26 as u8,
    /// 106-tone RU allocation
    Ru106 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_106 as u8,
    /// 106+26-tone RU allocation
    Ru106P26 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_106P26 as u8,
    /// 242-tone RU allocation
    Ru242 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_242 as u8,
    /// 484-tone RU allocation
    Ru484 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_484 as u8,
    /// 484+242-tone RU allocation
    Ru484P242 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_484P242 as u8,
    /// 996-tone RU allocation
    Ru996 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_996 as u8,
    /// 996+484 tone RU allocation
    Ru996P424 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_996P484 as u8,
    /// 996+484+242 tone RU allocation
    Ru996P424P242 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_996P484P242 as u8,
    /// 2x996-tone RU allocation
    Ru2x996 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_2x996 as u8,
    /// 2x996+484 tone RU allocation
    Ru2x996P424 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_2x996P484 as u8,
    /// 3x996-tone RU allocation
    Ru3x996 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_3x996 as u8,
    /// 3x996+484 tone RU allocation
    Ru3x996P424 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_3x996P484 as u8,
    /// 4x996-tone RU allocation
    Ru4x996 = nl80211_eht_ru_alloc::NL80211_RATE_INFO_EHT_RU_ALLOC_4x996 as u8,
}

/// Bitrate information (`enum nl80211_rate_info`)
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211RateInfo {
    /// Total bitrate (`u16`, 100kbit/s)
    Bitrate = nl80211_rate_info::NL80211_RATE_INFO_BITRATE as u16,
    /// MCS index for 802.11n (`u8`)
    Mcs = nl80211_rate_info::NL80211_RATE_INFO_MCS as u16,
    /// 40 MHz dualchannel bitrate
    Width40Mhz = nl80211_rate_info::NL80211_RATE_INFO_40_MHZ_WIDTH as u16,
    /// 400ns guard interval
    ShortGi = nl80211_rate_info::NL80211_RATE_INFO_SHORT_GI as u16,
    /// total bitrate (`u32`, 100kbit/s)
    Bitrate32 = nl80211_rate_info::NL80211_RATE_INFO_BITRATE32 as u16,
    /// MCS index for VHT (`u8`)
    VhtMcs = nl80211_rate_info::NL80211_RATE_INFO_VHT_MCS as u16,
    /// Number of streams in VHT (`u8`)
    VhtNss = nl80211_rate_info::NL80211_RATE_INFO_VHT_NSS as u16,
    /// 80 MHz VHT rate
    Width80Mhz = nl80211_rate_info::NL80211_RATE_INFO_80_MHZ_WIDTH as u16,
    /// Unused - 80+80 is treated the same as 160 MHz for purposes of bitrates
    Width80P80Mhz = nl80211_rate_info::NL80211_RATE_INFO_80P80_MHZ_WIDTH as u16,
    /// 160 MHz VHT rate
    Width160Mhz = nl80211_rate_info::NL80211_RATE_INFO_160_MHZ_WIDTH as u16,
    /// 10 MHz width - note that this is a legacy rate and will be reported
    /// as the actual bitrate, i.e. half the base (20 MHz) rate
    Width10Mhz = nl80211_rate_info::NL80211_RATE_INFO_10_MHZ_WIDTH as u16,
    /// 5 MHz width - note that this is a legacy rate and will be reported
    /// as the actual bitrate, i.e. a quarter of the base (20 MHz) rate
    Width5Mhz = nl80211_rate_info::NL80211_RATE_INFO_5_MHZ_WIDTH as u16,
    /// HE MCS index (`u8`, 0-11)
    HeMcs = nl80211_rate_info::NL80211_RATE_INFO_HE_MCS as u16,
    /// HE NSS value (`u8`, 1-8)
    HeNss = nl80211_rate_info::NL80211_RATE_INFO_HE_NSS as u16,
    /// HE guard interval identifier (`u8`, see [`Nl80211HeGi`])
    HeGi = nl80211_rate_info::NL80211_RATE_INFO_HE_GI as u16,
    /// HE DCM value (`u8`, 0/1)
    HeDcm = nl80211_rate_info::NL80211_RATE_INFO_HE_DCM as u16,
    /// HE RU allocation, if not present then non-OFDMA was used
    /// (`u8`, see [`Nl80211HeRuAlloc`])
    HeRuAlloc = nl80211_rate_info::NL80211_RATE_INFO_HE_RU_ALLOC as u16,
    /// 320 MHz bitrate
    Width320Mhz = nl80211_rate_info::NL80211_RATE_INFO_320_MHZ_WIDTH as u16,
    /// EHT MCS index (`u8`, 0-15)
    EhtMcs = nl80211_rate_info::NL80211_RATE_INFO_EHT_MCS as u16,
    /// EHT NSS value (`u8`, 1-8)
    EhtNss = nl80211_rate_info::NL80211_RATE_INFO_EHT_NSS as u16,
    /// EHT guard interval identifier (`u8`, see [`Nl80211EhtGi`])
    EhtGi = nl80211_rate_info::NL80211_RATE_INFO_EHT_GI as u16,
    /// EHT RU allocation, if not present then non-OFDMA was used
    /// (`u8`, see [`Nl80211EhtRuAlloc`])
    EhtRuAlloc = nl80211_rate_info::NL80211_RATE_INFO_EHT_RU_ALLOC as u16,
    /// S1G MCS index (`u8`, 0-10)
    S1gMcs = nl80211_rate_info::NL80211_RATE_INFO_S1G_MCS as u16,
    /// S1G NSS value (`u8`, 1-4)
    S1gNss = nl80211_rate_info::NL80211_RATE_INFO_S1G_NSS as u16,
    /// 1 MHz S1G rate
    Width1Mhz = nl80211_rate_info::NL80211_RATE_INFO_1_MHZ_WIDTH as u16,
    /// 2 MHz S1G rate
    Width2Mhz = nl80211_rate_info::NL80211_RATE_INFO_2_MHZ_WIDTH as u16,
    /// 4 MHz S1G rate
    Width4Mhz = nl80211_rate_info::NL80211_RATE_INFO_4_MHZ_WIDTH as u16,
    /// 8 MHz S1G rate
    Width8Mhz = nl80211_rate_info::NL80211_RATE_INFO_8_MHZ_WIDTH as u16,
    /// 16 MHz S1G rate
    Width16Mhz = nl80211_rate_info::NL80211_RATE_INFO_16_MHZ_WIDTH as u16,
    /// UHR MCS index (`u8`, 0-15, 17, 19, 20, 23)
    ///
    /// Note that the other EHT attributes (such as `Nl80211EhtGi:Gi16`) are used in conjunction with this where applicable
    UhrMcs = nl80211_rate_info::NL80211_RATE_INFO_UHR_MCS as u16,
    /// UHR ELR flag, which restricts NSS to 1, MCS to 0 or 1, and GI to [`Nl80211EhtGi::Gi16`].
    UhrElr = nl80211_rate_info::NL80211_RATE_INFO_UHR_ELR as u16,
    /// UHR Interference Mitigation flag
    UhrIm = nl80211_rate_info::NL80211_RATE_INFO_UHR_IM as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211RateInfo {}

/// BSS information collected by STA (`enum nl80211_sta_bss_param`)
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211StaBssParam {
    /// Whether CTS protection is enabled (flag)
    CtsProt = nl80211_sta_bss_param::NL80211_STA_BSS_PARAM_CTS_PROT as u16,
    /// Whether short short preamble is enabled (flag)
    ShortPreamble = nl80211_sta_bss_param::NL80211_STA_BSS_PARAM_SHORT_PREAMBLE as u16,
    /// Whether short slot time is enabled (flag)
    ShortSlotTime = nl80211_sta_bss_param::NL80211_STA_BSS_PARAM_SHORT_SLOT_TIME as u16,
    /// DTIM period for beaconing (`u8`)
    DtimPeriod = nl80211_sta_bss_param::NL80211_STA_BSS_PARAM_DTIM_PERIOD as u16,
    /// Beacon interval (`u16`)
    BeaconInterval = nl80211_sta_bss_param::NL80211_STA_BSS_PARAM_BEACON_INTERVAL as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211StaBssParam {}

/// Station information (`enum nl80211_sta_info`)
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211StaInfo {
    /// Time since last activity (`u32`, msecs)
    InactiveTime = nl80211_sta_info::NL80211_STA_INFO_INACTIVE_TIME as u16,
    /// Total received bytes (MPDU length) (`u32`, from this station)
    RxBytes = nl80211_sta_info::NL80211_STA_INFO_RX_BYTES as u16,
    /// Total transmitted bytes (MPDU length) (`u32`, to this station)
    TxBytes = nl80211_sta_info::NL80211_STA_INFO_TX_BYTES as u16,
    /// The station's mesh LLID
    Llid = nl80211_sta_info::NL80211_STA_INFO_LLID as u16,
    /// The station's mesh PLID
    Plid = nl80211_sta_info::NL80211_STA_INFO_PLID as u16,
    /// Peer link state for the station see `enum nl80211_plink_state`
    // TODO: Impl mesh nl80211_plink_state
    PlinkState = nl80211_sta_info::NL80211_STA_INFO_PLINK_STATE as u16,
    /// Signal strength of last received PPDU (i8, dBm)
    Signal = nl80211_sta_info::NL80211_STA_INFO_SIGNAL as u16,
    /// Current unicast tx rate, nested attribute containing info as possible,
    /// see [`Nl80211RateInfo`]
    TxBitrate = nl80211_sta_info::NL80211_STA_INFO_TX_BITRATE as u16,
    /// Total received packet (MSDUs and MMPDUs) (`u32`, from this station)
    RxPackets = nl80211_sta_info::NL80211_STA_INFO_RX_PACKETS as u16,
    /// Total transmitted packets (MSDUs and MMPDUs) (`u32`, to this station)
    TxPackets = nl80211_sta_info::NL80211_STA_INFO_TX_PACKETS as u16,
    /// Total retries (MPDUs) (`u32`, to this station)
    TxRetries = nl80211_sta_info::NL80211_STA_INFO_TX_RETRIES as u16,
    /// Total failed packets (MPDUs) (`u32`, to this station)
    TxFailed = nl80211_sta_info::NL80211_STA_INFO_TX_FAILED as u16,
    /// Signal strength average (`i8`, dBm)
    SignalAvg = nl80211_sta_info::NL80211_STA_INFO_SIGNAL_AVG as u16,
    /// Last unicast data frame rx rate, nested ttribute, like [`Nl80211StaInfo::TxBitrate`]
    RxBitrate = nl80211_sta_info::NL80211_STA_INFO_RX_BITRATE as u16,
    /// Current station's view of BSS, nested attribute containing info as possible,
    /// see [`Nl80211StaBssParam`]
    BssParam = nl80211_sta_info::NL80211_STA_INFO_BSS_PARAM as u16,
    /// Time since the station is last connected
    ConnectedTime = nl80211_sta_info::NL80211_STA_INFO_CONNECTED_TIME as u16,
    /// Contains a `struct nl80211_sta_flag`_update.
    // TODO: struct nl80211_sta_flag_update ???
    StaFlags = nl80211_sta_info::NL80211_STA_INFO_STA_FLAGS as u16,
    /// Count of times beacon loss was detected (`u32`)
    BeaconLoss = nl80211_sta_info::NL80211_STA_INFO_BEACON_LOSS as u16,
    /// Timing offset with respect to this STA (`i64`)
    TOffset = nl80211_sta_info::NL80211_STA_INFO_T_OFFSET as u16,
    /// Local mesh STA link-specific power mode
    LocalPm = nl80211_sta_info::NL80211_STA_INFO_LOCAL_PM as u16,
    /// Peer mesh STA link-specific power mode
    PeerPm = nl80211_sta_info::NL80211_STA_INFO_PEER_PM as u16,
    /// Neighbor mesh STA power save mode towards on-peer STA
    NonPeerPm = nl80211_sta_info::NL80211_STA_INFO_NONPEER_PM as u16,
    /// Total received bytes (MPDU length) (`u64`, from this station)
    RxBytes64 = nl80211_sta_info::NL80211_STA_INFO_RX_BYTES64 as u16,
    /// Total transmitted bytes (MPDU length) (`u64`, to this station)
    TxBytes64 = nl80211_sta_info::NL80211_STA_INFO_TX_BYTES64 as u16,
    /// Per-chain signal strength of last PPDU contains a nested array of
    /// signal strength attributes (`i8`, dBm)
    ChainSignal = nl80211_sta_info::NL80211_STA_INFO_CHAIN_SIGNAL as u16,
    /// Per-chain signal strength average. Same format as [`Nl80211StaInfo::ChainSignal`].
    ChainSignalAvg = nl80211_sta_info::NL80211_STA_INFO_CHAIN_SIGNAL_AVG as u16,
    /// Expected throughput considering also the 802.11 header (`u32`, kbps)
    ExpectedThroughput = nl80211_sta_info::NL80211_STA_INFO_EXPECTED_THROUGHPUT as u16,
    /// RX packets dropped for unspecified reasons (`u64`)
    RxDropMisc = nl80211_sta_info::NL80211_STA_INFO_RX_DROP_MISC as u16,
    /// Number of beacons received from this peer (`u64`)
    BeaconRx = nl80211_sta_info::NL80211_STA_INFO_BEACON_RX as u16,
    /// Signal strength average for beacons only (`u8`, dBm)
    BeaconSignalAvg = nl80211_sta_info::NL80211_STA_INFO_BEACON_SIGNAL_AVG as u16,
    /// Per-TID statistics (see [`Nl80211TidStats`]).
    ///
    /// This is a nested attribute where each the inner attribute number is the TID+1
    /// and the special TID 16 (i.e. value 17) is used for non-QoS frames; each one of
    /// those is again nested with [`Nl80211TidStats`] attributes carrying the actual values.
    TidStats = nl80211_sta_info::NL80211_STA_INFO_TID_STATS as u16,
    /// Aggregate PPDU duration for all frames received from the station (`u64`, usec)
    RxDuration = nl80211_sta_info::NL80211_STA_INFO_RX_DURATION as u16,
    /// Attribute used for padding for 64-bit alignment
    Pad = nl80211_sta_info::NL80211_STA_INFO_PAD as u16,
    /// Signal strength of the last ACK frame (`u8`, dBm)
    AckSignal = nl80211_sta_info::NL80211_STA_INFO_ACK_SIGNAL as u16,
    /// Avg signal strength of ACK frames (`i8`, dBm)
    AckSignalAvg = nl80211_sta_info::NL80211_STA_INFO_ACK_SIGNAL_AVG as u16,
    /// Total number of received packets (MPDUs) (`u32`, from this station)
    RxMpdus = nl80211_sta_info::NL80211_STA_INFO_RX_MPDUS as u16,
    /// Total number of packets (MPDUs) received with an FCS error (u32, from this station).
    /// This count may not include some packets with an FCS error due to TA corruption. Hence
    /// this counter might not be fully accurate.
    FcsErrorCount = nl80211_sta_info::NL80211_STA_INFO_FCS_ERROR_COUNT as u16,
    /// Set to true if STA has a path to a mesh gate (`u8`, 0 or 1)
    ConnectedToGate = nl80211_sta_info::NL80211_STA_INFO_CONNECTED_TO_GATE as u16,
    /// Aggregate PPDU duration for all frames sent to the station (`u64`, usec)
    TxDuration = nl80211_sta_info::NL80211_STA_INFO_TX_DURATION as u16,
    /// Current airtime weight for station (`u16`)
    AirtimeWeight = nl80211_sta_info::NL80211_STA_INFO_AIRTIME_WEIGHT as u16,
    /// Airtime link metric for mesh station
    AirtimeLinkMetric = nl80211_sta_info::NL80211_STA_INFO_AIRTIME_LINK_METRIC as u16,
    /// Timestamp (CLOCK_BOOTTIME, nanoseconds) of STA's association
    AssocAtBoottime = nl80211_sta_info::NL80211_STA_INFO_ASSOC_AT_BOOTTIME as u16,
    /// Set to true if STA has a path to authentication server (`u8`, 0 or 1)
    ConnectedToAs = nl80211_sta_info::NL80211_STA_INFO_CONNECTED_TO_AS as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211StaInfo {}

/// Per-TID statistics attributes (`enum nl80211_tid_stats`)
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211TidStats {
    /// Number of MSDUs received (`u64`)
    RxMsdu = nl80211_tid_stats::NL80211_TID_STATS_RX_MSDU as u16,
    /// Number of MSDUs transmitted (or attempted to transmit; `u64`)
    TxMsdu = nl80211_tid_stats::NL80211_TID_STATS_TX_MSDU as u16,
    /// Number of retries for transmitted MSDUs (not counting the first attempt; `u64`)
    TxMsduRetries = nl80211_tid_stats::NL80211_TID_STATS_TX_MSDU_RETRIES as u16,
    /// Number of failed transmitted MSDUs (`u64`)
    TxMsduFailed = nl80211_tid_stats::NL80211_TID_STATS_TX_MSDU_FAILED as u16,
    /// Attribute used for padding for 64-bit alignment
    Pad = nl80211_tid_stats::NL80211_TID_STATS_PAD as u16,
    /// TXQ stats (nested attribute)
    TxqStats = nl80211_tid_stats::NL80211_TID_STATS_TXQ_STATS as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211TidStats {}

/// Per TXQ statistics attributes (`enum nl80211_txq_stats`)
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211TxqStats {
    /// Number of bytes currently backlogged
    BacklogBytes = nl80211_txq_stats::NL80211_TXQ_STATS_BACKLOG_BYTES as u16,
    /// Number of packets currently backlogged
    BacklogPackets = nl80211_txq_stats::NL80211_TXQ_STATS_BACKLOG_PACKETS as u16,
    /// Total number of new flows seen
    Flows = nl80211_txq_stats::NL80211_TXQ_STATS_FLOWS as u16,
    /// Total number of packet drops
    Drops = nl80211_txq_stats::NL80211_TXQ_STATS_DROPS as u16,
    /// Total number of packet ECN marks
    EcnMarks = nl80211_txq_stats::NL80211_TXQ_STATS_ECN_MARKS as u16,
    /// Number of drops due to queue space overflow
    Overlimit = nl80211_txq_stats::NL80211_TXQ_STATS_OVERLIMIT as u16,
    /// Number of drops due to memory limit overflow (only for per-phy stats)
    Overmemory = nl80211_txq_stats::NL80211_TXQ_STATS_OVERMEMORY as u16,
    /// Number of hash collisions
    Collisions = nl80211_txq_stats::NL80211_TXQ_STATS_COLLISIONS as u16,
    /// Total number of bytes dequeued from TXQ
    Bytes = nl80211_txq_stats::NL80211_TXQ_STATS_TX_BYTES as u16,
    /// Total number of packets dequeued from TXQ
    Packets = nl80211_txq_stats::NL80211_TXQ_STATS_TX_PACKETS as u16,
    /// Number of flow buckets for phy
    MaxFlows = nl80211_txq_stats::NL80211_TXQ_STATS_MAX_FLOWS as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211TxqStats {}

/// Band attributes (`enum nl80211_band_attr`)
///
/// Payload for `Nl80211Attr::WiphyBands`
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211BandAttr {
    /// Attribute number 0 is reserved
    Invalid = nl80211_band_attr::__NL80211_BAND_ATTR_INVALID as u16,
    /// Supported frequencies in this band, an array of nested frequency attributes
    Freqs = nl80211_band_attr::NL80211_BAND_ATTR_FREQS as u16,
    /// Supported bitrates in this band, an array of nested bitrate attributes
    Rates = nl80211_band_attr::NL80211_BAND_ATTR_RATES as u16,
    /// 16-byte attribute containing the MCS set as defined in 802.11n
    HtMcsSet = nl80211_band_attr::NL80211_BAND_ATTR_HT_MCS_SET as u16,
    /// HT capabilities, as in the HT information IE
    HtCapa = nl80211_band_attr::NL80211_BAND_ATTR_HT_CAPA as u16,
    /// A-MPDU factor, as in 11n
    HtAmpduFactor = nl80211_band_attr::NL80211_BAND_ATTR_HT_AMPDU_FACTOR as u16,
    /// A-MPDU density, as in 11n
    HtAmpduDensity = nl80211_band_attr::NL80211_BAND_ATTR_HT_AMPDU_DENSITY as u16,
    /// 32-byte attribute containing the MCS set as defined in 802.11ac
    VhtMcsSet = nl80211_band_attr::NL80211_BAND_ATTR_VHT_MCS_SET as u16,
    /// VHT capabilities, as in the HT information IE
    VhtCapa = nl80211_band_attr::NL80211_BAND_ATTR_VHT_CAPA as u16,
    /// Nested array attribute, with each entry using attributes from `enum nl80211_band_iftype_attr`
    // TODO: enum nl80211_band_iftype_attr
    IftypeData = nl80211_band_attr::NL80211_BAND_ATTR_IFTYPE_DATA as u16,
    /// Bitmap that indicates the 2.16 GHz channel(s) that are allowed to be used for EDMG transmissions.
    ///
    /// Defined by IEEE P802.11ay/D4.0 section 9.4.2.251.
    EdmgChannels = nl80211_band_attr::NL80211_BAND_ATTR_EDMG_CHANNELS as u16,
    /// Channel BW Configuration subfield encodes the allowed channel bandwidth configurations.
    ///
    /// Defined by IEEE P802.11ay/D4.0 section 9.4.2.251, Table 13.
    EdmgBwConfig = nl80211_band_attr::NL80211_BAND_ATTR_EDMG_BW_CONFIG as u16,
    /// S1G capabilities, supported S1G-MCS and NSS set subfield, as in the S1G information IE, 5 bytes
    S1gMcsNssSet = nl80211_band_attr::NL80211_BAND_ATTR_S1G_MCS_NSS_SET as u16,
    /// S1G capabilities information subfield as in the S1G information IE, 10 bytes
    S1gCapa = nl80211_band_attr::NL80211_BAND_ATTR_S1G_CAPA as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211BandAttr {}

// TODO: There are several CPP defines which appear to manage attribute name changes or deprecation.
//       Do we want to handle that in this module?
/// Frequency attributes (`enum nl80211_frequency_attr`)
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211FrequencyAttr {
    /// Attribute number 0 is reserved
    Invalid = nl80211_frequency_attr::__NL80211_FREQUENCY_ATTR_INVALID as u16,
    /// Frequency in MHz
    Freq = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_FREQ as u16,
    /// Channel is disabled in current regulatory domain.
    Disabled = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_DISABLED as u16,
    /// No mechanisms that initiate radiation are permitted on this channel, this includes sending probe
    /// requests, or modes of operation that require beaconing.
    NoIr = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_IR as u16,
    /// Obsolete, same as [`Nl80211FrequencyAttr::NoIr`]
    // TODO: Mark as deprecated?
    NoIbss = nl80211_frequency_attr::__NL80211_FREQUENCY_ATTR_NO_IBSS as u16,
    /// Radar detection is mandatory on this channel in current regulatory domain.
    Radar = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_RADAR as u16,
    /// Maximum transmission power in mBm (100 * dBm).
    MaxTxPower = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_MAX_TX_POWER as u16,
    /// Current state for DFS (`enum nl80211_dfs_state`)
    // TODO: enum nl80211_dfs_state
    DfsState = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_DFS_STATE as u16,
    /// Time in milliseconds for how long this channel is in this DFS state.
    DfsTime = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_DFS_TIME as u16,
    /// HT40- isn't possible with this channel as the control channel
    NoHt40Minus = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_HT40_MINUS as u16,
    /// HT40+ isn't possible with this channel as the control channel
    NoHt40Plus = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_HT40_PLUS as u16,
    /// Any 80 MHz channel using this channel as the primary or any of the secondary channels isn't
    /// possible, this includes 80+80 channels
    No80Mhz = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_80MHZ as u16,
    /// Any 160 MHz (but not 80+80) channel using this channel as the primary or any of the secondary
    /// channels isn't possible
    No160Mhz = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_160MHZ as u16,
    /// DFS CAC time in milliseconds.
    DfsCacTime = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_DFS_CAC_TIME as u16,
    /// Only indoor use is permitted on this channel.
    ///
    /// A channel that has the [`Nl80211FrequencyAttr::IndoorOnly`] attribute can only be used when
    /// there is a clear assessment that the device is operating in an indoor surroundings, i.e.
    /// it is connected to AC power (and not through portable DC inverters) or is under the control
    /// of a master that is acting as an AP and is connected to AC power.
    IndoorOnly = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_INDOOR_ONLY as u16,
    /// IR operation is allowed on this channel if it's connected concurrently to a BSS on the same channel
    /// on the 2 GHz band or to a channel in the same UNII band (on the 5 GHz band), and `IEEE80211_CHAN_RADAR`
    /// is not set.
    ///
    /// Instantiating a GO or TDLS off-channel on a channel that has the [`Nl80211FrequencyAttr::IrConcurrent`]
    /// attribute set can be done when there is a clear assessment that the device is operating under the
    /// guidance of an authorized master, i.e., setting up a GO or TDLS off-channel while the device is also
    /// connected to an AP with DFS and radar detection on the UNII band (it is up to user-space, i.e. `wpa_supplicant`
    /// to perform the required verifications).
    ///
    /// Using this attribute for IR is disallowed for master interfaces ([`Nl80211Iftype::Adhoc`], [`Nl80211Iftype::Ap`]).
    IrConcurrent = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_IR_CONCURRENT as u16,
    /// 20 MHz operation is not allowed on this channel in current regulatory domain.
    No20Mhz = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_20MHZ as u16,
    /// 10 MHz operation is not allowed on this channel in current regulatory domain.
    No10Mhz = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_10MHZ as u16,
    /// This channel has WMM limitations.
    ///
    /// This is a nested attribute that contains the WMM limitation per AC (see `enum nl80211_wmm_rule`).
    // TODO: enum nl80211_wmm_rule
    Wmm = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_WMM as u16,
    /// HE operation is not allowed on this channel in current regulatory domain.
    NoHe = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_HE as u16,
    /// Frequency offset in KHz
    Offset = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_OFFSET as u16,
    /// 1 MHz operation is allowed on this channel in current regulatory domain.
    _1Mhz = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_1MHZ as u16,
    /// 2 MHz operation is allowed on this channel in current regulatory domain.
    _2Mhz = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_2MHZ as u16,
    /// 4 MHz operation is allowed on this channel in current regulatory domain.
    _4Mhz = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_4MHZ as u16,
    /// 8 MHz operation is allowed on this channel in current regulatory domain.
    _8Mhz = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_8MHZ as u16,
    /// 16 MHz operation is allowed on this channel in current regulatory domain.
    _16Mhz = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_16MHZ as u16,
    /// Any 320 MHz channel using this channel as the primary or any of the secondary channels isn't possible
    No320Mhz = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_320MHZ as u16,
    /// EHT operation is not allowed on this channel in current regulatory domain.
    NoEht = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_EHT as u16,
    /// Power spectral density (in dBm) that is allowed on this channel in current regulatory domain.
    Psd = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_PSD as u16,
    /// Operation on this channel is allowed for peer-to-peer (P2P) or adhoc (IBSS) communication under
    /// the control of a DFS master which operates on the same channel (FCC-594280 D01 Section B.3).
    ///
    /// Should be used together with `NL80211_RRF_DFS` only.
    // TODO: enum nl80211_reg_rule_flags
    DfsConcurrent = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_DFS_CONCURRENT as u16,
    /// Client connection to VLP AP not allowed using this channel
    No6GhzVlpClient = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_6GHZ_VLP_CLIENT as u16,
    /// Client connection to AFC AP not allowed using this channel
    No6GhzAfcClient = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_6GHZ_AFC_CLIENT as u16,
    /// This channel can be used in monitor mode despite other (regulatory) restrictions, even if
    /// the channel is otherwise completely disabled.
    CanMonitor = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_CAN_MONITOR as u16,
    /// This channel can be used for a very low power (VLP) AP, despite being [`Nl80211FrequencyAttr::NoIr`].
    Allow6GhzVlpAp = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_ALLOW_6GHZ_VLP_AP as u16,
    /// This channel can be active in 20 MHz bandwidth, despite being [`Nl80211FrequencyAttr::NoIr`].
    Allow20MhzActivity = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_ALLOW_20MHZ_ACTIVITY as u16,
    // v7.1+
    /// 4 MHz operation is not allowed on this channel in current regulatory domain.
    No4Mhz = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_4MHZ as u16,
    /// 8 MHz operation is not allowed on this channel in current regulatory domain.
    No8MHz = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_8MHZ as u16,
    /// 16 MHz operation is not allowed on this channel in current regulatory domain.
    No16MHz = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_16MHZ as u16,
    /// Channel is not permitted for use as a primary channel.
    ///
    /// Does not prevent the channel from existing as a non-primary subchannel.
    /// Only applicable to S1G channels.
    S1gNoPrimary = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_S1G_NO_PRIMARY as u16,
    /// UHR operation is not allowed on this channel in current regulatory domain.
    NoUhr = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_NO_UHR as u16,
    /// Channel Availability Check (CAC) start time (CLOCK_BOOTTIME, nanoseconds).
    ///
    /// Only present when CAC is currently in progress on this channel.
    CacStartTime = nl80211_frequency_attr::NL80211_FREQUENCY_ATTR_CAC_START_TIME as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211FrequencyAttr {}

/// Bitrate attributes (`enum nl80211_bitrate_attr`)
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211BitrateAttr {
    ///  Attribute number 0 is reserved
    Invalid = nl80211_bitrate_attr::__NL80211_BITRATE_ATTR_INVALID as u16,
    /// Bitrate in units of 100 kbps
    Rate = nl80211_bitrate_attr::NL80211_BITRATE_ATTR_RATE as u16,
    /// Short preamble supported in 2.4 GHz band
    _2GhzShortpreamble = nl80211_bitrate_attr::NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211BitrateAttr {}

/// Indicates the initiator of a reg domain request (`enum nl80211_reg_initiator`)
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211RegInitiator {
    /// Core queried CRDA for a dynamic world regulatory domain.
    SetByCore = nl80211_reg_initiator::NL80211_REGDOM_SET_BY_CORE as u16,
    /// User asked the wireless core to set the regulatory domain.
    SetByUser = nl80211_reg_initiator::NL80211_REGDOM_SET_BY_USER as u16,
    /// A wireless drivers has hinted to the wireless core it thinks its knows the regulatory domain we should be in.
    SetByDriver = nl80211_reg_initiator::NL80211_REGDOM_SET_BY_DRIVER as u16,
    /// The wireless core has received an 802.11 country information element with regulatory information
    /// it thinks we should consider.
    ///
    /// `cfg80211` only processes the country code from the IE, and relies on the regulatory domain information
    /// structure passed by userspace (CRDA) from our wireless-regdb.
    ///
    /// If a channel is enabled but the country code indicates it should be disabled we disable the channel
    /// and re-enable it upon disassociation.
    SetByCountryIe = nl80211_reg_initiator::NL80211_REGDOM_SET_BY_COUNTRY_IE as u16,
}

/// Specifies the type of regulatory domain (`enum nl80211_reg_type`)
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211RegType {
    /// The regulatory domain set is one that pertains to a specific country.
    ///
    /// When this is set you can count on the ISO / IEC 3166 alpha2 country code being valid.
    Country = nl80211_reg_type::NL80211_REGDOM_TYPE_COUNTRY as u16,
    /// The regulatory set domain is the world regulatory domain.
    World = nl80211_reg_type::NL80211_REGDOM_TYPE_WORLD as u16,
    /// The regulatory domain set is a custom driver specific world regulatory domain.
    ///
    /// These do not apply system-wide and are only applicable to the individual devices which have
    /// requested them to be applied.
    CustomWorld = nl80211_reg_type::NL80211_REGDOM_TYPE_CUSTOM_WORLD as u16,
    /// The regulatory domain set is the product of an intersection between two regulatory domains
    /// -- the previously set regulatory domain on the system and the last accepted regulatory domain
    /// request to be processed.
    Intersection = nl80211_reg_type::NL80211_REGDOM_TYPE_INTERSECTION as u16,
}

/// Regulatory rule attributes (`enum nl80211_reg_rule_attr`)
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211RegRuleAttr {
    /// A set of flags which specify additional considerations for a given frequency range.
    /// These are the [`Nl80211RegRuleFlags`].
    Flags = nl80211_reg_rule_attr::NL80211_ATTR_REG_RULE_FLAGS as u16,
    /// Starting frequencry for the regulatory rule in KHz.
    ///
    /// This is not a center of frequency but an actual regulatory band edge.
    FreqRangeStart = nl80211_reg_rule_attr::NL80211_ATTR_FREQ_RANGE_START as u16,
    /// Ending frequency for the regulatory rule in KHz.
    ///
    /// This is not a center a frequency but an actual regulatory band edge.
    FreqRangeEnd = nl80211_reg_rule_attr::NL80211_ATTR_FREQ_RANGE_END as u16,
    /// Maximum allowed bandwidth for this frequency range, in KHz.
    FreqRangeMaxBw = nl80211_reg_rule_attr::NL80211_ATTR_FREQ_RANGE_MAX_BW as u16,
    /// The maximum allowed antenna gain for a given frequency range. The value is in mBi (100 * dBi).
    ///
    /// If you don't have one then don't send this.
    PowerRuleMaxAntGain = nl80211_reg_rule_attr::NL80211_ATTR_POWER_RULE_MAX_ANT_GAIN as u16,
    /// The maximum allowed EIRP for a given frequency range. The value is in mBm (100 * dBm).
    PowerRuleMaxEirp = nl80211_reg_rule_attr::NL80211_ATTR_POWER_RULE_MAX_EIRP as u16,
    /// DFS CAC time in milliseconds.
    ///
    /// If not present or 0 default CAC time will be used.
    DfsCacTime = nl80211_reg_rule_attr::NL80211_ATTR_DFS_CAC_TIME as u16,
    /// Power spectral density (in dBm). This could be negative.
    PowerRulePsd = nl80211_reg_rule_attr::NL80211_ATTR_POWER_RULE_PSD as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211RegRuleAttr {}

impl_flags!(
    /// Regulatory rule flags (`enum nl80211_reg_rule_flags`)
    pub Nl80211RegRuleFlags: u32 {
        /// OFDM modulation not allowed
        NoOfdm = nl80211_reg_rule_flags::NL80211_RRF_NO_OFDM as u32,
        /// CCK modulation not allowed
        NoCck = nl80211_reg_rule_flags::NL80211_RRF_NO_CCK  as u32,
        /// Indoor operation not allowed
        NoIndoor = nl80211_reg_rule_flags::NL80211_RRF_NO_INDOOR as u32,
        /// Outdoor operation not allowed
        NoOutdoor = nl80211_reg_rule_flags::NL80211_RRF_NO_OUTDOOR as u32,
        /// DFS support is required to be used
        Dfs = nl80211_reg_rule_flags::NL80211_RRF_DFS as u32,
        /// This is only for Point To Point links
        PtpOnly = nl80211_reg_rule_flags::NL80211_RRF_PTP_ONLY as u32,
        /// This is only for Point To Multi Point links
        PtmpOnly = nl80211_reg_rule_flags::NL80211_RRF_PTMP_ONLY as u32,
        /// No mechanisms that initiate radiation are allowed, this includes probe requests or modes
        /// of operation that require beaconing.
        NoIr = nl80211_reg_rule_flags::NL80211_RRF_NO_IR as u32,
        /// Obsolete, same as [`Nl80211RegRuleFlags::NoIr`]
        NoIbss = nl80211_reg_rule_flags::__NL80211_RRF_NO_IBSS as u32,
        /// Maximum available bandwidth should be calculated base on contiguous rules and wider channels
        /// will be allowed to cross multiple contiguous/overlapping frequency ranges.
        AutoBw = nl80211_reg_rule_flags::NL80211_RRF_AUTO_BW as u32,
        /// See [`Nl80211FrequencyAttr::IrConcurrent`]
        IrConcurrent = nl80211_reg_rule_flags::NL80211_RRF_IR_CONCURRENT as u32,
        /// Channels can't be used in HT40- operation
        NoHt40Minus = nl80211_reg_rule_flags::NL80211_RRF_NO_HT40MINUS as u32,
        /// Channels can't be used in HT40+ operation
        NoHt40Plus = nl80211_reg_rule_flags::NL80211_RRF_NO_HT40PLUS as u32,
        /// 80 MHz operation not allowed
        No80Mhz= nl80211_reg_rule_flags::NL80211_RRF_NO_80MHZ as u32,
        /// 160 MHz operation not allowed
        No160Mhz = nl80211_reg_rule_flags::NL80211_RRF_NO_160MHZ as u32,
        /// HE operation not allowed
        NoHe = nl80211_reg_rule_flags::NL80211_RRF_NO_HE as u32,
        /// 320 MHz operation not allowed
        No320Mhz = nl80211_reg_rule_flags::NL80211_RRF_NO_320MHZ as u32,
        /// EHT operation not allowed
        NoEht = nl80211_reg_rule_flags::NL80211_RRF_NO_EHT as u32,
        /// Ruleset has power spectral density value
        Psd = nl80211_reg_rule_flags::NL80211_RRF_PSD   as u32,
        /// Operation on this channel is allowed for peer-to-peer or adhoc communication under the control
        /// of a DFS master which operates on the same channel (FCC-594280 D01 Section B.3).
        ///
        /// Should be used together with [`Nl80211RegRuleFlags::Dfs`] only.
        DfsConcurrent = nl80211_reg_rule_flags::NL80211_RRF_DFS_CONCURRENT          as u32,
        /// Client connection to VLP AP not allowed
        No6GhzVlpClient = nl80211_reg_rule_flags::NL80211_RRF_NO_6GHZ_VLP_CLIENT     as u32,
        /// Client connection to AFC AP not allowed
        No6GhzAfcClient = nl80211_reg_rule_flags::NL80211_RRF_NO_6GHZ_AFC_CLIENT    as u32,
        /// Very low power (VLP) AP can be permitted despite [`Nl80211RegRuleFlags::NoIr`] configuration.
        Allow6GhzVlpAp = nl80211_reg_rule_flags::NL80211_RRF_ALLOW_6GHZ_VLP_AP    as u32,
        /// Allow activity in 20 MHz bandwidth, despite [`Nl80211RegRuleFlags::NoIr`] configuration.
        Allow20MhzActivity = nl80211_reg_rule_flags::NL80211_RRF_ALLOW_20MHZ_ACTIVITY as u32,
        /// UHR operation not allowed.
        NoUhr = nl80211_reg_rule_flags::NL80211_RRF_NO_UHR as u32,
    }
);

/// Regulatory DFS regions (`enum nl80211_dfs_regions`)
#[neli::neli_enum(serialized_type = "u8")]
pub enum Nl80211DfsRegions {
    /// Country has no DFS master region specified
    Unset = nl80211_dfs_regions::NL80211_DFS_UNSET as u8,
    /// Country follows DFS master rules from FCC
    Fcc = nl80211_dfs_regions::NL80211_DFS_FCC as u8,
    /// Country follows DFS master rules from ETSI
    Etsi = nl80211_dfs_regions::NL80211_DFS_ETSI as u8,
    /// Country follows DFS master rules from JP/MKK/Telec
    Jp = nl80211_dfs_regions::NL80211_DFS_JP as u8,
}

/// Survey information (`enum nl80211_survey_info`)
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211SurveyInfo {
    /// Attribute number 0 is reserved
    Invalid = nl80211_survey_info::__NL80211_SURVEY_INFO_INVALID as u16,
    /// Center frequency of channel
    Frequency = nl80211_survey_info::NL80211_SURVEY_INFO_FREQUENCY as u16,
    /// Noise level of channel (`u8`, dBm)
    Noise = nl80211_survey_info::NL80211_SURVEY_INFO_NOISE as u16,
    /// Channel is currently being used
    InUse = nl80211_survey_info::NL80211_SURVEY_INFO_IN_USE as u16,
    /// Amount of time (in ms) that the radio was turned on (on channel or globally)
    Time = nl80211_survey_info::NL80211_SURVEY_INFO_TIME as u16,
    /// Amount of the time the primary channel was sensed busy (either due to activity or energy detect)
    TimeBusy = nl80211_survey_info::NL80211_SURVEY_INFO_TIME_BUSY as u16,
    /// Amount of time the extension channel was sensed busy
    TimeExtBusy = nl80211_survey_info::NL80211_SURVEY_INFO_TIME_EXT_BUSY as u16,
    /// Amount of time the radio spent receiving data (on channel or globally)
    TimeRx = nl80211_survey_info::NL80211_SURVEY_INFO_TIME_RX as u16,
    /// Amount of time the radio spent transmitting data (on channel or globally)
    TimeTx = nl80211_survey_info::NL80211_SURVEY_INFO_TIME_TX as u16,
    /// Time the radio spent for scan (on this channel or globally)
    TimeScan = nl80211_survey_info::NL80211_SURVEY_INFO_TIME_SCAN as u16,
    /// Attribute used for padding for 64-bit alignment
    Pad = nl80211_survey_info::NL80211_SURVEY_INFO_PAD as u16,
    /// Amount of time the radio spent receiving frames destined to the local BSS
    TimeBssRx = nl80211_survey_info::NL80211_SURVEY_INFO_TIME_BSS_RX as u16,
    /// Center frequency offset in KHz
    FrequencyOffset = nl80211_survey_info::NL80211_SURVEY_INFO_FREQUENCY_OFFSET as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211SurveyInfo {}

impl_flags!(
    /// Monitor configuration flags (`enum nl80211_mntr_flags`)
    pub Nl80211MntrFlags: u32 {
        /// Pass frames with bad FCS
        FcsFail = 1 << nl80211_mntr_flags::NL80211_MNTR_FLAG_FCSFAIL as u32,
        /// Pass frames with bad PLCP
        PlcpFail = 1 << nl80211_mntr_flags::NL80211_MNTR_FLAG_PLCPFAIL as u32,
        /// Pass control frames
        Control = 1 << nl80211_mntr_flags::NL80211_MNTR_FLAG_CONTROL as u32,
        /// Disable BSSID filtering
        OtherBss = 1 << nl80211_mntr_flags::NL80211_MNTR_FLAG_OTHER_BSS as u32,
        /// Deprecated. Will unconditionally be refused
        CookFrames = 1 << nl80211_mntr_flags::NL80211_MNTR_FLAG_COOK_FRAMES as u32,
        /// Use the configured MAC address and ACK incoming unicast packets
        Active = 1 << nl80211_mntr_flags::NL80211_MNTR_FLAG_ACTIVE as u32,
        /// Do not pass local TX packets
        SkipTx = 1 << nl80211_mntr_flags::NL80211_MNTR_FLAG_SKIP_TX as u32,
    }
);

/// Channel type (`enum nl80211_channel_type`)
///
/// This is a legacy value, primarily used for identifying legacy and 802.11n (Wi-Fi 4)
/// channel widths from. This information is generally sent along with [`Nl80211ChanWidth`],
/// which together with control and center frequency ([`Nl80211Attr::WiphyFreq`] and
/// [`Nl80211Attr::CenterFreq1`]) can distinguish many more channel types.
#[neli::neli_enum(serialized_type = "u32")]
pub enum Nl80211ChannelType {
    /// 20 MHz, non-HT (legacy) channel
    NoHt = nl80211_channel_type::NL80211_CHAN_NO_HT as u32,
    /// 20 MHz HT channel
    Ht20 = nl80211_channel_type::NL80211_CHAN_HT20 as u32,
    /// 40 MHz HT channel, secondary channel below the control channel
    Ht40Plus = nl80211_channel_type::NL80211_CHAN_HT40PLUS as u32,
    /// 40 MHz HT channel, secondary channel above the control channel
    Ht40Minus = nl80211_channel_type::NL80211_CHAN_HT40MINUS as u32,
}

/// Key mode (`enum nl80211_key_mode`)
#[neli::neli_enum(serialized_type = "u32")]
pub enum Nl80211KeyMode {
    /// (Default) Key can be used for RX and TX immediately.
    ///
    /// The following modes can only be selected for unicast keys and when the
    /// driver supports @NL80211_EXT_FEATURE_EXT_KEY_ID:
    RxTx = nl80211_key_mode::NL80211_KEY_RX_TX as u32,
    /// Only allowed in combination with [`Nl80211Command::NewKey`]: Unicast key can only be used for RX,
    /// TX not allowed, yet.
    NoTx = nl80211_key_mode::NL80211_KEY_NO_TX as u32,
    /// Only allowed in combination with [`Nl80211Command::SetKey`]: The unicast key identified by idx and MAC
    /// is cleared for TX and becomes the preferred TX key for the station.
    SetTx = nl80211_key_mode::NL80211_KEY_SET_TX as u32,
}

/// Channel width definitions (`enum nl80211_chan_width`)
#[neli::neli_enum(serialized_type = "u32")]
pub enum Nl80211ChanWidth {
    /// 20 MHz, non-HT (legacy) channel
    Width20NoHT = nl80211_chan_width::NL80211_CHAN_WIDTH_20_NOHT as u32,
    /// 20 MHz HT channel
    Width20 = nl80211_chan_width::NL80211_CHAN_WIDTH_20 as u32,
    /// 40 MHz channel, the [`Nl80211Attr::CenterFreq1`] attribute must be provided as well
    Width40 = nl80211_chan_width::NL80211_CHAN_WIDTH_40 as u32,
    /// 80 MHz channel, the [`Nl80211Attr::CenterFreq1`] attribute must be provided as well
    Width80 = nl80211_chan_width::NL80211_CHAN_WIDTH_80 as u32,
    /// 80+80 MHz channel, the [`Nl80211Attr::CenterFreq1`] and [`Nl80211Attr::CenterFreq2`] attributes must be provided as well
    Width80P80 = nl80211_chan_width::NL80211_CHAN_WIDTH_80P80 as u32,
    /// 160 MHz channel, the [`Nl80211Attr::CenterFreq1`] attribute must be provided as well
    Width160 = nl80211_chan_width::NL80211_CHAN_WIDTH_160 as u32,
    /// 5 MHz OFDM channel
    // TODO: Deprecated in 7.1 or 7.2
    Width5 = nl80211_chan_width::NL80211_CHAN_WIDTH_5 as u32,
    /// 10 MHz OFDM channel
    // TODO: Deprecated in 7.1 or 7.2
    Width10 = nl80211_chan_width::NL80211_CHAN_WIDTH_10 as u32,
    /// 1 MHz OFDM channel
    Width1 = nl80211_chan_width::NL80211_CHAN_WIDTH_1 as u32,
    /// 2 MHz OFDM channel
    Width2 = nl80211_chan_width::NL80211_CHAN_WIDTH_2 as u32,
    /// 4 MHz OFDM channel
    Width4 = nl80211_chan_width::NL80211_CHAN_WIDTH_4 as u32,
    /// 8 MHz OFDM channel
    Width8 = nl80211_chan_width::NL80211_CHAN_WIDTH_8 as u32,
    /// 16 MHz OFDM channel
    Width16 = nl80211_chan_width::NL80211_CHAN_WIDTH_16 as u32,
    /// 320 MHz channel, the [`Nl80211Attr::CenterFreq1`] attribute must be provided as well
    Width320 = nl80211_chan_width::NL80211_CHAN_WIDTH_320 as u32,
}

impl_flags!(
    /// Bitmap indicating possible BSS use (`enum nl80211_bss_use_for`)
    pub Nl80211BssUseFor: u32 {
        /// Use this BSS for normal "connection", including IBSS/MBSS depending on the type.
        Normal = nl80211_bss_use_for::NL80211_BSS_USE_FOR_NORMAL as u32,
        /// This BSS can be used as a link in an MLO connection.
        ///
        /// Note that for an MLO connection, all links including the assoc link must have this flag set,
        /// and the assoc link must additionally have [`Nl80211BssUseFor::Normal`] set.
        MldLink = nl80211_bss_use_for::NL80211_BSS_USE_FOR_MLD_LINK as u32,
    }
);

impl_flags!(
    /// Reason(s) connection to a BSS isn't possible (`enum nl80211_bss_cannot_use_reasons`)
    pub Nl80211BssCannotUseReasons: u64 {
        /// NSTR nonprimary links aren't supported by the device, and this BSS entry represents one.
        NstrNonPrimary = nl80211_bss_cannot_use_reasons::NL80211_BSS_CANNOT_USE_NSTR_NONPRIMARY as u64,
        /// STA is not supporting the AP power type (SP, VLP, AP) that the AP uses.
        SixGhzPowerMismatch = nl80211_bss_cannot_use_reasons::NL80211_BSS_CANNOT_USE_6GHZ_PWR_MISMATCH as u64,
    }
);

/// Netlink attributes for a BSS (`enum nl80211_bss`)
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211Bss {
    /// BSSID of the BSS (6 octets)
    Bssid = nl80211_bss::NL80211_BSS_BSSID as u16,
    /// Frequency in MHz (`u32`)
    Frequency = nl80211_bss::NL80211_BSS_FREQUENCY as u16,
    /// TSF of the received probe response/beacon (u64) (if [`Nl80211Bss::PrespData`] is present then
    /// this is known to be from a probe response, otherwise it may be from the same beacon that the
    /// [`Nl80211Bss::BeaconTsf`] will be from)
    Tsf = nl80211_bss::NL80211_BSS_TSF as u16,
    /// Beacon interval of the (I)BSS (u16)
    BeaconInterval = nl80211_bss::NL80211_BSS_BEACON_INTERVAL as u16,
    /// Capability field (CPU order, u16)
    Capability = nl80211_bss::NL80211_BSS_CAPABILITY as u16,
    /// Binary attribute containing the raw information elements from the probe response/beacon (bin);
    ///	if the [`Nl80211Bss::BeaconIes`] attribute is present and the data is different then the IEs here
    /// are from a Probe Response frame; otherwise they are from a Beacon frame. However, if the driver
    /// does not indicate the source of the IEs, these IEs may be from either frame subtype. If present,
    /// the [`Nl80211Bss::PrespData`] attribute indicates that the data here is known to be from a probe
    /// response, without any heuristics.
    InformationElements = nl80211_bss::NL80211_BSS_INFORMATION_ELEMENTS as u16,
    /// Signal strength of probe response/beacon in mBm (100 * dBm) (`i32`)
    SignalMbm = nl80211_bss::NL80211_BSS_SIGNAL_MBM as u16,
    /// Signal strength of the probe response/beacon in unspecified units, scaled to 0..100 (`u8`)
    SignalUnspec = nl80211_bss::NL80211_BSS_SIGNAL_UNSPEC as u16,
    /// Status, if this BSS is "used"
    Status = nl80211_bss::NL80211_BSS_STATUS as u16,
    /// Age of this BSS entry in ms
    SeenMsAgo = nl80211_bss::NL80211_BSS_SEEN_MS_AGO as u16,
    /// Binary attribute containing the raw information elements from a Beacon frame (bin);
    /// not present if no Beacon frame has yet been received
    BeaconIes = nl80211_bss::NL80211_BSS_BEACON_IES as u16,
    /// No longer used. Channel width of the control channel (`u32`, `enum nl80211_bss_scan_width`)
    ChanWidth = nl80211_bss::NL80211_BSS_CHAN_WIDTH as u16,
    /// TSF of the last received beacon (`u64`) (not present if no beacon frame has been received yet)
    BeaconTsf = nl80211_bss::NL80211_BSS_BEACON_TSF as u16,
    /// The data in [`Nl80211Bss::InformationElements`] and [`Nl80211Bss::Tsf`] is known to be from a
    /// probe response (flag attribute)
    PrespData = nl80211_bss::NL80211_BSS_PRESP_DATA as u16,
    /// `CLOCK_BOOTTIME` timestamp when this entry was last updated by a received frame. The value is
    /// expected to be accurate to about 10ms. (`u64`, nanoseconds)
    LastSeenSinceBootTime = nl80211_bss::NL80211_BSS_LAST_SEEN_BOOTTIME as u16,
    /// Attribute used for padding for 64-bit alignment
    Pad = nl80211_bss::NL80211_BSS_PAD as u16,
    /// The time at the start of reception of the first octet of the timestamp field of the last
    /// beacon/probe received for this BSS. The time is the TSF of the BSS specified by
    ///	[`Nl80211Bss::ParentBssid`]. (`u64`).
    ParentTsf = nl80211_bss::NL80211_BSS_PARENT_TSF as u16,
    /// The BSS according to which [`Nl80211Bss::ParentTsf`] is set.
    ParentBssid = nl80211_bss::NL80211_BSS_PARENT_BSSID as u16,
    /// Per-chain signal strength of last BSS update. Contains a nested array of signal strength
    /// attributes (`u8`, dBm), using the nesting index as the antenna number.
    ChainSignal = nl80211_bss::NL80211_BSS_CHAIN_SIGNAL as u16,
    /// Frequency offset in KHz
    FrequencyOffset = nl80211_bss::NL80211_BSS_FREQUENCY_OFFSET as u16,
    /// MLO link ID of the BSS (`u8`).
    MloLinkId = nl80211_bss::NL80211_BSS_MLO_LINK_ID as u16,
    /// MLD address of this BSS if connected to it.
    MldAddr = nl80211_bss::NL80211_BSS_MLD_ADDR as u16,
    /// `u32` bitmap attribute indicating what the BSS can be used for, see [`Nl80211BssUseFor`].
    UseFor = nl80211_bss::NL80211_BSS_USE_FOR as u16,
    /// Indicates the reason that this BSS cannot be used for all or some of the possible uses by the
    /// device reporting it, even though its presence was detected.
    ///
    /// This is a `u64` attribute containing a bitmap of values from [`Nl80211BssCannotUseReasons`],
    /// note that the attribute may be missing if no reasons are specified.
    CannotUseReasons = nl80211_bss::NL80211_BSS_CANNOT_USE_REASONS as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211Bss {}

/// Authentication type (`enum nl80211_auth_type`)
#[neli::neli_enum(serialized_type = "u32")]
pub enum Nl80211AuthType {
    /// Open System authentication
    OpenSystem = nl80211_auth_type::NL80211_AUTHTYPE_OPEN_SYSTEM as u32,
    /// Shared Key authentication (WEP only)
    SharedKey = nl80211_auth_type::NL80211_AUTHTYPE_SHARED_KEY as u32,
    /// Fast BSS Transition (IEEE 802.11r)
    FT = nl80211_auth_type::NL80211_AUTHTYPE_FT as u32,
    /// Network EAP (some Cisco APs and mainly LEAP)
    NetworkEap = nl80211_auth_type::NL80211_AUTHTYPE_NETWORK_EAP as u32,
    /// Simultaneous authentication of equals
    Sae = nl80211_auth_type::NL80211_AUTHTYPE_SAE as u32,
    /// Fast Initial Link Setup shared key
    FilsSk = nl80211_auth_type::NL80211_AUTHTYPE_FILS_SK as u32,
    /// Fast Initial Link Setup shared key with PFS
    FilsSkPfs = nl80211_auth_type::NL80211_AUTHTYPE_FILS_SK_PFS as u32,
    /// Fast Initial Link Setup public key
    FilsPk = nl80211_auth_type::NL80211_AUTHTYPE_FILS_PK as u32,
    /// Enhanced Privacy Protection Key Exchange
    Eppke = nl80211_auth_type::NL80211_AUTHTYPE_EPPKE as u32,
    /// IEEE 802.1X authentication utilizing Authentication frames
    Ieee8021x = nl80211_auth_type::NL80211_AUTHTYPE_IEEE8021X as u32,
}

/// Key type (`enum nl80211_key_type`)
#[neli::neli_enum(serialized_type = "u32")]
pub enum Nl80211KeyType {
    /// Group (broadcast/multicast) key.
    Group = nl80211_key_type::NL80211_KEYTYPE_GROUP as u32,
    /// Pairwise (unicast/individual) key.
    Pairwise = nl80211_key_type::NL80211_KEYTYPE_PAIRWISE as u32,
    /// PeerKey (DLS).
    PeerKey = nl80211_key_type::NL80211_KEYTYPE_PEERKEY as u32,
}

/// Management frame protection state (`enum nl80211_mfp`)
#[neli::neli_enum(serialized_type = "u32")]
pub enum Nl80211Mfp {
    /// Management frame protection not used.
    No = nl80211_mfp::NL80211_MFP_NO as u32,
    /// Management frame protection required.
    Required = nl80211_mfp::NL80211_MFP_REQUIRED as u32,
    /// Management frame protection is optional.
    Optional = nl80211_mfp::NL80211_MFP_OPTIONAL as u32,
}

impl_flags!(
    // TODO: No docstring in headerfile, this looks legacy?
    /// TODO (`enum nl80211_wpa_versions`)
    pub Nl80211WpaVersions: u32 {
        WpaVersion1 = nl80211_wpa_versions::NL80211_WPA_VERSION_1 as u32,
        WpaVersion2 = nl80211_wpa_versions::NL80211_WPA_VERSION_2 as u32,
        WpaVersion3 = nl80211_wpa_versions::NL80211_WPA_VERSION_3 as u32,
    }
);

/// Key default types (`enum nl80211_key_default_types`)
#[neli::neli_enum(serialized_type = "u32")]
pub enum Nl80211KeyDefaultTypes {
    /// Invalid.
    Invalid = nl80211_key_default_types::__NL80211_KEY_DEFAULT_TYPE_INVALID as u32,
    /// Key should be used as default unicast key
    Unicast = nl80211_key_default_types::NL80211_KEY_DEFAULT_TYPE_UNICAST as u32,
    /// Key should be used as default multicast key
    Multicast = nl80211_key_default_types::NL80211_KEY_DEFAULT_TYPE_MULTICAST as u32,
}

/// Key attributes (`enum nl80211_key_attributes`)
#[neli::neli_enum(serialized_type = "u32")]
pub enum Nl80211KeyAttributes {
    /// Invalid
    Invalid = nl80211_key_attributes::__NL80211_KEY_INVALID as u32,
    /// Temporal key data; for TKIP this consists of 16 bytes encryption key followed by 8 bytes each for TX and RX MIC keys.
    Data = nl80211_key_attributes::NL80211_KEY_DATA as u32,
    /// Key ID (`u8`, 0-3).
    Idx = nl80211_key_attributes::NL80211_KEY_IDX as u32,
    /// Key cipher suite (`u32`, as defined by IEEE 802.11 section 7.3.2.25.1, e.g. 0x000FAC04)
    Cipher = nl80211_key_attributes::NL80211_KEY_CIPHER as u32,
    /// Transmit key sequence number (IV/PN) for TKIP and CCMP keys, each six bytes in little endian.
    Seq = nl80211_key_attributes::NL80211_KEY_SEQ as u32,
    /// Flag indicating default key.
    Default = nl80211_key_attributes::NL80211_KEY_DEFAULT as u32,
    /// Flag indicating default management key.
    DefaultMgmt = nl80211_key_attributes::NL80211_KEY_DEFAULT_MGMT as u32,
    /// The key type from [`Nl80211KeyType`], if not specified the default depends on whether a MAC address was
    /// given with the command using the key or not (`u32`).
    Type = nl80211_key_attributes::NL80211_KEY_TYPE as u32,
    /// A nested attribute containing flags attributes, specifying what a key should be set as default as.
    /// See [`Nl80211KeyDefaultTypes`].
    DefaultTypes = nl80211_key_attributes::NL80211_KEY_DEFAULT_TYPES as u32,
    /// The mode from [`Nl80211KeyMode`]. Defaults to [`Nl80211KeyMode::RxTx`].
    Mode = nl80211_key_attributes::NL80211_KEY_MODE as u32,
    /// Flag indicating default Beacon frame key.
    DefaultBeacon = nl80211_key_attributes::NL80211_KEY_DEFAULT_BEACON as u32,
    // v7.2+
    /// LTF key seed is used by the driver to generate secure LTF keys used in case of peer measurement request with FTM
    /// request type as either `NL80211_PMSR_FTM_REQ_ATTR_NON_TRIGGER_BASED` or `NL80211_PMSR_FTM_REQ_ATTR_TRIGGER_BASED`
    ///
    /// Secure LTF key seeds will help enable PHY security in peer measurement session.
    ///
    /// The LTF key seed is installed along with the TK (Temporal Key) using [`Nl80211Command::NewKey`]. The TK is configured
    /// using the [`Nl80211Attr::KeyData`] attribute, while the LTF key seed is configured using this attribute. Both keys must
    /// be configured before initiation of peer measurement to ensure peer measurement session is secure.
    ///
    /// Only valid if [`Nl80211ExtFeatureIndex::SetKeyLtfSeed`] is set.
    ///
    /// This attribute is restricted to pairwise keys ([`Nl80211KeyType::Pairwise`]).
    // TODO: enum nl80211_peer_measurement_ftm_req
    LtfSeed = nl80211_key_attributes::NL80211_KEY_LTF_SEED as u32,
}

/// Frequency band (`enum nl80211_band`)
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211Band {
    /// 2.4 GHz ISM band
    Band2Ghz = nl80211_band::NL80211_BAND_2GHZ as u16,
    /// Around 5 GHz band (4.9 - 5.7 GHz)
    Band5Ghz = nl80211_band::NL80211_BAND_5GHZ as u16,
    /// Around 60 GHz band (58.32 - 69.12 GHz)
    Band60Ghz = nl80211_band::NL80211_BAND_60GHZ as u16,
    /// Around 6 GHz band (5.9 - 7.2 GHz)
    Band6Ghz = nl80211_band::NL80211_BAND_6GHZ as u16,
    /// Around 900MHz, supported by S1G PHYs
    BandS1Ghz = nl80211_band::NL80211_BAND_S1GHZ as u16,
    /// Light communication band (placeholder)
    BandLc = nl80211_band::NL80211_BAND_LC as u16,
}

/// Connection quality monitor attributes (`enum nl80211_attr_cqm`)
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211AttrCqm {
    /// RSSI threshold in dBm. This value specifies the threshold for the RSSI level
    /// at which an event will be sent. Zero to disable.
    ///
    /// Alternatively, if `%NL80211_EXT_FEATURE_CQM_RSSI_LIST` is set, multiple values
    /// can be supplied as a low-to-high sorted array of threshold values in dBm.
    /// Events will be sent when the RSSI value crosses any of the thresholds.
    RssiThold = nl80211_attr_cqm::NL80211_ATTR_CQM_RSSI_THOLD as u16,
    /// RSSI hysteresis in dBm. This value specifies the minimum amount the RSSI level
    /// must change after an event before a new event may be issued (to reduce effects
    /// of RSSI oscillation).
    RssiHyst = nl80211_attr_cqm::NL80211_ATTR_CQM_RSSI_HYST as u16,
    /// RSSI threshold event
    RssiThresholdEvent = nl80211_attr_cqm::NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT as u16,
    /// `u32` value indicating that this many consecutive packets were not acknowledged by the peer
    PktLossEvent = nl80211_attr_cqm::NL80211_ATTR_CQM_PKT_LOSS_EVENT as u16,
    /// TX error rate in %. Minimum % of TX failures during the given [`Nl80211AttrCqm::TxeIntvl`]
    /// before an [`Nl80211Command::NotifyCqm`] with reported [`Nl80211AttrCqm::TxeRate`]
    /// [`Nl80211AttrCqm::TxePkts`] is generated.
    ///
    /// In upstream Linux kernel, this is only used in the legacy `ath6kl` driver.
    TxeRate = nl80211_attr_cqm::NL80211_ATTR_CQM_TXE_RATE as u16,
    /// Number of attempted packets in a given [`Nl80211AttrCqm::TxeIntvl`] before
    /// [`Nl80211AttrCqm::TxeRate`] is checked.
    ///
    /// In upstream Linux kernel, this is only used in the legacy `ath6kl` driver.
    TxePkts = nl80211_attr_cqm::NL80211_ATTR_CQM_TXE_PKTS as u16,
    /// Interval in seconds. Specifies the periodic interval in which [`Nl80211AttrCqm::TxePkts`]
    /// and [`Nl80211AttrCqm::TxeRate`] must be satisfied before generating an
    /// [`Nl80211Command::NotifyCqm`]. Set to 0 to turn off TX error reporting.
    ///
    /// In upstream Linux kernel, this is only used in the legacy `ath6kl` driver.
    TxeIntvl = nl80211_attr_cqm::NL80211_ATTR_CQM_TXE_INTVL as u16,
    /// Flag attribute that's set in a beacon loss event
    BeaconLossEvent = nl80211_attr_cqm::NL80211_ATTR_CQM_BEACON_LOSS_EVENT as u16,
    /// The RSSI value in dBm that triggered the RSSI threshold event.
    RssiLevel = nl80211_attr_cqm::NL80211_ATTR_CQM_RSSI_LEVEL as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211AttrCqm {}

/// RSSI threshold event (`enum nl80211_cqm_rssi_threshold_event`)
#[neli::neli_enum(serialized_type = "u32")]
pub enum Nl80211CqmRssiThresholdEvent {
    /// The RSSI level is lower than the configured threshold
    Low = nl80211_cqm_rssi_threshold_event::NL80211_CQM_RSSI_THRESHOLD_EVENT_LOW as u32,
    /// The RSSI is higher than the configured threshold
    High = nl80211_cqm_rssi_threshold_event::NL80211_CQM_RSSI_THRESHOLD_EVENT_HIGH as u32,
    /// Reserved, never sent
    BeaconLoss = nl80211_cqm_rssi_threshold_event::NL80211_CQM_RSSI_BEACON_LOSS_EVENT as u32,
}

/// TX power adjustment (`enum nl80211_tx_power_setting`)
#[neli::neli_enum(serialized_type = "u32")]
pub enum Nl80211TxpowerSetting {
    /// Automatically determine transmit power
    Automatic = nl80211_tx_power_setting::NL80211_TX_POWER_AUTOMATIC as u32,
    /// Limit TX power by the mBm parameter
    Limited = nl80211_tx_power_setting::NL80211_TX_POWER_LIMITED as u32,
    /// Fix TX power to the mBm parameter
    Fixed = nl80211_tx_power_setting::NL80211_TX_POWER_FIXED as u32,
}

// Interface limit attributes (`enum nl80211_iface_limit_attrs`)
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211IfaceLimitAttrs {
    /// Reserved
    Unspec = nl80211_iface_limit_attrs::NL80211_IFACE_LIMIT_UNSPEC as u16,
    /// Maximum number of interfaces that can be chosen from this set of interface types (`u32`)
    Max = nl80211_iface_limit_attrs::NL80211_IFACE_LIMIT_MAX as u16,
    /// Nested attribute containing a flag attribute for each interface type in this set
    Types = nl80211_iface_limit_attrs::NL80211_IFACE_LIMIT_TYPES as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211IfaceLimitAttrs {}

/// Interface combination attributes (`enum nl80211_if_combination_attrs`)
///
/// Examples:
///     limits = [ #{STA} <= 1, #{AP} <= 1 ], matching BI, channels = 1, max = 2
///     => allows an AP and a STA that must match BIs
//
///     numbers = [ #{AP, P2P-GO} <= 8 ], BI min gcd, channels = 1, max = 8,
///     => allows 8 of AP/GO that can have BI gcd >= min gcd
//
///     numbers = [ #{STA} <= 2 ], channels = 2, max = 2
///     => allows two STAs on the same or on different channels
//
///     numbers = [ #{STA} <= 1, #{P2P-client,P2P-GO} <= 3 ], max = 4
///     => allows a STA plus three P2P interfaces
//
/// The list of these four possibilities could completely be contained
/// within the [`Nl80211Attr::InterfaceCombinations`] attribute to indicate
/// that any of these groups must match.
//
/// "Combinations" of just a single interface will not be listed here,
/// a single interface of any valid interface type is assumed to always
/// be possible by itself. This means that implicitly, for each valid
/// interface type, the following group always exists:
/// numbers = [ #{\<type>} <= 1 ], channels = 1, max = 1
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211IfCombinationAttrs {
    /// Reserved
    Unspec = nl80211_if_combination_attrs::NL80211_IFACE_COMB_UNSPEC as u16,
    /// Nested attributes containing the limits for given interface types, see [`Nl80211IfaceLimitAttrs`]
    Limits = nl80211_if_combination_attrs::NL80211_IFACE_COMB_LIMITS as u16,
    /// `u32` attribute giving the total number of interfaces that can be created in this group
    ///
    /// This number doesn't apply to interfaces purely managed in software, which are listed
    /// in a separate attribute [`Nl80211Attr::SoftwareIftypes`].
    MaxNum = nl80211_if_combination_attrs::NL80211_IFACE_COMB_MAXNUM as u16,
    /// Flag attribute specifying that beacon intervals within this group must be all the same even for
    /// infrastructure and AP/GO combinations, i.e. the GO(s) must adopt the infrastructure network's
    /// beacon interval.
    StaApBiMatch = nl80211_if_combination_attrs::NL80211_IFACE_COMB_STA_AP_BI_MATCH as u16,
    /// `u32` attribute specifying how many different channels may be used within this group
    NumChannels = nl80211_if_combination_attrs::NL80211_IFACE_COMB_NUM_CHANNELS as u16,
    /// `u32` attribute containing the bitmap of supported channel widths for radar detection
    RadarDetectWidths = nl80211_if_combination_attrs::NL80211_IFACE_COMB_RADAR_DETECT_WIDTHS as u16,
    /// `u32` attribute containing the bitmap of supported regulatory regions for radar detection
    RadarDetectRegions =
        nl80211_if_combination_attrs::NL80211_IFACE_COMB_RADAR_DETECT_REGIONS as u16,
    /// `u32` attribute specifying the minimum GCD of different beacon intervals supported
    /// by all the interface combinations in this group (if not present, all beacon intervals be identical).
    BiMinGcd = nl80211_if_combination_attrs::NL80211_IFACE_COMB_BI_MIN_GCD as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211IfCombinationAttrs {}

/// Values for [`Nl80211Attr::TdlsOperation`] (`enum nl80211_tdls_operation`)
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211TdlsOperation {
    /// Send a TDLS discovery request.
    DiscoveryReq = nl80211_tdls_operation::NL80211_TDLS_DISCOVERY_REQ as u16,
    /// Setup TDLS link.
    Setup = nl80211_tdls_operation::NL80211_TDLS_SETUP as u16,
    /// Teardown a TDLS link which is already established.
    Teardown = nl80211_tdls_operation::NL80211_TDLS_TEARDOWN as u16,
    /// Enable TDLS link.
    EnableLink = nl80211_tdls_operation::NL80211_TDLS_ENABLE_LINK as u16,
    /// Disable TDLS link.
    DisableLink = nl80211_tdls_operation::NL80211_TDLS_DISABLE_LINK as u16,
}

impl_flags!(
    /// Device/driver features (`enum nl80211_feature_flags`)
    pub Nl80211FeatureFlags: u32 {
        /// This driver supports reflecting back TX status to the socket error queue when requested with the socket option.
        SkTxStatus = nl80211_feature_flags::NL80211_FEATURE_SK_TX_STATUS as u32,
        /// This driver supports IBSS with HT datarates.
        HtIbss = nl80211_feature_flags::NL80211_FEATURE_HT_IBSS as u32,
        /// This driver takes care of freeing up the connected inactive stations in AP mode.
        InactivityTimer = nl80211_feature_flags::NL80211_FEATURE_INACTIVITY_TIMER as u32,
        /// This driver has been tested to work properly to support receiving regulatory hints from cellular base stations.
        CellBaseRegHints = nl80211_feature_flags::NL80211_FEATURE_CELL_BASE_REG_HINTS as u32,
        /// (No longer available, only here to reserve the value for API/ABI compatibility).
        P2pDeviceNeedsChannel = nl80211_feature_flags::NL80211_FEATURE_P2P_DEVICE_NEEDS_CHANNEL as u32,
        /// This driver supports simultaneous authentication of equals (SAE) with user space SME ([`Nl80211Command::Authenticate`]) in station mode.
        Sae = nl80211_feature_flags::NL80211_FEATURE_SAE as u32,
        /// This driver supports low priority scan.
        LowPriorityScan = nl80211_feature_flags::NL80211_FEATURE_LOW_PRIORITY_SCAN as u32,
        /// Scan flush is supported.
        ScanFlush = nl80211_feature_flags::NL80211_FEATURE_SCAN_FLUSH as u32,
        /// Support scanning using an AP vif.
        ApScan = nl80211_feature_flags::NL80211_FEATURE_AP_SCAN as u32,
        /// The driver supports per-vif TX power setting.
        VifTxpower = nl80211_feature_flags::NL80211_FEATURE_VIF_TXPOWER as u32,
        /// The driver expects userspace to perform OBSS scans and generate 20/40 BSS coex reports.
        /// This flag is used only for drivers implementing the CONNECT API, for AUTH/ASSOC it is implied.
        NeedObssScan = nl80211_feature_flags::NL80211_FEATURE_NEED_OBSS_SCAN as u32,
        /// P2P GO implementation supports CT Window setting.
        P2pGoCtwin = nl80211_feature_flags::NL80211_FEATURE_P2P_GO_CTWIN as u32,
        /// P2P GO implementation supports opportunistic powersave.
        P2pGoOppps = nl80211_feature_flags::NL80211_FEATURE_P2P_GO_OPPPS as u32,
        /// `cfg80211` advertises channel limits (HT40, VHT 80/160 MHz) if this flag is set.
        AdvertiseChanLimits = nl80211_feature_flags::NL80211_FEATURE_ADVERTISE_CHAN_LIMITS as u32,
        /// The driver supports full state transitions for AP clients.
        ///
        /// Without this flag (and if the driver doesn't have the AP SME in the device) the driver supports adding
        /// stations only when they're associated and adds them in associated state (to later be transitioned into
        /// authorized), with this flag they should be added before even sending the authentication reply
        /// and then transitioned into authenticated, associated and authorized states using station flags.
        ///
        /// Note that even for drivers that support this, the default is to add stations in authenticated/associated
        /// state, so to add unauthenticated stations the authenticated/associated bits have to be set in the mask.
        FullApClientState = nl80211_feature_flags::NL80211_FEATURE_FULL_AP_CLIENT_STATE as u32,
        /// This driver supports a userspace Mesh Peering Management entity which may be implemented by registering
        /// for beacons or [`Nl80211Command::NewPeerCandidate`] events. The mesh beacon is still generated by the driver.
        UserspaceMpm = nl80211_feature_flags::NL80211_FEATURE_USERSPACE_MPM as u32,
        /// This driver supports an active monitor interface.
        ///
        /// An active monitor interface behaves like a normal monitor interface, but gets added to the driver. It ensures
        /// that incoming unicast packets directed at the configured interface address get ACKed.
        ActiveMonitor = nl80211_feature_flags::NL80211_FEATURE_ACTIVE_MONITOR as u32,
        /// This driver supports dynamic channel bandwidth change (e.g., HT 20 <-> 40 MHz channel) during the lifetime of a BSS.
        ApModeChanWidthChange = nl80211_feature_flags::NL80211_FEATURE_AP_MODE_CHAN_WIDTH_CHANGE as u32,
        /// This device adds a DS Parameter Set IE to probe requests.
        DsParamSetIeInProbes = nl80211_feature_flags::NL80211_FEATURE_DS_PARAM_SET_IE_IN_PROBES as u32,
        /// This device adds a WFA TPC Report IE to probe requests.
        TpcIeInProbes = nl80211_feature_flags::NL80211_FEATURE_WFA_TPC_IE_IN_PROBES as u32,
        /// This device, in client mode, supports Quiet Period requests sent to it by an AP.
        Quiet = nl80211_feature_flags::NL80211_FEATURE_QUIET as u32,
        /// This device is capable of inserting the current tx power value into the TPC Report IE in the spectrum
        /// management TPC Report action frame, and in the Radio Measurement Link Measurement Report action frame.
        TxPowerInsertion = nl80211_feature_flags::NL80211_FEATURE_TX_POWER_INSERTION as u32,
        /// This driver supports dynamic ACK timeout estimation (dynack).
        ///
        /// [`Nl80211Attr::WiphyDynAck`] flag attribute is used to enable dynack.
        AcktoEstimation = nl80211_feature_flags::NL80211_FEATURE_ACKTO_ESTIMATION as u32,
        /// Device supports static spatial multiplexing powersave, i.e. can turn off all but one chain even on HT
        /// connections that should be using more chains.
        StaticSmps = nl80211_feature_flags::NL80211_FEATURE_STATIC_SMPS as u32,
        /// Device supports dynamic spatial multiplexing powersave, i.e. can turn off all but one chain and then
        /// wake the rest up as required after, for example, RTS/CTS handshake.
        DynamicSmps = nl80211_feature_flags::NL80211_FEATURE_DYNAMIC_SMPS as u32,
        /// The device supports setting up WMM TSPEC sessions (TID aka TSID 0-7) with the [`Nl80211Command::AddTxTs`] command.
        ///
        /// Standard IEEE 802.11 TSPEC setup is not yet supported, it needs to be able to handle Block-Ack agreements
        /// and other things.
        SupportsWmmAdmission = nl80211_feature_flags::NL80211_FEATURE_SUPPORTS_WMM_ADMISSION as u32,
        /// Device supports configuring the vif's MAC address upon creation.
        ///
        /// See 'macaddr' field in the vif_params (cfg80211.h).
        MacOnCreate = nl80211_feature_flags::NL80211_FEATURE_MAC_ON_CREATE as u32,
        /// Driver supports channel switching when operating as a TDLS peer.
        TdlsChannelSwitch = nl80211_feature_flags::NL80211_FEATURE_TDLS_CHANNEL_SWITCH as u32,
        /// This device/driver supports using a random MAC address during scan (if the device is unassociated);
        /// the [`Nl80211ScanFlag::RandomAttr`] flag may be set for scans and the MAC address mask/value will be used.
        ScanRandomMacAddr = nl80211_feature_flags::NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR as u32,
        /// This device/driver supports using a random MAC address for every scan iteration during scheduled
        /// scan (while not associated), the [`Nl80211ScanFlag::RandomAttr`] may be set for scheduled scan
        /// and the MAC address mask/value will be used.
        SchedScanRandomMacAddr = nl80211_feature_flags::NL80211_FEATURE_SCHED_SCAN_RANDOM_MAC_ADDR as u32,
        /// This device/driver supports using a random MAC address for every scan iteration during "net detect",
        /// i.e. scan in unassociated WoWLAN, the [`Nl80211ScanFlag::RandomAddr`] may be set for scheduled scan
        /// and the MAC address mask/value will be used.
        NdRandomMacAddr = nl80211_feature_flags::NL80211_FEATURE_ND_RANDOM_MAC_ADDR as u32,
    }
);

/// Bit index of device/driver extended features (`enum nl80211_ext_feature_index`)
///
/// Returned to userspace as byte array unlike [`Nl80211FeatureFlags`] which are bitflags in a single `u32`.
#[neli::neli_enum(serialized_type = "u32")]
pub enum Nl80211ExtFeatureIndex {
    /// This driver supports IBSS with VHT datarates.
    FeatureVhtIbss = nl80211_ext_feature_index::NL80211_EXT_FEATURE_VHT_IBSS as u32,
    /// This driver supports RRM. When featured, user can request to use RRM (see [`Nl80211Attr::UseRrm`])
    /// with [`Nl80211Command::Associate`] and [`Nl80211Command::Connect`] requests, which will set the ASSOC_REQ_USE_RRM flag
    /// in the association request even if [`Nl80211FeatureFlags::Quiet`] is not advertised.
    FeatureRrm = nl80211_ext_feature_index::NL80211_EXT_FEATURE_RRM as u32,
    /// This device supports MU-MIMO air sniffer which means that it can be configured to hear packets from certain groups
    /// which can be configured by the [`Nl80211Attr::MuMimoGroupData`] attribute, or can be configured to follow a station
    /// by configuring the [`Nl80211Attr::`MuMimoFollowMacAddr`] attribute.
    MuMimoAirSniffer = nl80211_ext_feature_index::NL80211_EXT_FEATURE_MU_MIMO_AIR_SNIFFER as u32,
    /// This driver includes the actual time the scan started in scan results event.
    ///
    /// The time is the TSF of the BSS that the interface that requested the scan is connected to (if available).
    ScanStartTime = nl80211_ext_feature_index::NL80211_EXT_FEATURE_SCAN_START_TIME as u32,
    /// Per BSS, this driver reports the time the last beacon/probe was received.
    ///
    /// For a non-MLO connection, the time is the TSF of the BSS that the interface that requested the scan is
    /// connected to (if available). For an MLO connection, the time is the TSF of the BSS corresponding with
    /// link ID specified in the scan request (if specified).
    BssParentTsf = nl80211_ext_feature_index::NL80211_EXT_FEATURE_BSS_PARENT_TSF as u32,
    /// This driver supports configuration of channel dwell time.
    SetScanDwell = nl80211_ext_feature_index::NL80211_EXT_FEATURE_SET_SCAN_DWELL as u32,
    /// Driver supports beacon rate configuration (AP/mesh), supporting a legacy (non-HT/VHT) rate.
    BeaconRateLegacy = nl80211_ext_feature_index::NL80211_EXT_FEATURE_BEACON_RATE_LEGACY as u32,
    /// Driver supports beacon rate configuration (AP/mesh) with HT rates.
    BeaconRateHt = nl80211_ext_feature_index::NL80211_EXT_FEATURE_BEACON_RATE_HT as u32,
    /// Driver supports beacon rate configuration (AP/mesh) with VHT rates.
    BeaconRateVht = nl80211_ext_feature_index::NL80211_EXT_FEATURE_BEACON_RATE_VHT as u32,
    /// This driver supports Fast Initial Link Setup with user space SME ([`Nl80211Command::Authenticate`]) in station mode.
    FilsSta = nl80211_ext_feature_index::NL80211_EXT_FEATURE_FILS_STA as u32,
    /// This driver supports randomized TA in [`Nl80211Command::Frame`] while not associated.
    MgmtTxRandomTa = nl80211_ext_feature_index::NL80211_EXT_FEATURE_MGMT_TX_RANDOM_TA as u32,
    /// This driver supports randomized TA in [`Nl80211Command::Frame`] while associated.
    MgmtTxRandomTaConnected =
        nl80211_ext_feature_index::NL80211_EXT_FEATURE_MGMT_TX_RANDOM_TA_CONNECTED as u32,
    /// The driver supports sched_scan for reporting BSSs with better RSSI than the current connected BSS
    /// ([`Nl80211Attr::SchedScanRelativeRssi`]).
    SchedScanRelativeRssi =
        nl80211_ext_feature_index::NL80211_EXT_FEATURE_SCHED_SCAN_RELATIVE_RSSI as u32,
    /// With this driver the [`Nl80211AttrCqm::RssiThold`] attribute accepts a list of zero or more RSSI
    /// threshold values to monitor rather than exactly one threshold.
    CqmRssiList = nl80211_ext_feature_index::NL80211_EXT_FEATURE_CQM_RSSI_LIST as u32,
    /// Driver SME supports FILS shared key authentication with [`Nl80211Command::Connect`].
    FilsSkOffload = nl80211_ext_feature_index::NL80211_EXT_FEATURE_FILS_SK_OFFLOAD as u32,
    /// Device wants to do 4-way handshake with PSK in station mode (PSK is passed as part of theuconnect and
    /// associate commands), doing it in the host might not be supported.
    _4WayHandshakeStaPsk =
        nl80211_ext_feature_index::NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK as u32,
    /// Device wants to do doing 4-way handshake with 802.1X in station mode (will pass EAP frames to the host
    /// and accept the set_pmk/del_pmk commands), doing it in the host might not be supported.
    _4WayHandshakeSta1x =
        nl80211_ext_feature_index::NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_1X as u32,
    /// Driver is capable of overriding the max channel attribute in the FILS request params IE with the actual dwell time.
    FilsMaxChannelTime =
        nl80211_ext_feature_index::NL80211_EXT_FEATURE_FILS_MAX_CHANNEL_TIME as u32,
    /// Driver accepts broadcast probe response.
    AcceptBcastProbeResp =
        nl80211_ext_feature_index::NL80211_EXT_FEATURE_ACCEPT_BCAST_PROBE_RESP as u32,
    /// Driver supports sending the first probe request in each channel at rate of at least 5.5Mbps.
    OceProbeReqHighTxRate =
        nl80211_ext_feature_index::NL80211_EXT_FEATURE_OCE_PROBE_REQ_HIGH_TX_RATE as u32,
    /// Driver supports probe request tx deferral and suppression.
    ProbeReqDeferralSuppression =
        nl80211_ext_feature_index::NL80211_EXT_FEATURE_OCE_PROBE_REQ_DEFERRAL_SUPPRESSION as u32,
    /// Driver supports the [`Nl80211Mfp::Optional`] value in [`Nl80211Attr::UseMfp`].
    MfpOptional = nl80211_ext_feature_index::NL80211_EXT_FEATURE_MFP_OPTIONAL as u32,
    /// Driver supports low span scan.
    LowSpanScan = nl80211_ext_feature_index::NL80211_EXT_FEATURE_LOW_SPAN_SCAN as u32,
    /// Driver supports low power scan.
    LowPowerScan = nl80211_ext_feature_index::NL80211_EXT_FEATURE_LOW_POWER_SCAN as u32,
    /// Driver supports high accuracy scan.
    HighAccuracyScan = nl80211_ext_feature_index::NL80211_EXT_FEATURE_HIGH_ACCURACY_SCAN as u32,
    /// HW/driver will offload DFS actions.
    ///
    ///  Device or driver will do all DFS-related actions by itself, informing user-space about CAC progress,
    /// radar detection event, channel change triggered by radar detection event. No need to start CAC from
    /// user-space, no need to react to "radar detected" event.
    DfsOffload = nl80211_ext_feature_index::NL80211_EXT_FEATURE_DFS_OFFLOAD as u32,
    /// Driver supports sending and receiving control port frames over nl80211 instead of the netdevice.
    ControlPortOverNl802211 =
        nl80211_ext_feature_index::NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211 as u32,
    /// This driver/device supports (average) ACK signal strength reporting.
    AckSignalSupport = nl80211_ext_feature_index::NL80211_EXT_FEATURE_ACK_SIGNAL_SUPPORT as u32,
    /// Backward-compatible ID
    DataAckSignalSupport =
        nl80211_ext_feature_index::NL80211_EXT_FEATURE_DATA_ACK_SIGNAL_SUPPORT as u32,
    /// Driver supports FQ-CoDel-enabled intermediate TXQs.
    Txqs = nl80211_ext_feature_index::NL80211_EXT_FEATURE_TXQS as u32,
    /// Driver/device supports randomizing the SN in probe request frames if requested by [`Nl80211ScanFlag::RandomSn`].
    ScanRandomSn = nl80211_ext_feature_index::NL80211_EXT_FEATURE_SCAN_RANDOM_SN as u32,
    /// Driver/device can omit all data except for supported rates from the probe request content if requested
    /// by the [`Nl80211ScanFlag::MinPreqContent`] flag.
    ScanMinPreqContent =
        nl80211_ext_feature_index::NL80211_EXT_FEATURE_SCAN_MIN_PREQ_CONTENT as u32,
    /// Driver/device confirm that they are able to rekey an in-use key correctly.
    ///
    /// Userspace must not rekey PTK keys if this flag is not set. Ignoring this can leak clear text
    /// packets and/or freeze the connection.
    CanReplacePtk0 = nl80211_ext_feature_index::NL80211_EXT_FEATURE_CAN_REPLACE_PTK0 as u32,
    /// Driver supports enabling fine timing measurement responder role.
    EnableFtmResponder = nl80211_ext_feature_index::NL80211_EXT_FEATURE_ENABLE_FTM_RESPONDER as u32,
    /// Driver supports getting airtime fairness for transmitted packets and has enabled airtime fairness scheduling.
    AirtimeFairness = nl80211_ext_feature_index::NL80211_EXT_FEATURE_AIRTIME_FAIRNESS as u32,
    /// Driver/device supports PMKSA caching (set/del PMKSA operations) in AP mode.
    ApPmksaCaching = nl80211_ext_feature_index::NL80211_EXT_FEATURE_AP_PMKSA_CACHING as u32,
    /// Obsolete.
    SchedScanBandSpecificRssiThold =
        nl80211_ext_feature_index::NL80211_EXT_FEATURE_SCHED_SCAN_BAND_SPECIFIC_RSSI_THOLD as u32,
    /// Driver supports "Extended Key ID for Individually Addressed Frames" from IEEE802.11-2016.
    KeyId = nl80211_ext_feature_index::NL80211_EXT_FEATURE_EXT_KEY_ID as u32,
    /// This driver supports controlling TX power to a station.
    StaTxPwr = nl80211_ext_feature_index::NL80211_EXT_FEATURE_STA_TX_PWR as u32,
    /// Device wants to do SAE authentication in station mode (SAE password is passed as part of the connect command).
    SaeOffload = nl80211_ext_feature_index::NL80211_EXT_FEATURE_SAE_OFFLOAD as u32,
    /// The driver supports a single netdev with VLAN tagged frames and separate VLAN-specific
    /// netdevs added using vconfig similarly to the Ethernet case.
    VlanOffload = nl80211_ext_feature_index::NL80211_EXT_FEATURE_VLAN_OFFLOAD as u32,
    /// The driver supports the Airtime Queue Limit (AQL) feature, which prevents bufferbloat by using the
    /// expected transmission time to limit the amount of data buffered in the hardware.
    Aql = nl80211_ext_feature_index::NL80211_EXT_FEATURE_AQL as u32,
    /// The driver supports Beacon protection and can receive key configuration for BIGTK using key indexes 6 and 7.
    BeaconProtection = nl80211_ext_feature_index::NL80211_EXT_FEATURE_BEACON_PROTECTION as u32,
    /// The driver can disable the forwarding of preauth frames over the control port. They are then handled as ordinary data frames.
    ControlPortNoPreauth =
        nl80211_ext_feature_index::NL80211_EXT_FEATURE_CONTROL_PORT_NO_PREAUTH as u32,
    /// Driver supports protected TWT frames.
    ProtectedTwt = nl80211_ext_feature_index::NL80211_EXT_FEATURE_PROTECTED_TWT as u32,
    /// The driver supports removing stations in IBSS mode, essentially by dropping their state.
    DelIbssSta = nl80211_ext_feature_index::NL80211_EXT_FEATURE_DEL_IBSS_STA as u32,
    /// Management frame registrations are possible for multicast frames and those will be reported properly.
    MulticastRegistrations =
        nl80211_ext_feature_index::NL80211_EXT_FEATURE_MULTICAST_REGISTRATIONS as u32,
    /// The driver supports Beacon protection as a client only and cannot transmit protected beacons.
    BeaconProtectionClient =
        nl80211_ext_feature_index::NL80211_EXT_FEATURE_BEACON_PROTECTION_CLIENT as u32,
    /// This driver supports receiving and reporting scan request with [`Nl80211Attr::ScanFreqKhz`].
    ///
    /// In order to report [`Nl80211Attr::ScanFreqKhz`], [`Nl80211ScanFlag::FreqKhz`] must be included in the scan request.
    ScanFreqKhz = nl80211_ext_feature_index::NL80211_EXT_FEATURE_SCAN_FREQ_KHZ as u32,
    /// The driver can report tx status for control port over nl80211 TX operations.
    ControlPortOverNl80211TxStatus =
        nl80211_ext_feature_index::NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211_TX_STATUS as u32,
    /// Driver supports Operating Channel Validation (OCV) when using driver's SME for RSNA handshakes.
    OperatingChannelValidation =
        nl80211_ext_feature_index::NL80211_EXT_FEATURE_OPERATING_CHANNEL_VALIDATION as u32,
    /// Device wants to do 4-way handshake with PSK in AP mode (PSK is passed as part of the start AP command).
    _4WayHandshakeApPsk =
        nl80211_ext_feature_index::NL80211_EXT_FEATURE_4WAY_HANDSHAKE_AP_PSK as u32,
    /// Device wants to do SAE authentication in AP mode (SAE password is passed as part of the start AP command).
    SaeOffloadAp = nl80211_ext_feature_index::NL80211_EXT_FEATURE_SAE_OFFLOAD_AP as u32,
    /// Driver/device supports FILS discovery frames transmission.
    FilsDiscovery = nl80211_ext_feature_index::NL80211_EXT_FEATURE_FILS_DISCOVERY as u32,
    /// Driver/device supports unsolicited broadcast probe response transmission.
    UnsolBcastProbeResp =
        nl80211_ext_feature_index::NL80211_EXT_FEATURE_UNSOL_BCAST_PROBE_RESP as u32,
    /// Driver supports beacon rate configuration (AP/mesh) with HE rates.
    BeaconRateHe = nl80211_ext_feature_index::NL80211_EXT_FEATURE_BEACON_RATE_HE as u32,
    /// Device supports secure LTF measurement exchange protocol.
    SecureLtf = nl80211_ext_feature_index::NL80211_EXT_FEATURE_SECURE_LTF as u32,
    /// Device supports secure RTT measurement exchange protocol.
    SecureRtt = nl80211_ext_feature_index::NL80211_EXT_FEATURE_SECURE_RTT as u32,
    /// Device supports management frame protection for all management frames exchanged during the negotiation
    /// and range measurement procedure.
    ProtRangeNegoAndMeasure =
        nl80211_ext_feature_index::NL80211_EXT_FEATURE_PROT_RANGE_NEGO_AND_MEASURE as u32,
    /// The driver supports BSS color collision detection and change announcemnts.
    BssColor = nl80211_ext_feature_index::NL80211_EXT_FEATURE_BSS_COLOR as u32,
    /// Driver running in AP mode supports FILS encryption and decryption for (Re)Association Request and Response frames.
    ///
    /// Userspace has to share FILS AAD details to the driver by using [`Nl80211Command::SetFilsAad`].
    FilsCryptoOffload = nl80211_ext_feature_index::NL80211_EXT_FEATURE_FILS_CRYPTO_OFFLOAD as u32,
    /// Device supports background radar/CAC detection.
    RadarBackground = nl80211_ext_feature_index::NL80211_EXT_FEATURE_RADAR_BACKGROUND as u32,
    /// Device can perform a MAC address change without having to bring the underlying network device down first.
    ///
    /// For example, in station mode this can be used to vary the origin MAC address prior to a connection to a new
    /// AP for privacy or other reasons. Note that certain driver specific restrictions might apply, e.g. no scans
    /// in progress, no offchannel operations in progress, and no active connections.
    PoweredAddrChange = nl80211_ext_feature_index::NL80211_EXT_FEATURE_POWERED_ADDR_CHANGE as u32,
    /// Driver supports preamble puncturing in AP mode.
    Punct = nl80211_ext_feature_index::NL80211_EXT_FEATURE_PUNCT as u32,
    /// Device supports NAN Pairing which enables authentication, data encryption and message integrity.
    SecureNan = nl80211_ext_feature_index::NL80211_EXT_FEATURE_SECURE_NAN as u32,
    /// Device supports randomized TA in authentication and deauthentication frames sent to unassociated peer using [`Nl80211Command::Frame`].
    AuthAndDeauthRandomTa =
        nl80211_ext_feature_index::NL80211_EXT_FEATURE_AUTH_AND_DEAUTH_RANDOM_TA as u32,
    /// Driver/Device wants to do OWE DH IE handling in station mode.
    OweOffload = nl80211_ext_feature_index::NL80211_EXT_FEATURE_OWE_OFFLOAD as u32,
    /// Driver/Device wants to do OWE DH IE handling in AP mode.
    OweOffloadAp = nl80211_ext_feature_index::NL80211_EXT_FEATURE_OWE_OFFLOAD_AP as u32,
    /// The device supports peer-to-peer or adhoc operation on DFS channels under the control of a concurrent
    /// DFS master on the same channel as described in FCC-594280 D01 (Section B.3).
    ///
    /// This, for example, allows P2P GO and P2P clients to operate on DFS channels as long as there's a
    /// concurrent BSS connection.
    DfsConcurrent = nl80211_ext_feature_index::NL80211_EXT_FEATURE_DFS_CONCURRENT as u32,
    /// The driver has support for SPP (signaling and payload protected). A-MSDUs and this shall be advertised in the RSNXE.
    SppAmsduSupport = nl80211_ext_feature_index::NL80211_EXT_FEATURE_SPP_AMSDU_SUPPORT as u32,
    // Driver supports beacon rate configuration (AP/mesh) with EHT rates.
    BeaconRateEht = nl80211_ext_feature_index::NL80211_EXT_FEATURE_BEACON_RATE_EHT as u32,
    /// Driver supports Enhanced Privacy Protection Key Exchange (EPPKE) with user space SME ([`Nl80211Command::Authenticate`]) in non-AP STA mode.
    Eppke = nl80211_ext_feature_index::NL80211_EXT_FEATURE_EPPKE as u32,
    /// This specifies that the driver supports encryption of (Re)Association Request and Response frames in both non‑AP STA
    /// and AP mode as specified in IEEE P802.11bi/D3.0, 12.16.6.
    AssocFrameEncryption =
        nl80211_ext_feature_index::NL80211_EXT_FEATURE_ASSOC_FRAME_ENCRYPTION as u32,
    /// Driver supports IEEE 802.1X authentication utilizing Authentication frames with user space SME ([`Nl80211Command::Authenticate`])
    /// in non-AP STA mode, as specified in IEEE P802.11bi/D4.0, 12.16.5.
    Ieee8021xAuth = nl80211_ext_feature_index::NL80211_EXT_FEATURE_IEEE8021X_AUTH as u32,
    // v7.2+
    /// Driver supports MAC address filtering during remain-on-channel.
    ///
    /// When [`Nl80211Attr::Mac`] is provided with [`Nl80211Command::RemainOnChannel`], the driver will forward frames with
    /// a matching MAC address to userspace during the off-channel period.
    RocAddrFilter = nl80211_ext_feature_index::NL80211_EXT_FEATURE_ROC_ADDR_FILTER as u32,
    /// Driver supports installing the LTF key seed via [`Nl80211KeyAttributes::LtfSeed`].
    ///
    /// The seed is used to generate secure LTF keys for secure LTF measurement sessions.
    SetKeyLtfSeed = nl80211_ext_feature_index::NL80211_EXT_FEATURE_SET_KEY_LTF_SEED as u32,
}

impl_flags!(
    /// Scan request control flags (`enum nl80211_scan_flags`)
    pub Nl80211ScanFlag: u32 {
        /// Scan request has low priority. Driver must indicate support in [`Nl80211Attr::FeatureFlags`]
        LowPriority = nl80211_scan_flags::NL80211_SCAN_FLAG_LOW_PRIORITY as u32,
        /// Flush cache before scanning
        Flush = nl80211_scan_flags::NL80211_SCAN_FLAG_FLUSH as u32,
        /// Force a scan even if the interface is configured as AP and the beaconing has already been configured.
        ///
        /// This attribute is dangerous because will destroy stations performance as a lot of frames
        /// will be lost while scanning off-channel, therefore it must be used only when really needed
        Ap = nl80211_scan_flags::NL80211_SCAN_FLAG_AP as u32,
        /// Use a random MAC address for this scan (or for scheduled scan, a different one for every scan iteration).
        ///
        /// When the flag is set, depending on device capabilities the [`Nl80211Attr::Mac`] and [`Nl80211Attr::MacMask`]
        /// attributes may also be given in which case only the masked bits will be preserved from the MAC address
        /// and the remainder randomised. If the attributes are not given full randomisation (46 bits,
        /// locally administered 1, multicast 0) is assumed.
        ///
        /// This flag must not be requested when the feature isn't supported, check [`Nl80211Attr::FeatureFlags`] for the device.
        RandomAddr = nl80211_scan_flags::NL80211_SCAN_FLAG_RANDOM_ADDR as u32,
        /// Fill the dwell time in the FILS request parameters IE in the probe request
        FilsMaxChannelTime = nl80211_scan_flags::NL80211_SCAN_FLAG_FILS_MAX_CHANNEL_TIME as u32,
        /// Accept broadcast probe responses
        AcceptBcastProbeResp = nl80211_scan_flags::NL80211_SCAN_FLAG_ACCEPT_BCAST_PROBE_RESP as u32,
        /// Send probe request frames at rate of at least 5.5M. In case non-OCE AP is discovered in the channel,
        /// only the first probe req in the channel will be sent in high rate.
        OceProbeReqHighTxRate = nl80211_scan_flags::NL80211_SCAN_FLAG_OCE_PROBE_REQ_HIGH_TX_RATE as u32,
        /// Allow probe request TX deferral (dot11FILSProbeDelay shall be set to 15ms) and suppression
        /// (if it has received a broadcast Probe Response frame, Beacon frame or FILS Discovery frame
        /// from an AP that the STA considers a suitable candidate for (re-)association - suitable in terms of
        /// SSID and/or RSSI.
        OceProbeReqDeferralSuppression = nl80211_scan_flags::NL80211_SCAN_FLAG_OCE_PROBE_REQ_DEFERRAL_SUPPRESSION as u32,
        /// Span corresponds to the total time taken to accomplish the scan. Thus, this flag intends the
        /// driver to perform the scan request with lesser span/duration. It is specific to the driver
        /// implementations on how this is accomplished. Scan accuracy may be impacted with this flag.
        LowSpan = nl80211_scan_flags::NL80211_SCAN_FLAG_LOW_SPAN as u32,
        /// This flag intends the scan attempts to consume optimal possible power. Drivers can resort to
        /// their specific means to optimize the power. Scan accuracy may be impacted with this flag.
        LowPower = nl80211_scan_flags::NL80211_SCAN_FLAG_LOW_POWER as u32,
        /// Accuracy here intends to the extent of scan results obtained. Thus [`ScanFlag::HighAccuracy`] scan flag aims
        /// to get maximum possible scan results. This flag hints the driver to use the best possible scan
        /// configuration to improve the accuracy in scanning. Latency and power use may be impacted with
        /// this flag.
        HighAccuracy = nl80211_scan_flags::NL80211_SCAN_FLAG_HIGH_ACCURACY as u32,
        /// Randomize the sequence number in probe request frames from this scan to avoid correlation/tracking
        /// being possible.
        RandomSn = nl80211_scan_flags::NL80211_SCAN_FLAG_RANDOM_SN as u32,
        /// Minimize probe request content to only have supported rates and no additional capabilities
        /// (unless added by userspace explicitly).
        MinPreqContent = nl80211_scan_flags::NL80211_SCAN_FLAG_MIN_PREQ_CONTENT as u32,
        /// Report scan results with [`Nl80211Attr::ScanFreqKhz`]. This also means [`Nl80211Attr::ScanFrequencies`]
        /// will not be included.
        FreqKhz = nl80211_scan_flags::NL80211_SCAN_FLAG_FREQ_KHZ as u32,
        /// Scan for collocated APs reported by 2.4/5 GHz APs.
        ///
        /// When the flag is set, the scan logic will use the information from the RNR element found in beacons/probe
        /// responses received on the 2.4/5 GHz channels to actively scan only the 6 GHz channels on which APs are
        /// expected to be found.
        ///
        /// Note that when not set, the scan logic would scan all 6 GHz channels, but since transmission of probe requests
        /// on non-PSC channels is limited, it is highly likely that these channels would passively be scanned. Also note
        /// that when the flag is set, in addition to the colocated APs, PSC channels would also be scanned if the user
        /// space has asked for it.
        Colocated6GHz = nl80211_scan_flags::NL80211_SCAN_FLAG_COLOCATED_6GHZ as u32,
    }
);

/// NAN function attributes (`enum nl80211_nan_func_attributes`)
#[neli::neli_enum(serialized_type = "u8")]
pub enum Nl80211NanFuncAttributes {
    /// `enum nl80211_nan_function_type` (`u8`)
    Type = nl80211_nan_func_attributes::NL80211_NAN_FUNC_TYPE as u8,
    /// 6 bytes of the service ID hash as specified in NAN spec. This is a binary attribute.
    ServiceId = nl80211_nan_func_attributes::NL80211_NAN_FUNC_SERVICE_ID as u8,
    /// Relevant if the function's type is publish.
    ///
    /// Defines the transmission type for the publish Service Discovery Frame, see `enum nl80211_nan_publish_type`.
    /// Its type is `u8`.
    PublishType = nl80211_nan_func_attributes::NL80211_NAN_FUNC_PUBLISH_TYPE as u8,
    /// Relevant if the function is a solicited publish. Should the solicited publish Service Discovery Frame be sent to
    /// the NAN Broadcast address. This is a flag.
    PublishBcast = nl80211_nan_func_attributes::NL80211_NAN_FUNC_PUBLISH_BCAST as u8,
    /// Relevant if the function's type is subscribe. Is the subscribe active. This is a flag.
    SubscribeActive = nl80211_nan_func_attributes::NL80211_NAN_FUNC_SUBSCRIBE_ACTIVE as u8,
    /// Relevant if the function's type is follow up. The instance ID for the follow up Service Discovery Frame. This is `u8`.
    FollowUpId = nl80211_nan_func_attributes::NL80211_NAN_FUNC_FOLLOW_UP_ID as u8,
    /// Relevant if the function's type is follow up. This is a `u8`. The requester instance ID for the follow up Service Discovery Frame.
    FollowUpReqId = nl80211_nan_func_attributes::NL80211_NAN_FUNC_FOLLOW_UP_REQ_ID as u8,
    /// The MAC address of the recipient of the follow up Service Discovery Frame. This is a binary attribute.
    FollowUpDest = nl80211_nan_func_attributes::NL80211_NAN_FUNC_FOLLOW_UP_DEST as u8,
    /// Is this function limited for devices in a close range. The range itself (RSSI) is defined by the device. This is a flag.
    CloseRange = nl80211_nan_func_attributes::NL80211_NAN_FUNC_CLOSE_RANGE as u8,
    /// Strictly positive number of DWs this function should stay active. If not present infinite TTL is assumed. This is a `u32`.
    Ttl = nl80211_nan_func_attributes::NL80211_NAN_FUNC_TTL as u8,
    /// Array of bytes describing the service specific info. This is a binary attribute.
    ServiceInfo = nl80211_nan_func_attributes::NL80211_NAN_FUNC_SERVICE_INFO as u8,
    /// Service Receive Filter. This is a nested attribute. See `enum nl80211_nan_srf_attributes`.
    Srf = nl80211_nan_func_attributes::NL80211_NAN_FUNC_SRF as u8,
    /// Receive Matching filter. This is a nested attribute. It is a list of binary values.
    RxMatchFilter = nl80211_nan_func_attributes::NL80211_NAN_FUNC_RX_MATCH_FILTER as u8,
    /// Transmit Matching filter. This is a nested attribute. It is a list of binary values.
    TxMatchFilter = nl80211_nan_func_attributes::NL80211_NAN_FUNC_TX_MATCH_FILTER as u8,
    /// The instance ID of the function. Its type is `u8` and it cannot be 0.
    InstanceId = nl80211_nan_func_attributes::NL80211_NAN_FUNC_INSTANCE_ID as u8,
    /// NAN function termination reason. See `enum nl80211_nan_func_term_reason`.
    TermReason = nl80211_nan_func_attributes::NL80211_NAN_FUNC_TERM_REASON as u8,
}

/// Wiphy radio attributes (`enum nl80211_wiphy_radio_attrs`)
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211WiphyRadioAttrs {
    /// Invalid.
    Invalid = nl80211_wiphy_radio_attrs::__NL80211_WIPHY_RADIO_ATTR_INVALID as u16,
    /// Index of this radio (`u32`).
    Index = nl80211_wiphy_radio_attrs::NL80211_WIPHY_RADIO_ATTR_INDEX as u16,
    /// Frequency range supported by this radio. Attribute may be present multiple times.
    FreqRange = nl80211_wiphy_radio_attrs::NL80211_WIPHY_RADIO_ATTR_FREQ_RANGE as u16,
    /// Supported interface combination for this radio.
    ///
    /// Attribute may be present multiple times and contains attributes defined in [`Nl80211IfCombinationAttrs`].
    InterfaceCombination =
        nl80211_wiphy_radio_attrs::NL80211_WIPHY_RADIO_ATTR_INTERFACE_COMBINATION as u16,
    /// Bitmask (`u32`) of antennas connected to this radio.
    AntennaMask = nl80211_wiphy_radio_attrs::NL80211_WIPHY_RADIO_ATTR_ANTENNA_MASK as u16,
    /// RTS threshold (u32) of this radio.
    RtsThreshold = nl80211_wiphy_radio_attrs::NL80211_WIPHY_RADIO_ATTR_RTS_THRESHOLD as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211WiphyRadioAttrs {}

/// Wiphy radio frequency range (`enum nl80211_wiphy_radio_freq_range`)
#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211WiphyRadioFreqRange {
    /// Invalid.
    Invalid = nl80211_wiphy_radio_freq_range::__NL80211_WIPHY_RADIO_FREQ_ATTR_INVALID as u16,
    /// Frequency range start (`u32`). The unit is kHz.
    Start = nl80211_wiphy_radio_freq_range::NL80211_WIPHY_RADIO_FREQ_ATTR_START as u16,
    /// Frequency range end (`u32`). The unit is kHz.
    End = nl80211_wiphy_radio_freq_range::NL80211_WIPHY_RADIO_FREQ_ATTR_END as u16,
}
impl neli::consts::genl::NlAttrType for Nl80211WiphyRadioFreqRange {}
