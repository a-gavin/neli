use std::{
    collections::{HashMap, HashSet},
    iter::once,
    marker::PhantomData,
    sync::Arc,
};

use log::{error, trace, warn};
use tokio::{
    spawn,
    sync::{
        Mutex,
        mpsc::{Receiver, Sender, channel, error::TryRecvError},
    },
};

use crate::{
    FromBytesWithInput, Size, ToBytes,
    consts::{
        genl::{CtrlAttr, CtrlAttrMcastGrp, CtrlCmd, Index},
        nl::{GenlId, NlType, NlmF, Nlmsg},
        socket::NlFamily,
    },
    err::RouterError,
    genl::{AttrTypeBuilder, Genlmsghdr, GenlmsghdrBuilder, NlattrBuilder, NoUserHeader},
    nl::{NlPayload, Nlmsghdr, NlmsghdrBuilder},
    socket::asynchronous::NlSocketHandle,
    types::{Buffer, GenlBuffer, NlBuffer},
    utils::{Groups, NetlinkBitArray},
};

type GenlFamily = Result<
    NlBuffer<GenlId, Genlmsghdr<CtrlCmd, CtrlAttr>>,
    RouterError<GenlId, Genlmsghdr<CtrlCmd, CtrlAttr>>,
>;
type Senders =
    Arc<Mutex<HashMap<u32, Sender<Result<Nlmsghdr<u16, Buffer>, RouterError<u16, Buffer>>>>>>;
type ProcThreadReturn = (
    Sender<()>,
    Receiver<Result<Nlmsghdr<u16, Buffer>, RouterError<u16, Buffer>>>,
);

/// A high-level handle for sending messages and generating a handle that validates
/// all of the received messages.
pub struct NlRouter {
    socket: Arc<NlSocketHandle>,
    seq: Mutex<u32>,
    senders: Senders,

    exit_sender: Sender<()>,
}

fn spawn_processing_thread(socket: Arc<NlSocketHandle>, senders: Senders) -> ProcThreadReturn {
    let (exit_sender, mut exit_receiver) = channel(1);
    let (multicast_sender, multicast_receiver) = channel(1024);
    spawn(async move {
        while let Err(TryRecvError::Empty) = exit_receiver.try_recv() {
            match socket.recv::<u16, Buffer>().await {
                Ok((iter, group)) => {
                    for msg in iter {
                        trace!("Message received: {msg:?}");
                        let mut seqs_to_remove = HashSet::new();
                        match msg {
                            Ok(m) => {
                                let seq = *m.nl_seq();
                                let lock = senders.lock().await;
                                if !group.is_empty() {
                                    if multicast_sender.send(Ok(m)).await.is_err() {
                                        warn!("{}", RouterError::<u16, Buffer>::ClosedChannel);
                                    }
                                } else if let Some(sender) = lock.get(m.nl_seq()) {
                                    if &socket.pid() == m.nl_pid() {
                                        if sender.send(Ok(m)).await.is_err() {
                                            error!("{}", RouterError::<u16, Buffer>::ClosedChannel);
                                            seqs_to_remove.insert(seq);
                                        }
                                    } else {
                                        for (seq, sender) in lock.iter() {
                                            if sender
                                                .send(Err(RouterError::BadSeqOrPid(m.clone())))
                                                .await
                                                .is_err()
                                            {
                                                error!(
                                                    "{}",
                                                    RouterError::<u16, Buffer>::ClosedChannel
                                                );
                                                seqs_to_remove.insert(*seq);
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                let lock = senders.lock().await;
                                for (seq, sender) in lock.iter() {
                                    if sender
                                        .send(Err(RouterError::from(e.clone())))
                                        .await
                                        .is_err()
                                    {
                                        error!("{}", RouterError::<u16, Buffer>::ClosedChannel);
                                        seqs_to_remove.insert(*seq);
                                    }
                                }
                            }
                        }
                        for seq in seqs_to_remove {
                            senders.lock().await.remove(&seq);
                        }
                    }
                }
                Err(e) => {
                    let mut seqs_to_remove = HashSet::new();
                    let mut lock = senders.lock().await;
                    for (seq, sender) in lock.iter() {
                        if sender
                            .send(Err(RouterError::from(e.clone())))
                            .await
                            .is_err()
                        {
                            seqs_to_remove.insert(*seq);
                            error!("{}", RouterError::<u16, Buffer>::ClosedChannel);
                            break;
                        }
                    }
                    for seq in seqs_to_remove {
                        lock.remove(&seq);
                    }
                }
            }
        }
    });
    (exit_sender, multicast_receiver)
}

impl NlRouter {
    /// Equivalent of `socket` and `bind` calls.
    pub async fn connect(
        proto: NlFamily,
        pid: Option<u32>,
        groups: Groups,
    ) -> Result<
        (
            Self,
            NlRouterReceiverHandle<u16, Genlmsghdr<u8, u16, NoUserHeader>>,
        ),
        RouterError<u16, Buffer>,
    > {
        let socket = Arc::new(NlSocketHandle::connect(proto, pid, groups)?);
        let senders = Arc::new(Mutex::new(HashMap::default()));
        let (exit_sender, multicast_receiver) =
            spawn_processing_thread(Arc::clone(&socket), Arc::clone(&senders));
        let multicast_receiver =
            NlRouterReceiverHandle::new(multicast_receiver, Arc::clone(&senders), false, None);
        Ok((
            NlRouter {
                socket,
                senders,
                seq: Mutex::new(0),
                exit_sender,
            },
            multicast_receiver,
        ))
    }

    /// Join multicast groups for a socket.
    pub fn add_mcast_membership(&self, groups: Groups) -> Result<(), RouterError<u16, Buffer>> {
        self.socket
            .add_mcast_membership(groups)
            .map_err(RouterError::from)
    }

    /// Leave multicast groups for a socket.
    pub fn drop_mcast_membership(&self, groups: Groups) -> Result<(), RouterError<u16, Buffer>> {
        self.socket
            .drop_mcast_membership(groups)
            .map_err(RouterError::from)
    }

    /// List joined groups for a socket.
    pub fn list_mcast_membership(&self) -> Result<NetlinkBitArray, RouterError<u16, Buffer>> {
        self.socket
            .list_mcast_membership()
            .map_err(RouterError::from)
    }

    /// If [`true`] is passed in, enable extended ACKs for this socket. If [`false`]
    /// is passed in, disable extended ACKs for this socket.
    pub fn enable_ext_ack(&self, enable: bool) -> Result<(), RouterError<u16, Buffer>> {
        self.socket
            .enable_ext_ack(enable)
            .map_err(RouterError::from)
    }

    /// Return [`true`] if an extended ACK is enabled for this socket.
    pub fn get_ext_ack_enabled(&self) -> Result<bool, RouterError<u16, Buffer>> {
        self.socket.get_ext_ack_enabled().map_err(RouterError::from)
    }

    /// If [`true`] is passed in, enable strict checking for this socket. If [`false`]
    /// is passed in, disable strict checking for for this socket.
    /// Only supported by `NlFamily::Route` sockets.
    /// Requires Linux >= 4.20.
    pub fn enable_strict_checking(&self, enable: bool) -> Result<(), RouterError<u16, Buffer>> {
        self.socket
            .enable_strict_checking(enable)
            .map_err(RouterError::from)
    }

    /// Return [`true`] if strict checking is enabled for this socket.
    /// Only supported by `NlFamily::Route` sockets.
    /// Requires Linux >= 4.20.
    pub fn get_strict_checking_enabled(&self) -> Result<bool, RouterError<u16, Buffer>> {
        self.socket
            .get_strict_checking_enabled()
            .map_err(RouterError::from)
    }

    /// Get the PID for the current socket.
    pub fn pid(&self) -> u32 {
        self.socket.pid()
    }

    async fn next_seq(&self) -> u32 {
        let mut lock = self.seq.lock().await;
        let next = *lock;
        *lock = lock.wrapping_add(1);
        next
    }

    /// Send a message and return a handle for receiving responses from this message.
    pub async fn send<ST, SP, RT, RP>(
        &self,
        nl_type: ST,
        nl_flags: NlmF,
        nl_payload: NlPayload<ST, SP>,
    ) -> Result<NlRouterReceiverHandle<RT, RP>, RouterError<ST, SP>>
    where
        ST: NlType,
        SP: Size + ToBytes,
    {
        let msg = NlmsghdrBuilder::default()
            .nl_type(nl_type)
            .nl_flags(
                // Required for messages
                nl_flags | NlmF::REQUEST,
            )
            .nl_pid(self.socket.pid())
            .nl_seq(self.next_seq().await)
            .nl_payload(nl_payload)
            .build()?;
        let seq = *msg.nl_seq();
        let (sender, receiver) = channel(1024);
        self.senders.lock().await.insert(seq, sender);
        let flags = *msg.nl_flags();

        self.socket.send(&msg).await?;

        Ok(NlRouterReceiverHandle::new(
            receiver,
            Arc::clone(&self.senders),
            flags.contains(NlmF::ACK) && !flags.contains(NlmF::DUMP),
            Some(seq),
        ))
    }

    async fn get_genl_family(&self, family_name: &str) -> GenlFamily {
        let mut recv = self
            .send::<_, _, u16, Genlmsghdr<u8, u16>>(
                GenlId::Ctrl,
                NlmF::ACK,
                NlPayload::Payload(
                    GenlmsghdrBuilder::default()
                        .cmd(CtrlCmd::Getfamily)
                        .version(2)
                        .attrs(
                            once(
                                NlattrBuilder::default()
                                    .nla_type(
                                        AttrTypeBuilder::default()
                                            .nla_type(CtrlAttr::FamilyName)
                                            .build()?,
                                    )
                                    .nla_payload(family_name)
                                    .build()?,
                            )
                            .collect::<GenlBuffer<_, _>>(),
                        )
                        .build()?,
                ),
            )
            .await?;

        let mut buffer = NlBuffer::new();
        while let Some(msg) = recv.next().await {
            buffer.push(msg?);
        }
        Ok(buffer)
    }

    /// Convenience function for resolving a [`str`] containing the
    /// generic netlink family name to a numeric generic netlink ID.
    pub async fn resolve_genl_family(
        &self,
        family_name: &str,
    ) -> Result<u16, RouterError<GenlId, Genlmsghdr<CtrlCmd, CtrlAttr>>> {
        let mut res = Err(RouterError::new(format!(
            "Generic netlink family {family_name} was not found"
        )));

        let nlhdrs = self.get_genl_family(family_name).await?;
        for nlhdr in nlhdrs.into_iter() {
            if let NlPayload::Payload(p) = nlhdr.nl_payload() {
                let handle = p.attrs().get_attr_handle();
                if let Ok(u) = handle.get_attr_payload_as::<u16>(CtrlAttr::FamilyId) {
                    res = Ok(u);
                }
            }
        }

        res
    }

    /// Convenience function for resolving a [`str`] containing the
    /// multicast group name to a numeric multicast group ID.
    pub async fn resolve_nl_mcast_group(
        &self,
        family_name: &str,
        mcast_name: &str,
    ) -> Result<u32, RouterError<GenlId, Genlmsghdr<CtrlCmd, CtrlAttr>>> {
        let mut res = Err(RouterError::new(format!(
            "Failed to resolve multicast group ID for family name {family_name}, multicast group name {mcast_name}"
        )));

        let nlhdrs = self.get_genl_family(family_name).await?;
        for nlhdr in nlhdrs {
            if let NlPayload::Payload(p) = nlhdr.nl_payload() {
                let handle = p.attrs().get_attr_handle();
                let mcast_groups = handle.get_nested_attributes::<Index>(CtrlAttr::McastGroups)?;
                if let Some(id) = mcast_groups.iter().find_map(|item| {
                    let nested_attrs = item.get_attr_handle::<CtrlAttrMcastGrp>().ok()?;
                    let string = nested_attrs
                        .get_attr_payload_as_with_len::<String>(CtrlAttrMcastGrp::Name)
                        .ok()?;
                    if string.as_str() == mcast_name {
                        nested_attrs
                            .get_attr_payload_as::<u32>(CtrlAttrMcastGrp::Id)
                            .ok()
                    } else {
                        None
                    }
                }) {
                    res = Ok(id);
                }
            }
        }

        res
    }

    /// Look up netlink family and multicast group name by ID.
    pub async fn lookup_id(
        &self,
        id: u32,
    ) -> Result<(String, String), RouterError<GenlId, Genlmsghdr<CtrlCmd, CtrlAttr>>> {
        let mut res = Err(RouterError::new(
            "ID does not correspond to a multicast group",
        ));

        let mut recv = self
            .send::<_, _, u16, Genlmsghdr<u8, u16>>(
                GenlId::Ctrl,
                NlmF::DUMP,
                NlPayload::Payload(
                    GenlmsghdrBuilder::<CtrlCmd, CtrlAttr, NoUserHeader>::default()
                        .cmd(CtrlCmd::Getfamily)
                        .version(2)
                        .attrs(GenlBuffer::new())
                        .build()?,
                ),
            )
            .await?;
        while let Some(res_msg) = recv.next().await {
            let msg = res_msg?;

            if let NlPayload::Payload(p) = msg.nl_payload() {
                let attributes = p.attrs().get_attr_handle();
                let name =
                    attributes.get_attr_payload_as_with_len::<String>(CtrlAttr::FamilyName)?;
                let groups = match attributes.get_nested_attributes::<Index>(CtrlAttr::McastGroups)
                {
                    Ok(grps) => grps,
                    Err(_) => continue,
                };
                for group_by_index in groups.iter() {
                    let attributes = group_by_index.get_attr_handle::<CtrlAttrMcastGrp>()?;
                    if let Ok(mcid) = attributes.get_attr_payload_as::<u32>(CtrlAttrMcastGrp::Id) {
                        if mcid == id {
                            let mcast_name = attributes
                                .get_attr_payload_as_with_len::<String>(CtrlAttrMcastGrp::Name)?;
                            res = Ok((name.clone(), mcast_name));
                        }
                    }
                }
            }
        }

        res
    }
}

impl Drop for NlRouter {
    fn drop(&mut self) {
        if self.exit_sender.try_send(()).is_err() {
            warn!("Failed to send shutdown message; processing thread should exit anyway");
        }
    }
}

/// A handle for receiving and validating all messages that correspond to a request.
pub struct NlRouterReceiverHandle<T, P> {
    receiver: Receiver<Result<Nlmsghdr<u16, Buffer>, RouterError<u16, Buffer>>>,
    senders: Senders,
    needs_ack: bool,
    seq: Option<u32>,
    next_is_none: bool,
    next_is_ack: bool,
    data: PhantomData<(T, P)>,
}

impl<T, P> NlRouterReceiverHandle<T, P> {
    fn new(
        receiver: Receiver<Result<Nlmsghdr<u16, Buffer>, RouterError<u16, Buffer>>>,
        senders: Senders,
        needs_ack: bool,
        seq: Option<u32>,
    ) -> Self {
        NlRouterReceiverHandle {
            receiver,
            senders,
            needs_ack,
            seq,
            next_is_none: false,
            next_is_ack: false,
            data: PhantomData,
        }
    }
}

impl<T, P> NlRouterReceiverHandle<T, P>
where
    T: NlType,
    P: Size + FromBytesWithInput<Input = usize>,
{
    /// Imitates the [`Iterator`][Iterator] API but allows parsing differently typed
    /// messages in a sequence of messages meant for this receiver.
    pub async fn next<TT, PP>(&mut self) -> Option<Result<Nlmsghdr<TT, PP>, RouterError<TT, PP>>>
    where
        TT: NlType,
        PP: Size + FromBytesWithInput<Input = usize>,
    {
        if self.next_is_none {
            return None;
        }

        let mut msg = match self.receiver.recv().await {
            Some(untyped) => match untyped {
                Ok(u) => match u.to_typed::<TT, PP>() {
                    Ok(t) => t,
                    Err(e) => {
                        self.next_is_none = true;
                        return Some(Err(e));
                    }
                },
                Err(e) => {
                    self.next_is_none = true;
                    return Some(Err(match e.to_typed() {
                        Ok(e) => e,
                        Err(e) => e,
                    }));
                }
            },
            None => {
                self.next_is_none = true;
                return Some(Err(RouterError::ClosedChannel));
            }
        };

        let nl_type = Nlmsg::from((*msg.nl_type()).into());
        if let NlPayload::Ack(_) = msg.nl_payload() {
            self.next_is_none = true;
            if !self.needs_ack {
                return Some(Err(RouterError::UnexpectedAck));
            }
        } else if let Some(e) = msg.get_err() {
            self.next_is_none = true;
            if self.next_is_ack {
                return Some(Err(RouterError::NoAck));
            } else {
                return Some(Err(RouterError::<TT, PP>::Nlmsgerr(e)));
            }
        } else if (!msg.nl_flags().contains(NlmF::MULTI) || nl_type == Nlmsg::Done)
            && self.seq.is_some()
        {
            assert!(!self.next_is_ack);

            if self.needs_ack {
                self.next_is_ack = true;
            } else {
                self.next_is_none = true;
            }
        } else if self.next_is_ack {
            self.next_is_none = true;
            return Some(Err(RouterError::NoAck));
        }

        trace!("Router received message: {msg:?}");

        Some(Ok(msg))
    }
}

impl<T, P> Drop for NlRouterReceiverHandle<T, P> {
    fn drop(&mut self) {
        if let Some(seq) = self.seq {
            if let Ok(mut lock) = self.senders.try_lock() {
                lock.remove(&seq);
            }
        }
    }
}
