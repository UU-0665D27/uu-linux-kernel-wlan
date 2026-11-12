//! Подключение к сети по WPS PIN.
//!
//! Слой связывает nl80211 и [`WpsEnrollee`]:
//!
//! 1. интерфейс переводится в managed-режим и подключается к `BSSID` с
//!    WPS-элементом `Request Type = Enrollee`;
//! 2. после ассоциации открывается `AF_PACKET`-сокет с ethertype `0x888e`;
//! 3. EAP-WSC обмен идёт в EAP-Expanded (vendor `00:37:2a`, тип `1`);
//! 4. из `M8` извлекаются `SSID`, `Network Key` и типы безопасности.
//!
//! Сохранение конфигурации и переподключение с полученным PSK — задача
//! вызывающего кода.

use std::time::{Duration, Instant};

use uu_linux_kernel_netlink::{AttrWriter, IfType, read_u16};

use crate::high::nl80211_ext::{
    ATTR_AUTH_TYPE, ATTR_IE, ATTR_IFINDEX, ATTR_MAC, ATTR_SSID, ATTR_STATUS_CODE, ATTR_TIMED_OUT,
    ATTR_WIPHY_FREQ, AUTHTYPE_OPEN_SYSTEM, CMD_ASSOCIATE, CMD_AUTHENTICATE, CMD_DEAUTHENTICATE,
    CMD_DISASSOCIATE,
};
use crate::high::scan::{Bss, DEFAULT_SCAN_WAIT};
use crate::high::wps_enrollee::{WpsCredentials, WpsEnrollee, message_type};
use crate::high::{Wlan, validate_unicast};
use crate::raw::eapol::{
    EAP_FAILURE, EAP_REQUEST, EAP_RESPONSE, EAP_TYPE_EXPANDED, EAP_TYPE_IDENTITY, EAPOL_TYPE_EAP,
    EAPOL_TYPE_START, ETHERTYPE_EAPOL, PAE_GROUP_ADDR, WPS_ATTR_REQUEST_TYPE, WPS_ATTR_VERSION,
    WPS_IDENTITY_ENROLLEE, WPS_MSG_M2, WPS_MSG_M2D, WPS_MSG_M4, WPS_MSG_M6, WPS_MSG_M8,
    WPS_REQUEST_TYPE_ENROLLEE, WPS_RF_BAND_5GHZ, WPS_RF_BAND_24GHZ, WPS_VENDOR_ID, WPS_VENDOR_TYPE,
    WPS_VERSION_1_0, WSC_FLAG_LF, WSC_FLAG_MF, WSC_FRAGMENT_SIZE, WSC_OP_DONE, WSC_OP_FRAG_ACK,
    WSC_OP_MSG, WSC_OP_NACK, WSC_OP_START, WpsTlvWriter, eap_identity, eapol, wps_eap,
};
use crate::raw::ie::IeList;
use crate::raw::mac::MacAddr;
use crate::raw::{Eap, EapExpanded, Eapol, PacketSocket};
use crate::{Error, Result};

/// Общий таймаут WPS-обмена по умолчанию.
pub const DEFAULT_WPS_TIMEOUT: Duration = Duration::from_secs(120);

/// Период повторной отправки `EAPOL-Start`, пока AP молчит.
const EAPOL_START_RETRY: Duration = Duration::from_secs(5);
/// Таймаут ожидания ассоциации с точкой доступа.
pub const DEFAULT_ASSOC_TIMEOUT: Duration = Duration::from_secs(20);

/// Таймаут одного чтения EAPOL-кадра.
const EAP_RECV_TIMEOUT: Duration = Duration::from_secs(3);
/// Таймаут одного чтения события `nl80211`.
const MLME_POLL: Duration = Duration::from_millis(200);
/// Верхняя граница длины WSC-сообщения (как в hostap).
const WSC_MAX_MESSAGE: usize = 50_000;

impl Wlan {
    /// Подключается к сети по WPS PIN и возвращает учётные данные.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку netlink, сокета или протокола, если интерфейс не
    /// удалось перевести в managed-режим, ассоциация не состоялась или
    /// регистратор отклонил PIN.
    pub fn wps_pin_psk(
        &mut self,
        ssid: &[u8],
        bssid: MacAddr,
        pin: &str,
    ) -> Result<WpsCredentials> {
        self.wps_pin_psk_with_timeout(ssid, bssid, pin, DEFAULT_WPS_TIMEOUT)
    }

    /// Подключается к сети по WPS PIN с явным таймаутом обмена.
    ///
    /// # Errors
    ///
    /// См. [`Wlan::wps_pin_psk`].
    pub fn wps_pin_psk_with_timeout(
        &mut self,
        ssid: &[u8],
        bssid: MacAddr,
        pin: &str,
        timeout: Duration,
    ) -> Result<WpsCredentials> {
        if ssid.is_empty() || ssid.len() > 32 {
            return Err(Error::Message("SSID must contain 1..=32 bytes".to_string()));
        }
        let bssid = validate_unicast(bssid)?;
        info!(
            ifname = %self.iface.name,
            %bssid,
            ssid_len = ssid.len(),
            pin_len = pin.len(),
            "starting WPS PIN enrolment"
        );

        self.ensure_station()?;
        if self.disconnect().is_err() {
            debug!("no current connection to disconnect");
        } else {
            debug!("disconnected from the current network");
        }

        let local = MacAddr::new(self.iface.mac);
        let enrollee = WpsEnrollee::new(local, pin)?;
        debug!(%local, "local enrollee MAC");

        let target = self.scan_target(bssid)?;
        let frequency = target.as_ref().map(|bss| bss.frequency);
        self.authenticate(ssid, bssid, frequency)?;
        self.associate_wps(ssid, bssid, frequency)?;

        let rf_band = rf_band_for(frequency);
        let mut session = Session::new(&self.socket, local, bssid, enrollee, rf_band);
        let credentials = session.run(timeout)?;
        info!(
            ssid = %String::from_utf8_lossy(&credentials.ssid),
            psk_len = credentials.psk().len(),
            "WPS credentials received"
        );
        Ok(credentials)
    }

    /// Переводит интерфейс в managed-режим и открывает EAPOL-сокет.
    fn ensure_station(&mut self) -> Result<()> {
        if self.iface.if_type != IfType::Station {
            self.nl.change_mode(&self.iface, IfType::Station, None)?;
            self.refresh()?;
        }
        let group = self.nl.genl_mut().multicast_group("nl80211", "mlme")?;
        self.nl.genl().socket().join_multicast(group)?;
        uu_linux_kernel_netlink::set_if_up(&self.iface.name, true)?;
        self.socket = PacketSocket::open_ethertype(&self.iface.name, ETHERTYPE_EAPOL)?;
        Ok(())
    }

    /// Ищет `BSSID` в результатах сканирования.
    fn scan_target(&mut self, bssid: MacAddr) -> Result<Option<Bss>> {
        debug!(%bssid, "scanning for the target BSSID");
        let mut found = None;
        self.scan_each_with(DEFAULT_SCAN_WAIT, |bss| {
            if found.is_none() && bss.bssid == bssid {
                found = Some(bss);
            }
        })?;
        debug!(
            found = found.is_some(),
            frequency = found.as_ref().map(|bss| bss.frequency),
            channel = found.as_ref().and_then(Bss::channel),
            wps = found.as_ref().is_some_and(Bss::is_wps),
            wps_selected_registrar =
                ?found.as_ref().and_then(|bss| bss.wps.as_ref()).and_then(|ie| ie.selected_registrar),
            wps_locked =
                ?found.as_ref().and_then(|bss| bss.wps.as_ref()).and_then(|ie| ie.ap_setup_locked),
            signal_dbm = found.as_ref().and_then(|bss| bss.signal_dbm),
            "scan for the target BSSID finished"
        );
        if found.is_none() {
            warn!(%bssid, "target BSSID is not present in scan results");
        }
        Ok(found)
    }

    /// Выполняет открытую аутентификацию на `bssid`.
    ///
    /// `NL80211_CMD_CONNECT` на этом ядре/iwiwifi не начинает аутентификацию
    /// (cfg80211 сразу отдаёт `timed out`), поэтому, как и `wpa_supplicant`,
    /// шаги SME выполняются явно.
    fn authenticate(&mut self, ssid: &[u8], bssid: MacAddr, frequency: Option<u32>) -> Result<()> {
        let mut attrs = AttrWriter::new();
        attrs.u32(ATTR_IFINDEX, self.iface.index);
        attrs.bytes(ATTR_MAC, &bssid.octets());
        attrs.bytes(ATTR_SSID, ssid);
        attrs.u32(ATTR_AUTH_TYPE, AUTHTYPE_OPEN_SYSTEM);
        if let Some(freq) = frequency {
            attrs.u32(ATTR_WIPHY_FREQ, freq);
        }

        debug!(
            ifname = %self.iface.name,
            %bssid,
            ?frequency,
            "requesting open-system authentication"
        );
        let family = self.nl.family_id();
        self.nl
            .genl_mut()
            .execute(family, CMD_AUTHENTICATE, 0, &attrs)?;
        self.wait_mlme(CMD_AUTHENTICATE, bssid, DEFAULT_ASSOC_TIMEOUT)
    }

    /// Отправляет запрос ассоциации с WPS-элементом `Enrollee`.
    fn associate_wps(&mut self, ssid: &[u8], bssid: MacAddr, frequency: Option<u32>) -> Result<()> {
        let mut wps = WpsTlvWriter::new();
        wps.u8(WPS_ATTR_VERSION, WPS_VERSION_1_0)?;
        wps.u8(WPS_ATTR_REQUEST_TYPE, WPS_REQUEST_TYPE_ENROLLEE)?;
        let mut ies = IeList::new();
        ies.wps(wps.as_bytes())?;

        let mut attrs = AttrWriter::new();
        attrs.u32(ATTR_IFINDEX, self.iface.index);
        attrs.bytes(ATTR_MAC, &bssid.octets());
        attrs.bytes(ATTR_SSID, ssid);
        attrs.bytes(ATTR_IE, ies.as_bytes());
        if let Some(freq) = frequency {
            attrs.u32(ATTR_WIPHY_FREQ, freq);
        }

        debug!(
            ifname = %self.iface.name,
            %bssid,
            ?frequency,
            ie_len = ies.as_bytes().len(),
            "requesting association with the WPS IE"
        );
        let family = self.nl.family_id();
        self.nl
            .genl_mut()
            .execute(family, CMD_ASSOCIATE, 0, &attrs)?;
        self.wait_mlme(CMD_ASSOCIATE, bssid, DEFAULT_ASSOC_TIMEOUT)
    }

    /// Ждёт событие `cmd` для `bssid` и проверяет код статуса.
    fn wait_mlme(&mut self, cmd: u8, bssid: MacAddr, timeout: Duration) -> Result<()> {
        debug!(%bssid, cmd, ?timeout, "waiting for an nl80211 event");
        self.nl.genl().socket().set_recv_timeout(Some(MLME_POLL))?;
        let result = self.wait_mlme_event(cmd, bssid, timeout);
        self.nl.genl().socket().set_recv_timeout(None)?;
        result
    }

    fn wait_mlme_event(&mut self, cmd: u8, bssid: MacAddr, timeout: Duration) -> Result<()> {
        let deadline = deadline_after(timeout)?;
        loop {
            let Some(message) = self.nl.genl_mut().socket_mut().recv_event()? else {
                if Instant::now() >= deadline {
                    error!(%bssid, cmd, "nl80211 event timed out");
                    return Err(Error::Message(format!(
                        "timed out waiting for the nl80211 event of {bssid}"
                    )));
                }
                continue;
            };
            let Some(header) = message.genl_header() else {
                continue;
            };
            if header.cmd != cmd
                && header.cmd != CMD_DEAUTHENTICATE
                && header.cmd != CMD_DISASSOCIATE
            {
                continue;
            }
            let mut event_bssid = None;
            let mut status = None;
            let mut timed_out = false;
            for (kind, value) in message.attrs() {
                match kind {
                    ATTR_MAC => event_bssid = <[u8; 6]>::try_from(value).ok(),
                    ATTR_STATUS_CODE => status = read_u16(value),
                    ATTR_TIMED_OUT => timed_out = true,
                    _ => {}
                }
            }
            if event_bssid.is_some_and(|event| event != bssid.octets()) {
                continue;
            }
            if header.cmd != cmd {
                error!(%bssid, cmd = header.cmd, "the AP dropped the connection");
                return Err(Error::Message(format!("{bssid} dropped the connection")));
            }
            if timed_out {
                error!(%bssid, "the AP did not answer");
                return Err(Error::Message(format!("{bssid} did not answer")));
            }
            match status {
                Some(0) => {
                    info!(%bssid, cmd, "nl80211 event reports success");
                    return Ok(());
                }
                Some(code) => {
                    error!(%bssid, status = code, "the AP rejected the request");
                    return Err(Error::Message(format!(
                        "{bssid} rejected the request with status {code}"
                    )));
                }
                None => return Ok(()),
            }
        }
    }
}

/// Возвращает момент в будущем или ошибку при переполнении.
fn deadline_after(timeout: Duration) -> Result<Instant> {
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| Error::Message("timeout is too large".to_string()))
}

/// `RF Bands` для `M1` по частоте подключения.
const fn rf_band_for(frequency: Option<u32>) -> u8 {
    match frequency {
        Some(freq) if freq >= 3000 => WPS_RF_BAND_5GHZ,
        _ => WPS_RF_BAND_24GHZ,
    }
}

/// Состояние одного EAP-WSC обмена.
struct Session<'a> {
    socket: &'a PacketSocket,
    local: MacAddr,
    bssid: MacAddr,
    enrollee: WpsEnrollee,
    rf_band: u8,
    in_buf: Vec<u8>,
    in_op: Option<u8>,
    outgoing: Option<Outgoing>,
    contacted: bool,
}

impl<'a> Session<'a> {
    const fn new(
        socket: &'a PacketSocket,
        local: MacAddr,
        bssid: MacAddr,
        enrollee: WpsEnrollee,
        rf_band: u8,
    ) -> Self {
        Self {
            socket,
            local,
            bssid,
            enrollee,
            rf_band,
            in_buf: Vec::new(),
            in_op: None,
            outgoing: None,
            contacted: false,
        }
    }

    /// Проводит обмен до получения учётных данных.
    fn run(&mut self, timeout: Duration) -> Result<WpsCredentials> {
        self.socket.set_recv_timeout(Some(EAP_RECV_TIMEOUT))?;
        let deadline = deadline_after(timeout)?;
        info!(?timeout, "starting EAP-WSC exchange");
        self.send_eapol_start()?;
        let mut retry_at = deadline_after(EAPOL_START_RETRY)?;
        loop {
            if Instant::now() >= deadline {
                error!("EAP-WSC exchange timed out");
                return Err(Error::Message("WPS exchange timed out".to_string()));
            }
            if !self.contacted && Instant::now() >= retry_at {
                debug!("the AP did not answer EAPOL-Start; retrying");
                self.send_eapol_start()?;
                retry_at = deadline_after(EAPOL_START_RETRY)?;
            }
            let frame = match self.socket.recv() {
                Ok(frame) => frame,
                Err(Error::Io(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    trace!("no EAPOL frame within the read timeout");
                    continue;
                }
                Err(error) => return Err(error),
            };
            trace!(len = frame.len(), "EAPOL frame received");
            if let Some(credentials) = self.handle_frame(&frame)? {
                return Ok(credentials);
            }
        }
    }

    /// Отправляет `EAPOL-Start` на групповой адрес `PAE`.
    fn send_eapol_start(&self) -> Result<()> {
        send_eapol_frame(self.socket, self.local, EAPOL_TYPE_START, &[])
    }

    /// Разбирает кадр и обрабатывает EAP-запрос.
    fn handle_frame(&mut self, frame: &[u8]) -> Result<Option<WpsCredentials>> {
        let Some((source, body)) = split_eapol_frame(frame) else {
            return Ok(None);
        };
        if source != self.bssid.octets() {
            return Ok(None);
        }
        let Some(eapol) = Eapol::parse(body) else {
            trace!(len = body.len(), "ignoring malformed EAPOL frame");
            return Ok(None);
        };
        if eapol.packet_type != EAPOL_TYPE_EAP {
            trace!(
                packet_type = eapol.packet_type,
                "ignoring non-EAP EAPOL frame"
            );
            return Ok(None);
        }
        self.contacted = true;
        match eapol.body.first().copied() {
            Some(EAP_REQUEST) => self.handle_request(eapol.body),
            Some(EAP_FAILURE) => {
                error!("registrar sent EAP-Failure");
                Err(Error::Message("WPS registrar reported failure".to_string()))
            }
            _ => {
                trace!("ignoring non-request EAP packet");
                Ok(None)
            }
        }
    }

    /// Отвечает на `EAP-Request`.
    fn handle_request(&mut self, body: &[u8]) -> Result<Option<WpsCredentials>> {
        let Some(eap) = Eap::parse(body) else {
            return Ok(None);
        };
        match eap.packet_type {
            EAP_TYPE_IDENTITY => {
                debug!(id = eap.id, "EAP-Request/Identity");
                let response = eap_identity(EAP_RESPONSE, eap.id, WPS_IDENTITY_ENROLLEE)?;
                self.send_eap(&response)?;
                trace!("EAP-Response/Identity sent");
                Ok(None)
            }
            EAP_TYPE_EXPANDED => {
                let Some(expanded) = EapExpanded::parse(body) else {
                    trace!(len = body.len(), "ignoring malformed EAP-Expanded");
                    return Ok(None);
                };
                if expanded.vendor_id != WPS_VENDOR_ID || expanded.vendor_type != WPS_VENDOR_TYPE {
                    trace!(
                        vendor = ?expanded.vendor_id,
                        vendor_type = expanded.vendor_type,
                        "ignoring foreign EAP-Expanded vendor"
                    );
                    return Ok(None);
                }
                self.handle_wsc(eap.id, expanded.data)
            }
            _ => {
                trace!("ignoring EAP request type");
                Ok(None)
            }
        }
    }

    /// Разбирает WSC-заголовок и собирает фрагменты.
    fn handle_wsc(&mut self, id: u8, data: &[u8]) -> Result<Option<WpsCredentials>> {
        let Some(&op_code) = data.first() else {
            warn!("WSC frame has no op-code");
            return Ok(None);
        };
        let Some(&flags) = data.get(1) else {
            warn!("WSC frame has no flags");
            return Ok(None);
        };
        trace!(op_code, flags, len = data.len(), "WSC frame");
        let position = if flags & WSC_FLAG_LF != 0 {
            let Some(length_bytes) = data.get(2..4) else {
                return Ok(None);
            };
            let total = usize::from(u16::from_be_bytes(
                <[u8; 2]>::try_from(length_bytes).map_err(|_| Error::Malformed)?,
            ));
            if total > WSC_MAX_MESSAGE {
                warn!(total, limit = WSC_MAX_MESSAGE, "WSC message is too long");
                return Ok(None);
            }
            4
        } else {
            2
        };
        let Some(payload) = data.get(position..) else {
            return Ok(None);
        };

        if op_code == WSC_OP_FRAG_ACK {
            debug!("registrar acknowledged a WSC fragment");
            if let Some(outgoing) = self.outgoing.as_mut() {
                outgoing.send_next(self.socket, self.local, id)?;
                if outgoing.is_complete() {
                    self.outgoing = None;
                }
            }
            return Ok(None);
        }

        if self.in_op != Some(op_code) {
            if !self.in_buf.is_empty() {
                trace!(
                    old_op = ?self.in_op,
                    op_code,
                    "restarting a fragmented WSC message"
                );
            }
            self.in_buf.clear();
            self.in_op = Some(op_code);
        }
        self.in_buf.extend_from_slice(payload);
        if flags & WSC_FLAG_MF != 0 {
            trace!(
                buffered = self.in_buf.len(),
                "waiting for the next WSC fragment"
            );
            return Ok(None);
        }
        let message = std::mem::take(&mut self.in_buf);
        self.in_op = None;
        trace!(len = message.len(), "WSC message assembled");
        self.handle_wsc_message(id, op_code, &message)
    }

    /// Обрабатывает op-code `WSC` и, если нужно, отвечает.
    fn handle_wsc_message(
        &mut self,
        id: u8,
        op_code: u8,
        message: &[u8],
    ) -> Result<Option<WpsCredentials>> {
        trace!(op_code, len = message.len(), "handling WSC op-code");
        match op_code {
            WSC_OP_START => {
                debug!("registrar started WSC; sending M1");
                let m1 = self.enrollee.m1(self.rf_band)?;
                self.send_wsc(id, WSC_OP_MSG, &m1)?;
                Ok(None)
            }
            WSC_OP_MSG => self.handle_message(id, message),
            WSC_OP_NACK => {
                debug!(payload = ?message, "WSC NACK payload");
                #[cfg(feature = "tracing")]
                for tlv in crate::raw::eapol::WpsTlvIter::new(message) {
                    debug!(
                        attr = tlv.kind,
                        value = ?tlv.value,
                        "NACK attribute"
                    );
                }
                let reason = crate::high::wps_enrollee::config_error(message);
                error!(?reason, "registrar sent WSC NACK");
                Err(Error::Message(reason.map_or_else(
                    || "WPS registrar rejected the exchange".to_string(),
                    |code| format!("WPS registrar rejected the exchange (error {code:#06x})"),
                )))
            }
            _ => {
                trace!("ignoring unsolicited WSC op-code");
                Ok(None)
            }
        }
    }

    /// Прогоняет `M2`–`M8` через state machine enrollee.
    fn handle_message(&mut self, id: u8, message: &[u8]) -> Result<Option<WpsCredentials>> {
        let Some(kind) = message_type(message) else {
            return Err(Error::Malformed);
        };
        debug!(kind, len = message.len(), "WPS message received");
        match kind {
            WPS_MSG_M2 => {
                let m3 = self.enrollee.process_m2(message)?;
                debug!("M2 processed; sending M3");
                self.send_wsc(id, WSC_OP_MSG, &m3)?;
                Ok(None)
            }
            WPS_MSG_M4 => {
                let m5 = self.enrollee.process_m4(message)?;
                debug!("M4 processed; sending M5");
                self.send_wsc(id, WSC_OP_MSG, &m5)?;
                Ok(None)
            }
            WPS_MSG_M6 => {
                let m7 = self.enrollee.process_m6(message)?;
                debug!("M6 processed; sending M7");
                self.send_wsc(id, WSC_OP_MSG, &m7)?;
                Ok(None)
            }
            WPS_MSG_M8 => {
                let credentials = self.enrollee.process_m8(message)?;
                info!("M8 processed; sending WSC_Done");
                let done = self.enrollee.wsc_done_message()?;
                self.send_wsc(id, WSC_OP_DONE, &done)?;
                Ok(Some(credentials))
            }
            WPS_MSG_M2D => {
                let ack = self.enrollee.wsc_ack_message()?;
                self.send_wsc(id, WSC_OP_MSG, &ack)?;
                warn!("registrar sent M2D: WPS pairing is not active on the AP");
                Err(Error::Message(
                    "WPS registrar answered M2D; start WPS PIN pairing on the router (enter the PIN in its WPS page) and retry"
                        .to_string(),
                ))
            }
            _ => Err(Error::Message(format!(
                "unexpected WPS message type {kind:#04x}"
            ))),
        }
    }

    /// Отправляет `EAP-Response/Expanded` с WSC-сообщением.
    fn send_wsc(&mut self, id: u8, op_code: u8, payload: &[u8]) -> Result<()> {
        trace!(op_code, len = payload.len(), "sending WSC message");
        let mut outgoing = Outgoing::new(op_code, payload);
        outgoing.send_next(self.socket, self.local, id)?;
        if outgoing.is_complete() {
            self.outgoing = None;
        } else {
            self.outgoing = Some(outgoing);
        }
        Ok(())
    }

    /// Отправляет готовый `EAP`-пакет.
    fn send_eap(&self, eap: &[u8]) -> Result<()> {
        send_eapol_frame(self.socket, self.local, EAPOL_TYPE_EAP, eap)
    }
}

/// Исходящее WSC-сообщение, возможно разбитое на фрагменты.
struct Outgoing {
    op_code: u8,
    payload: Vec<u8>,
    offset: usize,
    fragment_size: usize,
}

impl Outgoing {
    fn new(op_code: u8, payload: &[u8]) -> Self {
        Self {
            op_code,
            payload: payload.to_vec(),
            offset: 0,
            fragment_size: WSC_FRAGMENT_SIZE,
        }
    }

    const fn is_complete(&self) -> bool {
        self.offset >= self.payload.len()
    }

    fn send_next(&mut self, socket: &PacketSocket, local: MacAddr, id: u8) -> Result<()> {
        let (body, next) = wsc_chunk(self.op_code, &self.payload, self.offset, self.fragment_size)?;
        let eap = wps_eap(EAP_RESPONSE, id, &body)?;
        send_eapol_frame(socket, local, EAPOL_TYPE_EAP, &eap)?;
        self.offset = next;
        Ok(())
    }
}

/// Формирует WSC-тело с учётом фрагментации.
///
/// Возвращает тело (`op-code`, `flags`, при необходимости длина) и смещение
/// следующего фрагмента.
fn wsc_chunk(
    op_code: u8,
    payload: &[u8],
    offset: usize,
    fragment_size: usize,
) -> Result<(Vec<u8>, usize)> {
    let remaining = payload.len().checked_sub(offset).ok_or(Error::Malformed)?;
    if remaining.saturating_add(2) <= fragment_size {
        let mut body = Vec::with_capacity(2 + remaining);
        body.push(op_code);
        body.push(0);
        body.extend_from_slice(payload.get(offset..).ok_or(Error::Malformed)?);
        return Ok((body, payload.len()));
    }

    let first = offset == 0;
    let (flags, chunk_len) = if first {
        (
            WSC_FLAG_MF | WSC_FLAG_LF,
            remaining.min(fragment_size.saturating_sub(4)),
        )
    } else {
        (WSC_FLAG_MF, remaining.min(fragment_size.saturating_sub(2)))
    };
    if chunk_len == 0 {
        return Err(Error::Message(
            "EAP-WSC fragment size is too small".to_string(),
        ));
    }
    let end = offset.checked_add(chunk_len).ok_or(Error::Malformed)?;
    let chunk = payload.get(offset..end).ok_or(Error::Malformed)?;

    let mut body = Vec::with_capacity(4 + chunk_len);
    body.push(op_code);
    body.push(flags);
    if flags & WSC_FLAG_LF != 0 {
        let total = u16::try_from(payload.len())
            .map_err(|_| Error::OutOfRange(i64::try_from(payload.len()).unwrap_or(i64::MAX)))?;
        body.extend_from_slice(&total.to_be_bytes());
    }
    body.extend_from_slice(chunk);
    Ok((body, end))
}

/// Делит Ethernet-кадр на MAC источника и тело `EAPOL`.
fn split_eapol_frame(frame: &[u8]) -> Option<([u8; 6], &[u8])> {
    let source = <[u8; 6]>::try_from(frame.get(6..12)?).ok()?;
    let ethertype = u16::from_be_bytes(<[u8; 2]>::try_from(frame.get(12..14)?).ok()?);
    if ethertype != ETHERTYPE_EAPOL {
        return None;
    }
    Some((source, frame.get(14..)?))
}

/// Собирает Ethernet + `EAPOL` кадр и отправляет его.
fn send_eapol_frame(
    socket: &PacketSocket,
    local: MacAddr,
    packet_type: u8,
    body: &[u8],
) -> Result<()> {
    let encoded = eapol(packet_type, body)?;
    let mut frame = Vec::with_capacity(14 + encoded.len());
    frame.extend_from_slice(&PAE_GROUP_ADDR);
    frame.extend_from_slice(&local.octets());
    frame.extend_from_slice(&ETHERTYPE_EAPOL.to_be_bytes());
    frame.extend_from_slice(&encoded);
    trace!(len = frame.len(), "EAPOL frame sent");
    socket.send(&frame)
}

#[cfg(test)]
mod tests {
    use super::{split_eapol_frame, wsc_chunk};
    use crate::raw::eapol::{
        ETHERTYPE_EAPOL, WSC_FLAG_LF, WSC_FLAG_MF, WSC_FRAGMENT_SIZE, WSC_OP_MSG,
    };

    #[test]
    fn splits_eapol_frame() {
        let mut frame = vec![0u8; 14];
        frame[6..12].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        frame[12..14].copy_from_slice(&ETHERTYPE_EAPOL.to_be_bytes());
        frame.extend_from_slice(&[0xaa, 0xbb]);
        let (source, body) = split_eapol_frame(&frame).unwrap();
        assert_eq!(source, [1, 2, 3, 4, 5, 6]);
        assert_eq!(body, &[0xaa, 0xbb]);
    }

    #[test]
    fn rejects_foreign_ethertype() {
        let frame = [0u8; 14];
        assert!(split_eapol_frame(&frame).is_none());
    }

    #[test]
    fn sends_small_message_without_fragments() {
        let payload = [0x11u8; 16];
        let (body, next) = wsc_chunk(WSC_OP_MSG, &payload, 0, WSC_FRAGMENT_SIZE).unwrap();
        assert_eq!(body[0], WSC_OP_MSG);
        assert_eq!(body[1], 0);
        assert_eq!(&body[2..], &payload);
        assert_eq!(next, payload.len());
    }

    #[test]
    fn fragments_large_message() {
        let payload = vec![0x22u8; WSC_FRAGMENT_SIZE * 2];
        let (first, next) = wsc_chunk(WSC_OP_MSG, &payload, 0, WSC_FRAGMENT_SIZE).unwrap();
        assert_eq!(first[0], WSC_OP_MSG);
        assert_eq!(first[1], WSC_FLAG_MF | WSC_FLAG_LF);
        let declared = u16::from_be_bytes([first[2], first[3]]);
        assert_eq!(usize::from(declared), payload.len());
        assert_eq!(first.len(), WSC_FRAGMENT_SIZE);

        let (second, next) = wsc_chunk(WSC_OP_MSG, &payload, next, WSC_FRAGMENT_SIZE).unwrap();
        assert_eq!(second[0], WSC_OP_MSG);
        assert_eq!(second[1], WSC_FLAG_MF);
        assert_eq!(second.len(), WSC_FRAGMENT_SIZE);

        let (last, end) = wsc_chunk(WSC_OP_MSG, &payload, next, WSC_FRAGMENT_SIZE).unwrap();
        assert_eq!(last[0], WSC_OP_MSG);
        assert_eq!(last[1], 0);
        assert_eq!(end, payload.len());
    }
}
