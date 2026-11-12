//! WPS enrollee: state machine `M1`–`M8` поверх EAP-WSC.
//!
//! Реализация повторяет [`hostap`](https://w1.fi/hostap.git):
//! `wps_enrollee.c`, `wps_common.c` и `wps_attr_build.c`. Обмен идёт через
//! EAP-Expanded (vendor `00:37:2a`, тип `1`); транспорт находится в
//! [`crate::high::wps_connect`].
//!
//! Ключи:
//!
//! * `DHKey = SHA-256(g^AB mod p)`;
//! * `KDK = HMAC-SHA-256(DHKey, N1 || MAC_E || N2)`;
//! * `AuthKey || KeyWrapKey || EMSK = KDF(KDK, "Wi-Fi Easy and Secure Key Derivation", 80)`;
//! * `PSK1/PSK2 = HMAC-SHA-256(AuthKey, первая/вторая половина PIN)`.

use crate::crypto::aes::{aes128_cbc_decrypt, aes128_cbc_encrypt};
use crate::crypto::dh::{DH_LEN, DH_PRIVATE_LEN, generate_private_key, public_key, shared_secret};
use crate::crypto::hmac::hmac_sha256;
use crate::crypto::random::fill_random;
use crate::crypto::sha256::sha256;
use crate::raw::eapol::{
    WPS_ASSOC_NOT_ASSOC, WPS_ATTR_ASSOC_STATE, WPS_ATTR_AUTH_TYPE, WPS_ATTR_AUTH_TYPE_FLAGS,
    WPS_ATTR_AUTHENTICATOR, WPS_ATTR_CONFIG_ERROR, WPS_ATTR_CONFIG_METHODS,
    WPS_ATTR_CONNECTION_TYPE_FLAGS, WPS_ATTR_CREDENTIAL, WPS_ATTR_DEVICE_NAME,
    WPS_ATTR_DEVICE_PASSWORD_ID, WPS_ATTR_E_HASH1, WPS_ATTR_E_HASH2, WPS_ATTR_E_SNONCE1,
    WPS_ATTR_E_SNONCE2, WPS_ATTR_ENCRYPTED_SETTINGS, WPS_ATTR_ENCRYPTION_TYPE,
    WPS_ATTR_ENCRYPTION_TYPE_FLAGS, WPS_ATTR_ENROLLEE_NONCE, WPS_ATTR_KEY_WRAP_AUTH,
    WPS_ATTR_MAC_ADDR, WPS_ATTR_MANUFACTURER, WPS_ATTR_MESSAGE_TYPE, WPS_ATTR_MODEL_NAME,
    WPS_ATTR_MODEL_NUMBER, WPS_ATTR_NETWORK_KEY, WPS_ATTR_OS_VERSION, WPS_ATTR_PRIMARY_DEVICE_TYPE,
    WPS_ATTR_PUBLIC_KEY, WPS_ATTR_R_HASH1, WPS_ATTR_R_HASH2, WPS_ATTR_R_SNONCE1,
    WPS_ATTR_R_SNONCE2, WPS_ATTR_REGISTRAR_NONCE, WPS_ATTR_RF_BANDS, WPS_ATTR_SSID, WPS_ATTR_STATE,
    WPS_ATTR_UUID_E, WPS_ATTR_VERSION, WPS_AUTH_WPA2PSK, WPS_AUTH_WPAPSK, WPS_CFG_NO_ERROR,
    WPS_CONFIG_KEYPAD, WPS_CONFIG_LABEL, WPS_CONN_ESS, WPS_DEVICE_PASSWORD_ID_PIN, WPS_ENCR_AES,
    WPS_ENCR_TKIP, WPS_MSG_DONE, WPS_MSG_M1, WPS_MSG_M3, WPS_MSG_M5, WPS_MSG_M7,
    WPS_STATE_NOT_CONFIGURED, WPS_VERSION_1_0, WpsTlvWriter,
};
use crate::raw::mac::MacAddr;
use crate::{Error, Result};

const NONCE_LEN: usize = 16;
const HASH_LEN: usize = 32;
const PSK_LEN: usize = 32;
const AUTHKEY_LEN: usize = 32;
const KEYWRAP_LEN: usize = 16;
const KWA_LEN: usize = 8;
const BLOCK_LEN: usize = 16;
const PIN_LEN: usize = 8;
const KDF_LEN: usize = AUTHKEY_LEN + KEYWRAP_LEN + 32;
const KDF_LABEL: &[u8] = b"Wi-Fi Easy and Secure Key Derivation";

/// Учётные данные, полученные от регистратора в `M8`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WpsCredentials {
    /// `SSID` сети.
    pub ssid: Vec<u8>,
    /// `Network Key`: пароль или 64-символьный hex-PSK.
    pub network_key: Vec<u8>,
    /// `Authentication Type` (`WPS_AUTH_*`).
    pub auth_type: u16,
    /// `Encryption Type` (`WPS_ENCR_*`).
    pub encryption_type: u16,
    /// `MAC Address` из учётных данных, если он был.
    pub mac_addr: Option<MacAddr>,
}

impl WpsCredentials {
    /// Пароль в виде строки (для 64-символьного hex-PSK это сам PSK).
    #[must_use]
    pub fn psk(&self) -> String {
        String::from_utf8_lossy(&self.network_key).into_owned()
    }

    /// Возвращает `true`, если `Network Key` уже является hex-PSK.
    #[must_use]
    pub fn is_hex_psk(&self) -> bool {
        self.network_key.len() == 64 && self.network_key.iter().all(u8::is_ascii_hexdigit)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    WaitM2,
    WaitM4,
    WaitM6,
    WaitM8,
    Done,
}

/// Состояние одного WPS-сеанса enrollee.
#[derive(Debug)]
pub struct WpsEnrollee {
    mac: MacAddr,
    pin: [u8; PIN_LEN],
    uuid_e: [u8; NONCE_LEN],
    nonce_e: [u8; NONCE_LEN],
    nonce_r: [u8; NONCE_LEN],
    private_key: [u8; DH_PRIVATE_LEN],
    public_key_e: [u8; DH_LEN],
    public_key_r: Vec<u8>,
    authkey: [u8; AUTHKEY_LEN],
    keywrapkey: [u8; KEYWRAP_LEN],
    psk1: [u8; PSK_LEN],
    psk2: [u8; PSK_LEN],
    e_s1: [u8; NONCE_LEN],
    e_s2: [u8; NONCE_LEN],
    r_hash1: [u8; HASH_LEN],
    r_hash2: [u8; HASH_LEN],
    last_message: Vec<u8>,
    state: State,
}

/// Извлекает `Configuration Error` из сообщения `WSC_NACK`.
#[must_use]
pub fn config_error(message: &[u8]) -> Option<u16> {
    let value = tlv_value(message, WPS_ATTR_CONFIG_ERROR)?;
    <[u8; 2]>::try_from(value).ok().map(u16::from_be_bytes)
}

impl WpsEnrollee {
    /// Создаёт сеанс для `PIN`, введённого пользователем.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::Message`], если PIN не состоит из 8 цифр, и
    /// [`Error::Io`], если `getrandom(2)` недоступен.
    pub fn new(mac: MacAddr, pin: &str) -> Result<Self> {
        if pin.len() != PIN_LEN || !pin.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Error::Message("WPS PIN must be 8 digits".to_string()));
        }
        let mut pin_bytes = [0u8; PIN_LEN];
        pin_bytes.copy_from_slice(pin.as_bytes());

        let mut uuid_e = [0u8; NONCE_LEN];
        fill_random(&mut uuid_e)?;
        if let Some(byte) = uuid_e.get_mut(6) {
            *byte = (*byte & 0x0f) | 0x40;
        }
        if let Some(byte) = uuid_e.get_mut(8) {
            *byte = (*byte & 0x3f) | 0x80;
        }

        let mut nonce_e = [0u8; NONCE_LEN];
        fill_random(&mut nonce_e)?;
        let mut secret_nonces = [0u8; NONCE_LEN * 2];
        fill_random(&mut secret_nonces)?;
        let mut e_s1 = [0u8; NONCE_LEN];
        let mut e_s2 = [0u8; NONCE_LEN];
        if let (Some(first), Some(second)) = (
            secret_nonces.get(..NONCE_LEN),
            secret_nonces.get(NONCE_LEN..),
        ) {
            e_s1.copy_from_slice(first);
            e_s2.copy_from_slice(second);
        }

        let private_key = generate_private_key()?;
        let public_key_e = public_key(&private_key);

        Ok(Self {
            mac,
            pin: pin_bytes,
            uuid_e,
            nonce_e,
            nonce_r: [0u8; NONCE_LEN],
            private_key,
            public_key_e,
            public_key_r: Vec::new(),
            authkey: [0u8; AUTHKEY_LEN],
            keywrapkey: [0u8; KEYWRAP_LEN],
            psk1: [0u8; PSK_LEN],
            psk2: [0u8; PSK_LEN],
            e_s1,
            e_s2,
            r_hash1: [0u8; HASH_LEN],
            r_hash2: [0u8; HASH_LEN],
            last_message: Vec::new(),
            state: State::Idle,
        })
    }

    /// Возвращает `true`, если сеанс завершён и учётные данные получены.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        matches!(self.state, State::Done)
    }

    /// Собирает `M1`.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::OutOfRange`] при переполнении TLV (невозможно для
    /// фиксированного набора атрибутов).
    pub fn m1(&mut self) -> Result<Vec<u8>> {
        let mut writer = WpsTlvWriter::new();
        writer.u8(WPS_ATTR_VERSION, WPS_VERSION_1_0)?;
        writer.u8(WPS_ATTR_MESSAGE_TYPE, WPS_MSG_M1)?;
        writer.push(WPS_ATTR_UUID_E, &self.uuid_e)?;
        writer.push(WPS_ATTR_MAC_ADDR, &self.mac.octets())?;
        writer.push(WPS_ATTR_ENROLLEE_NONCE, &self.nonce_e)?;
        writer.push(WPS_ATTR_PUBLIC_KEY, &self.public_key_e)?;
        writer.u16(WPS_ATTR_AUTH_TYPE_FLAGS, WPS_AUTH_WPAPSK | WPS_AUTH_WPA2PSK)?;
        writer.u16(WPS_ATTR_ENCRYPTION_TYPE_FLAGS, WPS_ENCR_AES | WPS_ENCR_TKIP)?;
        writer.u8(WPS_ATTR_CONNECTION_TYPE_FLAGS, WPS_CONN_ESS)?;
        writer.u16(
            WPS_ATTR_CONFIG_METHODS,
            WPS_CONFIG_KEYPAD | WPS_CONFIG_LABEL,
        )?;
        writer.u8(WPS_ATTR_STATE, WPS_STATE_NOT_CONFIGURED)?;
        writer.push(WPS_ATTR_MANUFACTURER, b"uu")?;
        writer.push(WPS_ATTR_MODEL_NAME, b"uu-linux-kernel-wlan")?;
        writer.push(WPS_ATTR_MODEL_NUMBER, b"1")?;
        writer.push(WPS_ATTR_DEVICE_NAME, b"uu-wlan")?;
        writer.push(
            WPS_ATTR_PRIMARY_DEVICE_TYPE,
            &[0x00, 0x01, 0x00, 0x50, 0xf2, 0x04, 0x00, 0x01],
        )?;
        writer.u8(WPS_ATTR_RF_BANDS, 0x03)?;
        writer.u16(WPS_ATTR_ASSOC_STATE, WPS_ASSOC_NOT_ASSOC)?;
        writer.u16(WPS_ATTR_DEVICE_PASSWORD_ID, WPS_DEVICE_PASSWORD_ID_PIN)?;
        writer.u16(WPS_ATTR_CONFIG_ERROR, WPS_CFG_NO_ERROR)?;
        writer.u32(WPS_ATTR_OS_VERSION, 0x8000_0000)?;

        let message = writer.finish();
        debug!(len = message.len(), "M1 built");
        self.last_message.clone_from(&message);
        self.state = State::WaitM2;
        Ok(message)
    }

    /// Обрабатывает `M2` и собирает `M3`.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку при неожиданном состоянии, неверном nonce или
    /// ошибке DH. `M2` не содержит `Authenticator`, поэтому он здесь не
    /// проверяется: `AuthKey` ещё не выведен.
    pub fn process_m2(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        self.expect_state(State::WaitM2)?;
        self.check_enrollee_nonce(message)?;

        let nonce_r = fixed::<NONCE_LEN>(message, WPS_ATTR_REGISTRAR_NONCE)?;
        let public_key_r = tlv_value(message, WPS_ATTR_PUBLIC_KEY)
            .ok_or_else(|| Error::Message("WPS M2 has no Public Key attribute".to_string()))?;
        if public_key_r.is_empty() {
            return Err(Error::Message("WPS M2 Public Key is empty".to_string()));
        }

        debug!(public_key_len = public_key_r.len(), "M2 parsed");
        self.nonce_r = nonce_r;
        self.public_key_r = public_key_r.to_vec();
        self.derive_keys()?;

        self.last_message.clone_from(&message.to_vec());
        let m3 = self.build_m3()?;
        self.last_message.clone_from(&m3);
        self.state = State::WaitM4;
        Ok(m3)
    }

    /// Обрабатывает `M4` и собирает `M5`.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку при неверном `Authenticator`, `R-Hash1` или
    /// повреждённых `Encrypted Settings`.
    pub fn process_m4(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        self.expect_state(State::WaitM4)?;
        self.check_enrollee_nonce(message)?;
        let authenticator = fixed::<HASH_LEN>(message, WPS_ATTR_AUTHENTICATOR)?;
        self.verify_authenticator(message, &authenticator)?;

        let r_hash1 = fixed::<HASH_LEN>(message, WPS_ATTR_R_HASH1)?;
        let r_hash2 = fixed::<HASH_LEN>(message, WPS_ATTR_R_HASH2)?;
        let encrypted = tlv_value(message, WPS_ATTR_ENCRYPTED_SETTINGS)
            .ok_or_else(|| Error::Message("WPS M4 has no Encrypted Settings".to_string()))?;
        let plain = self.decrypt_settings(encrypted)?;
        let r_snonce1 = tlv_value(&plain, WPS_ATTR_R_SNONCE1)
            .ok_or_else(|| Error::Message("WPS M4 has no R-SNonce1".to_string()))?;

        let expected = self.hash_with_psk(r_snonce1, &self.psk1);
        if !constant_time_eq(&expected, &r_hash1) {
            warn!("R-Hash1 mismatch: the PIN is probably wrong");
            return Err(Error::Message(
                "WPS R-Hash1 does not match the PIN".to_string(),
            ));
        }
        debug!("M4 authenticator and R-Hash1 verified");
        self.r_hash1 = r_hash1;
        self.r_hash2 = r_hash2;

        self.last_message.clone_from(&message.to_vec());
        let m5 = self.build_m5()?;
        self.last_message.clone_from(&m5);
        self.state = State::WaitM6;
        Ok(m5)
    }

    /// Обрабатывает `M6` и собирает `M7`.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку при неверном `Authenticator`, `R-Hash2` или
    /// повреждённых `Encrypted Settings`.
    pub fn process_m6(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        self.expect_state(State::WaitM6)?;
        self.check_enrollee_nonce(message)?;
        let authenticator = fixed::<HASH_LEN>(message, WPS_ATTR_AUTHENTICATOR)?;
        self.verify_authenticator(message, &authenticator)?;

        let encrypted = tlv_value(message, WPS_ATTR_ENCRYPTED_SETTINGS)
            .ok_or_else(|| Error::Message("WPS M6 has no Encrypted Settings".to_string()))?;
        let plain = self.decrypt_settings(encrypted)?;
        let r_snonce2 = tlv_value(&plain, WPS_ATTR_R_SNONCE2)
            .ok_or_else(|| Error::Message("WPS M6 has no R-SNonce2".to_string()))?;

        let expected = self.hash_with_psk(r_snonce2, &self.psk2);
        if !constant_time_eq(&expected, &self.r_hash2) {
            warn!("R-Hash2 mismatch: the PIN is probably wrong");
            return Err(Error::Message(
                "WPS R-Hash2 does not match the PIN".to_string(),
            ));
        }
        debug!("M6 authenticator and R-Hash2 verified");

        self.last_message.clone_from(&message.to_vec());
        let m7 = self.build_m7()?;
        self.last_message.clone_from(&m7);
        self.state = State::WaitM8;
        Ok(m7)
    }

    /// Обрабатывает `M8` и возвращает учётные данные сети.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку при неверном `Authenticator` или повреждённом
    /// `Credential`.
    pub fn process_m8(&mut self, message: &[u8]) -> Result<WpsCredentials> {
        self.expect_state(State::WaitM8)?;
        self.check_enrollee_nonce(message)?;
        let authenticator = fixed::<HASH_LEN>(message, WPS_ATTR_AUTHENTICATOR)?;
        self.verify_authenticator(message, &authenticator)?;

        let encrypted = tlv_value(message, WPS_ATTR_ENCRYPTED_SETTINGS)
            .ok_or_else(|| Error::Message("WPS M8 has no Encrypted Settings".to_string()))?;
        let plain = self.decrypt_settings(encrypted)?;
        let credential = tlv_value(&plain, WPS_ATTR_CREDENTIAL)
            .ok_or_else(|| Error::Message("WPS M8 has no Credential attribute".to_string()))?;

        let ssid = tlv_value(credential, WPS_ATTR_SSID)
            .ok_or_else(|| Error::Message("WPS Credential has no SSID".to_string()))?
            .to_vec();
        let auth_type = read_u16(credential, WPS_ATTR_AUTH_TYPE)?;
        let encryption_type = read_u16(credential, WPS_ATTR_ENCRYPTION_TYPE)?;
        let network_key = tlv_value(credential, WPS_ATTR_NETWORK_KEY)
            .ok_or_else(|| Error::Message("WPS Credential has no Network Key".to_string()))?
            .to_vec();
        let mac_addr = tlv_value(credential, WPS_ATTR_MAC_ADDR).and_then(MacAddr::from_bytes);

        debug!(
            ssid_len = ssid.len(),
            key_len = network_key.len(),
            auth_type,
            encryption_type,
            mac = ?mac_addr,
            "M8 credentials parsed"
        );
        self.state = State::Done;
        Ok(WpsCredentials {
            ssid,
            network_key,
            auth_type,
            encryption_type,
            mac_addr,
        })
    }

    /// Собирает `WSC_Done`, которым enrollee завершает обмен после `M8`.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::OutOfRange`] при переполнении TLV (невозможно для
    /// фиксированного набора атрибутов).
    pub fn wsc_done_message(&self) -> Result<Vec<u8>> {
        let mut writer = WpsTlvWriter::new();
        writer.u8(WPS_ATTR_VERSION, WPS_VERSION_1_0)?;
        writer.u8(WPS_ATTR_MESSAGE_TYPE, WPS_MSG_DONE)?;
        writer.push(WPS_ATTR_ENROLLEE_NONCE, &self.nonce_e)?;
        writer.push(WPS_ATTR_REGISTRAR_NONCE, &self.nonce_r)?;
        debug!("WSC_Done built");
        Ok(writer.finish())
    }

    fn expect_state(&self, expected: State) -> Result<()> {
        if self.state == expected {
            Ok(())
        } else {
            Err(Error::Message(format!(
                "unexpected WPS state: {:?}, expected {:?}",
                self.state, expected
            )))
        }
    }

    fn check_enrollee_nonce(&self, message: &[u8]) -> Result<()> {
        let nonce = tlv_value(message, WPS_ATTR_ENROLLEE_NONCE)
            .ok_or_else(|| Error::Message("WPS message has no Enrollee Nonce".to_string()))?;
        if nonce.len() != NONCE_LEN || !constant_time_eq(nonce, &self.nonce_e) {
            warn!("enrollee nonce mismatch");
            return Err(Error::Message("WPS Enrollee Nonce mismatch".to_string()));
        }
        trace!("enrollee nonce verified");
        Ok(())
    }

    fn verify_authenticator(&self, message: &[u8], authenticator: &[u8]) -> Result<()> {
        if authenticator.len() != HASH_LEN {
            return Err(Error::Malformed);
        }
        let (offset, _) = find_tlv_offset(message, WPS_ATTR_AUTHENTICATOR)
            .ok_or_else(|| Error::Message("WPS Authenticator is missing".to_string()))?;
        let prefix = message.get(..offset).ok_or(Error::Malformed)?;
        let expected = hmac_sha256(&self.authkey, &[&self.last_message, prefix]);
        if !constant_time_eq(&expected, authenticator) {
            warn!("Authenticator mismatch");
            return Err(Error::Message("WPS Authenticator mismatch".to_string()));
        }
        trace!("Authenticator verified");
        Ok(())
    }

    fn derive_keys(&mut self) -> Result<()> {
        let shared = shared_secret(&self.private_key, &self.public_key_r)?;
        let dhkey = sha256(&shared);
        let kdk = hmac_sha256(&dhkey, &[&self.nonce_e, &self.mac.octets(), &self.nonce_r]);
        let keys = kdf(&kdk);
        if let Some(slot) = keys.get(..AUTHKEY_LEN) {
            self.authkey.copy_from_slice(slot);
        }
        if let Some(slot) = keys.get(AUTHKEY_LEN..AUTHKEY_LEN + KEYWRAP_LEN) {
            self.keywrapkey.copy_from_slice(slot);
        }

        let half = PIN_LEN / 2;
        let Some(first) = self.pin.get(..half) else {
            return Err(Error::Malformed);
        };
        let Some(second) = self.pin.get(half..) else {
            return Err(Error::Malformed);
        };
        self.psk1 = hmac_sha256(&self.authkey, &[first]);
        self.psk2 = hmac_sha256(&self.authkey, &[second]);
        trace!("DH shared secret and WPS keys derived");
        Ok(())
    }

    fn hash_with_psk(&self, nonce: &[u8], psk: &[u8; PSK_LEN]) -> [u8; HASH_LEN] {
        hmac_sha256(
            &self.authkey,
            &[nonce, psk, &self.public_key_e, self.public_key_r.as_slice()],
        )
    }

    fn build_m3(&self) -> Result<Vec<u8>> {
        let e_hash1 = self.hash_with_psk(&self.e_s1, &self.psk1);
        let e_hash2 = self.hash_with_psk(&self.e_s2, &self.psk2);

        let mut writer = WpsTlvWriter::new();
        writer.u8(WPS_ATTR_VERSION, WPS_VERSION_1_0)?;
        writer.u8(WPS_ATTR_MESSAGE_TYPE, WPS_MSG_M3)?;
        writer.push(WPS_ATTR_REGISTRAR_NONCE, &self.nonce_r)?;
        writer.push(WPS_ATTR_E_HASH1, &e_hash1)?;
        writer.push(WPS_ATTR_E_HASH2, &e_hash2)?;
        self.push_authenticator(&mut writer)?;
        Ok(writer.finish())
    }

    fn build_m5(&self) -> Result<Vec<u8>> {
        let mut plain = WpsTlvWriter::new();
        plain.push(WPS_ATTR_E_SNONCE1, &self.e_s1)?;
        self.push_key_wrap_auth(&mut plain)?;
        let encrypted = self.encrypted_settings(plain.as_bytes())?;

        let mut writer = WpsTlvWriter::new();
        writer.u8(WPS_ATTR_VERSION, WPS_VERSION_1_0)?;
        writer.u8(WPS_ATTR_MESSAGE_TYPE, WPS_MSG_M5)?;
        writer.push(WPS_ATTR_REGISTRAR_NONCE, &self.nonce_r)?;
        writer.push(WPS_ATTR_ENCRYPTED_SETTINGS, &encrypted)?;
        self.push_authenticator(&mut writer)?;
        Ok(writer.finish())
    }

    fn build_m7(&self) -> Result<Vec<u8>> {
        let mut plain = WpsTlvWriter::new();
        plain.push(WPS_ATTR_E_SNONCE2, &self.e_s2)?;
        self.push_key_wrap_auth(&mut plain)?;
        let encrypted = self.encrypted_settings(plain.as_bytes())?;

        let mut writer = WpsTlvWriter::new();
        writer.u8(WPS_ATTR_VERSION, WPS_VERSION_1_0)?;
        writer.u8(WPS_ATTR_MESSAGE_TYPE, WPS_MSG_M7)?;
        writer.push(WPS_ATTR_REGISTRAR_NONCE, &self.nonce_r)?;
        writer.push(WPS_ATTR_ENCRYPTED_SETTINGS, &encrypted)?;
        self.push_authenticator(&mut writer)?;
        Ok(writer.finish())
    }

    fn push_authenticator(&self, writer: &mut WpsTlvWriter) -> Result<()> {
        let authenticator = hmac_sha256(&self.authkey, &[&self.last_message, writer.as_bytes()]);
        writer.push(WPS_ATTR_AUTHENTICATOR, &authenticator)
    }

    fn push_key_wrap_auth(&self, writer: &mut WpsTlvWriter) -> Result<()> {
        let hash = hmac_sha256(&self.authkey, &[writer.as_bytes()]);
        let kwa = hash.get(..KWA_LEN).ok_or(Error::Malformed)?;
        writer.push(WPS_ATTR_KEY_WRAP_AUTH, kwa)
    }

    fn encrypted_settings(&self, plain: &[u8]) -> Result<Vec<u8>> {
        let pad_len = BLOCK_LEN - plain.len() % BLOCK_LEN;
        let pad_byte = u8::try_from(pad_len).map_err(|_| Error::Malformed)?;
        let mut padded = Vec::with_capacity(plain.len() + pad_len);
        padded.extend_from_slice(plain);
        padded.extend(std::iter::repeat_n(pad_byte, pad_len));

        let mut iv = [0u8; BLOCK_LEN];
        fill_random(&mut iv)?;
        let ciphertext =
            aes128_cbc_encrypt(&self.keywrapkey, &iv, &padded).ok_or(Error::Malformed)?;

        let mut out = Vec::with_capacity(BLOCK_LEN + ciphertext.len());
        out.extend_from_slice(&iv);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn decrypt_settings(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 2 * BLOCK_LEN || !data.len().is_multiple_of(BLOCK_LEN) {
            return Err(Error::Message(
                "WPS Encrypted Settings has invalid length".to_string(),
            ));
        }
        let iv: [u8; BLOCK_LEN] = data
            .get(..BLOCK_LEN)
            .and_then(|raw| raw.try_into().ok())
            .ok_or(Error::Malformed)?;
        let ciphertext = data.get(BLOCK_LEN..).ok_or(Error::Malformed)?;
        let mut plain =
            aes128_cbc_decrypt(&self.keywrapkey, &iv, ciphertext).ok_or(Error::Malformed)?;

        let pad_byte = *plain.last().ok_or(Error::Malformed)?;
        let pad_len = usize::from(pad_byte);
        if pad_len == 0 || pad_len > plain.len() {
            return Err(Error::Message("invalid WPS PKCS#5 padding".to_string()));
        }
        let content_len = plain.len() - pad_len;
        let padding = plain.get(content_len..).ok_or(Error::Malformed)?;
        if padding.iter().any(|byte| *byte != pad_byte) {
            return Err(Error::Message("invalid WPS PKCS#5 padding".to_string()));
        }
        plain.truncate(content_len);

        let kwa_offset = plain
            .len()
            .checked_sub(4 + KWA_LEN)
            .ok_or(Error::Malformed)?;
        let (offset, kwa) = find_tlv_offset(&plain, WPS_ATTR_KEY_WRAP_AUTH)
            .ok_or_else(|| Error::Message("WPS KWA is missing".to_string()))?;
        if offset != kwa_offset || kwa.len() != KWA_LEN {
            return Err(Error::Message("WPS KWA is malformed".to_string()));
        }
        let expected = hmac_sha256(
            &self.authkey,
            &[plain.get(..offset).ok_or(Error::Malformed)?],
        );
        if !constant_time_eq(expected.get(..KWA_LEN).ok_or(Error::Malformed)?, kwa) {
            return Err(Error::Message(
                "WPS Key Wrap Authenticator mismatch".to_string(),
            ));
        }
        plain.truncate(offset);
        Ok(plain)
    }
}

/// Тип WPS-сообщения (`WPS_MSG_*`) из набора TLV.
#[must_use]
pub fn message_type(message: &[u8]) -> Option<u8> {
    tlv_value(message, WPS_ATTR_MESSAGE_TYPE).and_then(|value| value.first().copied())
}

fn kdf(key: &[u8; AUTHKEY_LEN]) -> [u8; KDF_LEN] {
    let mut out = [0u8; KDF_LEN];
    let bits = u32::try_from(KDF_LEN * 8).unwrap_or(u32::MAX);
    let mut counter = 1u32;
    let mut filled = 0usize;
    while filled < out.len() {
        let hash = hmac_sha256(
            key,
            &[&counter.to_be_bytes(), KDF_LABEL, &bits.to_be_bytes()],
        );
        let remaining = out.len() - filled;
        let take = remaining.min(HASH_LEN);
        if let (Some(slot), Some(source)) = (out.get_mut(filled..filled + take), hash.get(..take)) {
            slot.copy_from_slice(source);
        }
        filled += take;
        counter = counter.wrapping_add(1);
    }
    out
}

fn find_tlv_offset(data: &[u8], kind: u16) -> Option<(usize, &[u8])> {
    let mut position = 0usize;
    loop {
        let header = data.get(position..position.checked_add(4)?)?;
        let attr_type = u16::from_be_bytes(<[u8; 2]>::try_from(header.get(0..2)?).ok()?);
        let length = usize::from(u16::from_be_bytes(
            <[u8; 2]>::try_from(header.get(2..4)?).ok()?,
        ));
        let start = position.checked_add(4)?;
        let end = start.checked_add(length)?;
        let value = data.get(start..end)?;
        if attr_type == kind {
            return Some((position, value));
        }
        position = end;
    }
}

fn tlv_value(data: &[u8], kind: u16) -> Option<&[u8]> {
    find_tlv_offset(data, kind).map(|(_, value)| value)
}

fn fixed<const N: usize>(data: &[u8], kind: u16) -> Result<[u8; N]> {
    let value = tlv_value(data, kind).ok_or(Error::Malformed)?;
    <[u8; N]>::try_from(value).map_err(|_| Error::Malformed)
}

fn read_u16(data: &[u8], kind: u16) -> Result<u16> {
    fixed::<2>(data, kind).map(u16::from_be_bytes)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::{
        AUTHKEY_LEN, BLOCK_LEN, HASH_LEN, KEYWRAP_LEN, NONCE_LEN, WpsEnrollee, constant_time_eq,
        find_tlv_offset, fixed, kdf, message_type, tlv_value,
    };
    use crate::crypto::aes::{aes128_cbc_decrypt, aes128_cbc_encrypt};
    use crate::crypto::dh::{generate_private_key, public_key, shared_secret};
    use crate::crypto::hmac::hmac_sha256;
    use crate::crypto::sha256::sha256;
    use crate::raw::eapol::{
        WPS_ASSOC_NOT_ASSOC, WPS_ATTR_ASSOC_STATE, WPS_ATTR_AUTH_TYPE, WPS_ATTR_AUTH_TYPE_FLAGS,
        WPS_ATTR_AUTHENTICATOR, WPS_ATTR_CONFIG_ERROR, WPS_ATTR_CONFIG_METHODS,
        WPS_ATTR_CONNECTION_TYPE_FLAGS, WPS_ATTR_CREDENTIAL, WPS_ATTR_DEVICE_PASSWORD_ID,
        WPS_ATTR_E_SNONCE1, WPS_ATTR_E_SNONCE2, WPS_ATTR_ENCRYPTED_SETTINGS,
        WPS_ATTR_ENCRYPTION_TYPE, WPS_ATTR_ENCRYPTION_TYPE_FLAGS, WPS_ATTR_ENROLLEE_NONCE,
        WPS_ATTR_KEY_WRAP_AUTH, WPS_ATTR_MAC_ADDR, WPS_ATTR_MESSAGE_TYPE, WPS_ATTR_NETWORK_KEY,
        WPS_ATTR_OS_VERSION, WPS_ATTR_PUBLIC_KEY, WPS_ATTR_R_HASH1, WPS_ATTR_R_HASH2,
        WPS_ATTR_R_SNONCE1, WPS_ATTR_R_SNONCE2, WPS_ATTR_REGISTRAR_NONCE, WPS_ATTR_RF_BANDS,
        WPS_ATTR_SSID, WPS_ATTR_STATE, WPS_ATTR_UUID_R, WPS_ATTR_VERSION, WPS_AUTH_WPA2PSK,
        WPS_AUTH_WPAPSK, WPS_CFG_NO_ERROR, WPS_CONFIG_KEYPAD, WPS_CONN_ESS,
        WPS_DEVICE_PASSWORD_ID_PIN, WPS_ENCR_AES, WPS_ENCR_TKIP, WPS_MSG_DONE, WPS_MSG_M1,
        WPS_MSG_M2, WPS_MSG_M4, WPS_MSG_M6, WPS_MSG_M8, WPS_STATE_NOT_CONFIGURED, WPS_VERSION_1_0,
        WpsTlvWriter,
    };
    use crate::raw::mac::MacAddr;

    fn mac() -> MacAddr {
        MacAddr::new([0x02, 0x11, 0x22, 0x33, 0x44, 0x55])
    }

    fn append_authenticator(writer: &mut WpsTlvWriter, last: &[u8], authkey: &[u8; AUTHKEY_LEN]) {
        let digest = hmac_sha256(authkey, &[last, writer.as_bytes()]);
        writer.push(WPS_ATTR_AUTHENTICATOR, &digest).unwrap();
    }

    fn append_key_wrap_auth(writer: &mut WpsTlvWriter, authkey: &[u8; AUTHKEY_LEN]) {
        let digest = hmac_sha256(authkey, &[writer.as_bytes()]);
        let kwa = digest.get(..8).unwrap();
        writer.push(WPS_ATTR_KEY_WRAP_AUTH, kwa).unwrap();
    }

    fn seal(keywrap: &[u8; KEYWRAP_LEN], plain: &[u8], iv: &[u8; BLOCK_LEN]) -> Vec<u8> {
        let pad_len = BLOCK_LEN - plain.len() % BLOCK_LEN;
        let pad = u8::try_from(pad_len).unwrap();
        let mut padded = plain.to_vec();
        padded.extend(std::iter::repeat_n(pad, pad_len));
        let cipher = aes128_cbc_encrypt(keywrap, iv, &padded).unwrap();
        let mut out = iv.to_vec();
        out.extend_from_slice(&cipher);
        out
    }

    fn open(keywrap: &[u8; KEYWRAP_LEN], authkey: &[u8; AUTHKEY_LEN], data: &[u8]) -> Vec<u8> {
        let iv: [u8; BLOCK_LEN] = data.get(..BLOCK_LEN).unwrap().try_into().unwrap();
        let mut plain = aes128_cbc_decrypt(keywrap, &iv, data.get(BLOCK_LEN..).unwrap()).unwrap();
        let pad = usize::from(*plain.last().unwrap());
        plain.truncate(plain.len() - pad);
        let (offset, kwa) = find_tlv_offset(&plain, WPS_ATTR_KEY_WRAP_AUTH).unwrap();
        let digest = hmac_sha256(authkey, &[plain.get(..offset).unwrap()]);
        assert_eq!(kwa, digest.get(..8).unwrap());
        plain.truncate(offset);
        plain
    }

    /// Минимальный регистратор для проверки state machine без сети.
    struct Registrar {
        enrollee_mac: MacAddr,
        nonce_e: [u8; NONCE_LEN],
        nonce_r: [u8; NONCE_LEN],
        public_key_e: Vec<u8>,
        public_key_r: [u8; 192],
        authkey: [u8; AUTHKEY_LEN],
        keywrap: [u8; KEYWRAP_LEN],
        psk1: [u8; HASH_LEN],
        psk2: [u8; HASH_LEN],
        r_snonce1: [u8; NONCE_LEN],
        r_snonce2: [u8; NONCE_LEN],
        last: Vec<u8>,
    }

    impl Registrar {
        fn new(m1: &[u8], pin: &str, enrollee_mac: MacAddr) -> Self {
            let nonce_e = fixed::<NONCE_LEN>(m1, WPS_ATTR_ENROLLEE_NONCE).unwrap();
            let public_key_e = tlv_value(m1, WPS_ATTR_PUBLIC_KEY).unwrap();
            let private = generate_private_key().unwrap();
            let public_key_r = public_key(&private);
            let shared = shared_secret(&private, public_key_e).unwrap();
            let dhkey = sha256(&shared);
            let nonce_r = [0x5au8; NONCE_LEN];
            let kdk = hmac_sha256(&dhkey, &[&nonce_e, &enrollee_mac.octets(), &nonce_r]);
            let keys = kdf(&kdk);
            let authkey: [u8; AUTHKEY_LEN] = keys.get(..AUTHKEY_LEN).unwrap().try_into().unwrap();
            let keywrap: [u8; KEYWRAP_LEN] = keys
                .get(AUTHKEY_LEN..AUTHKEY_LEN + KEYWRAP_LEN)
                .unwrap()
                .try_into()
                .unwrap();
            let pin_bytes = pin.as_bytes();
            let psk1 = hmac_sha256(&authkey, &[pin_bytes.get(..4).unwrap()]);
            let psk2 = hmac_sha256(&authkey, &[pin_bytes.get(4..).unwrap()]);
            Self {
                enrollee_mac,
                nonce_e,
                nonce_r,
                public_key_e: public_key_e.to_vec(),
                public_key_r,
                authkey,
                keywrap,
                psk1,
                psk2,
                r_snonce1: [0x11; NONCE_LEN],
                r_snonce2: [0x22; NONCE_LEN],
                last: Vec::new(),
            }
        }

        fn build_m2(&mut self) -> Vec<u8> {
            let mut writer = WpsTlvWriter::new();
            writer.u8(WPS_ATTR_VERSION, WPS_VERSION_1_0).unwrap();
            writer.u8(WPS_ATTR_MESSAGE_TYPE, WPS_MSG_M2).unwrap();
            writer.push(WPS_ATTR_ENROLLEE_NONCE, &self.nonce_e).unwrap();
            writer
                .push(WPS_ATTR_REGISTRAR_NONCE, &self.nonce_r)
                .unwrap();
            writer.push(WPS_ATTR_UUID_R, &[0x44; NONCE_LEN]).unwrap();
            writer
                .push(WPS_ATTR_PUBLIC_KEY, &self.public_key_r)
                .unwrap();
            writer
                .u16(WPS_ATTR_AUTH_TYPE_FLAGS, WPS_AUTH_WPAPSK | WPS_AUTH_WPA2PSK)
                .unwrap();
            writer
                .u16(WPS_ATTR_ENCRYPTION_TYPE_FLAGS, WPS_ENCR_AES | WPS_ENCR_TKIP)
                .unwrap();
            writer
                .u8(WPS_ATTR_CONNECTION_TYPE_FLAGS, WPS_CONN_ESS)
                .unwrap();
            writer
                .u16(WPS_ATTR_CONFIG_METHODS, WPS_CONFIG_KEYPAD)
                .unwrap();
            writer.u8(WPS_ATTR_STATE, WPS_STATE_NOT_CONFIGURED).unwrap();
            writer
                .u16(WPS_ATTR_ASSOC_STATE, WPS_ASSOC_NOT_ASSOC)
                .unwrap();
            writer.u16(WPS_ATTR_CONFIG_ERROR, WPS_CFG_NO_ERROR).unwrap();
            writer
                .u16(WPS_ATTR_DEVICE_PASSWORD_ID, WPS_DEVICE_PASSWORD_ID_PIN)
                .unwrap();
            writer.u32(WPS_ATTR_OS_VERSION, 0x8000_0000).unwrap();
            writer.u8(WPS_ATTR_RF_BANDS, 0x03).unwrap();
            let message = writer.finish();
            self.last.clone_from(&message);
            message
        }

        fn receive(&mut self, message: &[u8]) {
            let (offset, authenticator) = find_tlv_offset(message, WPS_ATTR_AUTHENTICATOR).unwrap();
            let prefix = message.get(..offset).unwrap();
            let expected = hmac_sha256(&self.authkey, &[&self.last, prefix]);
            assert_eq!(authenticator, expected.as_slice());
            self.last = message.to_vec();
        }

        fn build_m4(&mut self) -> Vec<u8> {
            let r_hash1 = hmac_sha256(
                &self.authkey,
                &[
                    &self.r_snonce1,
                    &self.psk1,
                    &self.public_key_e,
                    &self.public_key_r,
                ],
            );
            let r_hash2 = hmac_sha256(
                &self.authkey,
                &[
                    &self.r_snonce2,
                    &self.psk2,
                    &self.public_key_e,
                    &self.public_key_r,
                ],
            );

            let mut plain = WpsTlvWriter::new();
            plain.push(WPS_ATTR_R_SNONCE1, &self.r_snonce1).unwrap();
            append_key_wrap_auth(&mut plain, &self.authkey);

            let mut writer = WpsTlvWriter::new();
            writer.u8(WPS_ATTR_VERSION, WPS_VERSION_1_0).unwrap();
            writer.u8(WPS_ATTR_MESSAGE_TYPE, WPS_MSG_M4).unwrap();
            writer.push(WPS_ATTR_ENROLLEE_NONCE, &self.nonce_e).unwrap();
            writer.push(WPS_ATTR_R_HASH1, &r_hash1).unwrap();
            writer.push(WPS_ATTR_R_HASH2, &r_hash2).unwrap();
            let encrypted = seal(&self.keywrap, &plain.finish(), &[0x33; BLOCK_LEN]);
            writer
                .push(WPS_ATTR_ENCRYPTED_SETTINGS, &encrypted)
                .unwrap();
            append_authenticator(&mut writer, &self.last, &self.authkey);
            let message = writer.finish();
            self.last.clone_from(&message);
            message
        }

        fn receive_m5(&self, message: &[u8]) {
            let encrypted = tlv_value(message, WPS_ATTR_ENCRYPTED_SETTINGS).unwrap();
            let plain = open(&self.keywrap, &self.authkey, encrypted);
            assert!(tlv_value(&plain, WPS_ATTR_E_SNONCE1).is_some());
        }

        fn build_m6(&mut self) -> Vec<u8> {
            let mut plain = WpsTlvWriter::new();
            plain.push(WPS_ATTR_R_SNONCE2, &self.r_snonce2).unwrap();
            append_key_wrap_auth(&mut plain, &self.authkey);

            let mut writer = WpsTlvWriter::new();
            writer.u8(WPS_ATTR_VERSION, WPS_VERSION_1_0).unwrap();
            writer.u8(WPS_ATTR_MESSAGE_TYPE, WPS_MSG_M6).unwrap();
            writer.push(WPS_ATTR_ENROLLEE_NONCE, &self.nonce_e).unwrap();
            let encrypted = seal(&self.keywrap, &plain.finish(), &[0x44; BLOCK_LEN]);
            writer
                .push(WPS_ATTR_ENCRYPTED_SETTINGS, &encrypted)
                .unwrap();
            append_authenticator(&mut writer, &self.last, &self.authkey);
            let message = writer.finish();
            self.last.clone_from(&message);
            message
        }

        fn receive_m7(&self, message: &[u8]) {
            let encrypted = tlv_value(message, WPS_ATTR_ENCRYPTED_SETTINGS).unwrap();
            let plain = open(&self.keywrap, &self.authkey, encrypted);
            assert!(tlv_value(&plain, WPS_ATTR_E_SNONCE2).is_some());
        }

        fn build_m8(&mut self, ssid: &[u8], network_key: &[u8]) -> Vec<u8> {
            let mut credential = WpsTlvWriter::new();
            credential.push(WPS_ATTR_SSID, ssid).unwrap();
            credential
                .u16(WPS_ATTR_AUTH_TYPE, WPS_AUTH_WPA2PSK)
                .unwrap();
            credential
                .u16(WPS_ATTR_ENCRYPTION_TYPE, WPS_ENCR_AES)
                .unwrap();
            credential.push(WPS_ATTR_NETWORK_KEY, network_key).unwrap();
            credential
                .push(WPS_ATTR_MAC_ADDR, &self.enrollee_mac.octets())
                .unwrap();

            let mut plain = WpsTlvWriter::new();
            plain
                .push(WPS_ATTR_CREDENTIAL, &credential.finish())
                .unwrap();
            append_key_wrap_auth(&mut plain, &self.authkey);

            let mut writer = WpsTlvWriter::new();
            writer.u8(WPS_ATTR_VERSION, WPS_VERSION_1_0).unwrap();
            writer.u8(WPS_ATTR_MESSAGE_TYPE, WPS_MSG_M8).unwrap();
            writer.push(WPS_ATTR_ENROLLEE_NONCE, &self.nonce_e).unwrap();
            let encrypted = seal(&self.keywrap, &plain.finish(), &[0x55; BLOCK_LEN]);
            writer
                .push(WPS_ATTR_ENCRYPTED_SETTINGS, &encrypted)
                .unwrap();
            append_authenticator(&mut writer, &self.last, &self.authkey);
            let message = writer.finish();
            self.last.clone_from(&message);
            message
        }
    }

    #[test]
    fn completes_full_pin_handshake() {
        let mut enrollee = WpsEnrollee::new(mac(), "48293563").unwrap();
        let m1 = enrollee.m1().unwrap();
        let mut registrar = Registrar::new(&m1, "48293563", mac());

        let m2 = registrar.build_m2();
        let m3 = enrollee.process_m2(&m2).unwrap();
        registrar.receive(&m3);

        let m4 = registrar.build_m4();
        let m5 = enrollee.process_m4(&m4).unwrap();
        registrar.receive(&m5);
        registrar.receive_m5(&m5);

        let m6 = registrar.build_m6();
        let m7 = enrollee.process_m6(&m6).unwrap();
        registrar.receive(&m7);
        registrar.receive_m7(&m7);

        let m8 = registrar.build_m8(b"LP", b"secret-password-123");
        let credentials = enrollee.process_m8(&m8).unwrap();
        assert_eq!(credentials.ssid, b"LP");
        assert_eq!(credentials.network_key, b"secret-password-123");
        assert_eq!(credentials.auth_type, WPS_AUTH_WPA2PSK);
        assert_eq!(credentials.encryption_type, WPS_ENCR_AES);
        assert!(enrollee.is_done());

        let done = enrollee.wsc_done_message().unwrap();
        assert_eq!(message_type(&done), Some(WPS_MSG_DONE));
    }

    #[test]
    fn builds_m1_with_required_attributes() {
        let mut enrollee = WpsEnrollee::new(mac(), "48293563").unwrap();
        let m1 = enrollee.m1().unwrap();
        assert_eq!(message_type(&m1), Some(WPS_MSG_M1));
        assert_eq!(
            find_tlv_offset(&m1, WPS_ATTR_VERSION).map(|(_, value)| value),
            Some(&[0x10][..])
        );
        assert_eq!(
            find_tlv_offset(&m1, WPS_ATTR_PUBLIC_KEY).map(|(_, value)| value.len()),
            Some(192)
        );
    }

    #[test]
    fn reads_config_error_from_nack() {
        let mut writer = WpsTlvWriter::new();
        writer.u16(WPS_ATTR_CONFIG_ERROR, 0x000d).unwrap();
        let message = writer.finish();
        assert_eq!(super::config_error(&message), Some(0x000d));
    }

    #[test]
    fn rejects_invalid_pin() {
        assert!(WpsEnrollee::new(mac(), "1234").is_err());
        assert!(WpsEnrollee::new(mac(), "1234567a").is_err());
    }

    #[test]
    fn kdf_matches_reference() {
        let key = [0x0bu8; 32];
        let keys = kdf(&key);
        assert_eq!(
            keys.get(..16),
            Some(
                &[
                    0x2b, 0xc4, 0x83, 0x7b, 0x1a, 0x80, 0x62, 0x5b, 0x66, 0x60, 0x03, 0x4b, 0x25,
                    0x73, 0xb7, 0x2f,
                ][..]
            )
        );
    }

    #[test]
    fn compares_in_constant_time() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn writes_and_finds_tlv() {
        let mut writer = WpsTlvWriter::new();
        writer.u8(WPS_ATTR_MESSAGE_TYPE, WPS_MSG_M1).unwrap();
        let data = writer.finish();
        assert_eq!(
            find_tlv_offset(&data, WPS_ATTR_MESSAGE_TYPE),
            Some((0, &[WPS_MSG_M1][..]))
        );
    }
}
