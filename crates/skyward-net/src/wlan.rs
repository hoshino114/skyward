//! The WLAN as the pages show it, and how it moves on with what the
//! supplicant tells and the address the network gives.

use crate::dhcp::Lease;
use crate::reach::Reach;
use crate::supplicant::{Bss, Event, Security};
use std::net::Ipv4Addr;

/// The WLAN, as the pages show it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Wlan {
    pub power: Power,
    /// The networks in range, strongest first, each once however many
    /// access points it has; one that does not say its name is left out.
    pub networks: Vec<Network>,
    /// The network chosen, and how joining it goes.
    pub joined: Option<Joined>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Power {
    #[default]
    Off,
    /// The driver and the supplicant are being brought up.
    Starting,
    On,
    /// It did not come up, or the supplicant went away: why.
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    pub ssid: Vec<u8>,
    /// Its name to show: as UTF-8, with what is not put right.
    pub name: String,
    /// The strongest of its access points, in dBm, and that one's channel.
    pub signal: i32,
    pub frequency: u32,
    /// The bands its access points are on.
    pub bands: Bands,
    pub security: Security,
}

/// The bands a network's access points are on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Bands {
    pub ghz2: bool,
    pub ghz5: bool,
    pub ghz6: bool,
}

impl Bands {
    /// The band of a channel of `mhz`.
    pub fn of(mhz: u32) -> Bands {
        Bands { ghz2: (2400..2500).contains(&mhz), ghz5: (4900..5925).contains(&mhz), ghz6: (5925..7125).contains(&mhz) }
    }

    fn join(self, other: Bands) -> Bands {
        Bands { ghz2: self.ghz2 || other.ghz2, ghz5: self.ghz5 || other.ghz5, ghz6: self.ghz6 || other.ghz6 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Joined {
    pub ssid: Vec<u8>,
    pub name: String,
    pub security: Security,
    pub stage: Stage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage {
    /// Reaching the access point and agreeing keys with it.
    Joining,
    /// Joined, and asking for an address.
    Addressing,
    Connected(Link),
    /// The access point refused the password.
    WrongPassword,
    /// The network is not in range; the supplicant keeps looking for it.
    NotFound,
    /// Joining failed; the supplicant tries again after a while.
    Failed,
    /// Joined, and no address was given: why.
    NoAddress(String),
}

/// A network joined, and what it gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub address: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub router: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    /// In dBm, and the channel's frequency in MHz.
    pub signal: i32,
    pub frequency: u32,
    /// How fast the link is, in Mbit/s, where the driver says.
    pub speed: Option<u32>,
    /// Which generation of Wi-Fi the link is, where the supplicant says.
    pub generation: Option<u8>,
    /// The phone's own hardware address.
    pub mac: String,
    /// How far the network reaches, once looked at.
    pub reach: Option<Reach>,
}

impl Link {
    pub fn new(lease: &Lease, mac: [u8; 6]) -> Link {
        Link {
            address: lease.address,
            mask: lease.mask,
            router: lease.router,
            dns: lease.dns.clone(),
            signal: 0,
            frequency: 0,
            speed: None,
            generation: None,
            mac: mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"),
            reach: None,
        }
    }
}

/// How fast data went over the network joined in the last second, in and
/// out, in bytes a second.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Traffic {
    pub rx: u64,
    pub tx: u64,
}

/// The networks the access points found make, strongest first.
pub fn networks(found: &[Bss]) -> Vec<Network> {
    let mut out: Vec<Network> = Vec::new();
    for bss in found.iter().filter(|b| !b.ssid.is_empty() && b.ssid.iter().any(|&c| c != 0)) {
        match out.iter_mut().find(|n| n.ssid == bss.ssid) {
            Some(n) => {
                n.bands = n.bands.join(Bands::of(bss.frequency));
                if bss.signal > n.signal {
                    n.signal = bss.signal;
                    n.frequency = bss.frequency;
                }
            }
            None => out.push(Network {
                ssid: bss.ssid.clone(),
                name: String::from_utf8_lossy(&bss.ssid).into_owned(),
                signal: bss.signal,
                frequency: bss.frequency,
                bands: Bands::of(bss.frequency),
                security: bss.security,
            }),
        }
    }
    out.sort_by(|a, b| b.signal.cmp(&a.signal).then_with(|| a.name.cmp(&b.name)));
    out
}

/// What joining has to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// Nothing beyond showing the stage.
    Show,
    /// Ask for an address.
    Address,
    /// Give back the address and stop keeping it: the network was left.
    Unaddress,
    /// Stop trying the network: its password is wrong.
    Forget,
}

impl Joined {
    /// Move on with an event from the supplicant.
    pub fn on(&mut self, event: &Event) -> Next {
        match event {
            // Said again of a network joined, as the supplicant does on
            // moving to another of its access points, it changes nothing:
            // the address asked for or had still holds.
            Event::Connected if matches!(self.stage, Stage::Addressing | Stage::Connected(_) | Stage::NoAddress(_)) => Next::Show,
            Event::Connected => {
                self.stage = Stage::Addressing;
                Next::Address
            }
            Event::Disconnected => {
                let had = matches!(self.stage, Stage::Addressing | Stage::Connected(_) | Stage::NoAddress(_));
                // A refused password goes on showing after the leaving it
                // brings.
                if self.stage != Stage::WrongPassword {
                    self.stage = Stage::Joining;
                }
                if had {
                    Next::Unaddress
                } else {
                    Next::Show
                }
            }
            Event::TemporarilyDisabled { reason } if reason == "WRONG_KEY" => {
                self.stage = Stage::WrongPassword;
                Next::Forget
            }
            Event::TemporarilyDisabled { .. } | Event::Rejected if !matches!(self.stage, Stage::Connected(_)) => {
                self.stage = Stage::Failed;
                Next::Show
            }
            Event::NotFound if self.stage == Stage::Joining || self.stage == Stage::Failed => {
                self.stage = Stage::NotFound;
                Next::Show
            }
            _ => Next::Show,
        }
    }
}

/// The networks an installed Android system keeps in `text`, as its
/// `WifiConfigStore.xml` writes them: each with the password it is joined
/// with, where it keeps one the recovery can join with.
///
/// A name the system writes in hex rather than quoted is left out, as is a
/// network whose password is kept as a 64-digit key rather than as the
/// password itself, and one that is joined with a login of its own.
pub fn system_saved(text: &str) -> Vec<Saved> {
    let Ok(doc) = roxmltree::Document::parse(text) else { return Vec::new() };
    let mut out = Vec::new();
    for network in doc.descendants().filter(|n| n.has_tag_name("Network")) {
        let Some(config) = network.descendants().find(|n| n.has_tag_name("WifiConfiguration")) else { continue };
        let field = |name: &str| -> String {
            config
                .descendants()
                .find(|n| n.has_tag_name("string") && n.attribute("name") == Some(name))
                .and_then(|n| n.text())
                .map(unquoted)
                .unwrap_or_default()
        };
        let number = |name: &str| -> Option<i64> {
            config
                .descendants()
                .find(|n| n.has_tag_name("int") && n.attribute("name") == Some(name))
                .and_then(|n| n.attribute("value"))
                .and_then(|v| v.parse().ok())
        };
        let flag = |name: &str| -> bool {
            config
                .descendants()
                .find(|n| n.has_tag_name("boolean") && n.attribute("name") == Some(name))
                .and_then(|n| n.attribute("value"))
                .is_some_and(|v| v == "true")
        };
        let Some(ssid) = config
            .descendants()
            .find(|n| n.has_tag_name("string") && n.attribute("name") == Some("SSID"))
            .and_then(|n| n.text())
            .and_then(quoted)
        else {
            continue;
        };
        let password = field("PreSharedKey");
        let security = match number("SecurityType") {
            Some(0) => Security::Open,
            Some(5) => Security::Owe,
            Some(2) => Security::Psk,
            Some(4) => Security::Sae,
            _ => continue,
        };
        let joinable = match security {
            Security::Open | Security::Owe => password.is_empty(),
            Security::Psk => (8..=63).contains(&password.len()) && password.bytes().all(|b| (32..=126).contains(&b)),
            Security::Sae => !password.is_empty(),
            _ => false,
        };
        if !joinable {
            continue;
        }
        let name = String::from_utf8(ssid.clone()).unwrap_or_default();
        out.push(Saved { ssid, name, security, password, hidden: flag("HiddenSSID") });
    }
    out
}

/// What the system wrote between the quotes it puts around a name or a
/// password, where it wrote it quoted.
fn quoted(text: &str) -> Option<Vec<u8>> {
    let inner = text.strip_prefix('"')?.strip_suffix('"')?;
    Some(inner.as_bytes().to_vec())
}

/// The text the system quoted, or as it stands where it quoted none.
fn unquoted(text: &str) -> String {
    text.strip_prefix('"').and_then(|t| t.strip_suffix('"')).unwrap_or(text).to_string()
}

/// A network joined, as it is written down to be joined again without
/// asking for its password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Saved {
    pub ssid: Vec<u8>,
    pub name: String,
    pub security: Security,
    pub password: String,
    pub hidden: bool,
}

impl Saved {
    /// The line that keeps it: the name's bytes and the password's as hex,
    /// which takes any of them, then how the network is protected and
    /// whether it hides its name.
    pub fn line(&self) -> String {
        format!("{}\t{}\t{}\t{}\n", hex::encode(&self.ssid), security_name(self.security), hex::encode(&self.password), u8::from(self.hidden))
    }

    /// Read back what [`line`](Saved::line) wrote, where it is all there.
    pub fn of(line: &str) -> Option<Saved> {
        let mut parts = line.trim_end().split('\t');
        let ssid = hex::decode(parts.next()?).ok()?;
        let security = security_named(parts.next()?)?;
        let password = String::from_utf8(hex::decode(parts.next()?).ok()?).ok()?;
        let hidden = matches!(parts.next(), Some("1"));
        let name = String::from_utf8(ssid.clone()).unwrap_or_default();
        Some(Saved { ssid, name, security, password, hidden })
    }
}

/// How a network is protected, as a kept network writes it.
pub fn security_name(security: Security) -> &'static str {
    match security {
        Security::Open => "open",
        Security::Owe => "owe",
        Security::Psk => "psk",
        Security::Sae => "sae",
        Security::PskSae => "psk-sae",
        Security::Wep => "wep",
        Security::Enterprise => "enterprise",
    }
}

/// What [`security_name`] wrote, read back.
pub fn security_named(name: &str) -> Option<Security> {
    Some(match name {
        "open" => Security::Open,
        "owe" => Security::Owe,
        "psk" => Security::Psk,
        "sae" => Security::Sae,
        "psk-sae" => Security::PskSae,
        "wep" => Security::Wep,
        "enterprise" => Security::Enterprise,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bss(id: u32, ssid: &[u8], signal: i32, frequency: u32) -> Bss {
        Bss { id, bssid: format!("00:00:00:00:00:{id:02x}"), frequency, signal, security: Security::Psk, ssid: ssid.to_vec() }
    }

    #[test]
    fn a_network_shows_once_with_its_strongest_access_point() {
        let found = [
            bss(1, b"Skyward", -62, 2462),
            bss(2, b"Skyward", -34, 5805),
            bss(3, b"", -30, 2462),
            bss(4, b"\0\0\0", -30, 2462),
            bss(5, "Skyward客厅".as_bytes(), -50, 5180),
            bss(6, b"\xff\xfe", -90, 2412),
        ];
        let n = networks(&found);
        let names: Vec<&str> = n.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["Skyward", "Skyward客厅", "\u{fffd}\u{fffd}"], "the strongest first, nameless ones left out");
        assert_eq!((n[0].signal, n[0].frequency), (-34, 5805));
        assert_eq!(n[0].bands, Bands { ghz2: true, ghz5: true, ghz6: false }, "both its access points' bands");
        assert_eq!(n[1].bands, Bands { ghz2: false, ghz5: true, ghz6: false });
        assert_eq!(Bands::of(5955), Bands { ghz2: false, ghz5: false, ghz6: true });
        assert_eq!(n[2].ssid, b"\xff\xfe", "a name that is not UTF-8 is joined as it is");
    }

    fn joining() -> Joined {
        Joined { ssid: b"Skyward".to_vec(), name: "Skyward".into(), security: Security::Psk, stage: Stage::Joining }
    }

    #[test]
    fn joining_moves_on_with_what_the_supplicant_tells() {
        let mut j = joining();
        assert_eq!(j.on(&Event::Connected), Next::Address);
        assert_eq!(j.stage, Stage::Addressing);
        assert_eq!(j.on(&Event::Connected), Next::Show, "said again, the address is asked for once");
        j.stage = Stage::NoAddress("no DHCP server offered an address".into());
        assert_eq!(j.on(&Event::Connected), Next::Show, "an address not given is asked for again in time");
        j.stage = Stage::Addressing;
        assert_eq!(j.on(&Event::ScanResults), Next::Show);
        assert_eq!(j.on(&Event::Disconnected), Next::Unaddress, "an address asked for or had goes with the network");
        assert_eq!(j.stage, Stage::Joining, "the supplicant joins it again by itself");
        assert_eq!(j.on(&Event::Disconnected), Next::Show, "no address to give back");
        assert_eq!(j.on(&Event::NotFound), Next::Show);
        assert_eq!(j.stage, Stage::NotFound);
        assert_eq!(j.on(&Event::Connected), Next::Address);
        let lease = Lease {
            address: Ipv4Addr::new(192, 168, 0, 102),
            mask: Ipv4Addr::new(255, 255, 255, 0),
            router: Some(Ipv4Addr::new(192, 168, 0, 1)),
            dns: Vec::new(),
            server: Ipv4Addr::new(192, 168, 0, 1),
            seconds: 86400,
            renew: 43200,
            rebind: 75600,
        };
        j.stage = Stage::Connected(Link::new(&lease, [0; 6]));
        assert_eq!(j.on(&Event::Connected), Next::Show, "moved to another access point, the address is kept");
        assert!(matches!(j.stage, Stage::Connected(_)));
    }

    #[test]
    fn a_refused_password_stops_the_trying() {
        let mut j = joining();
        assert_eq!(j.on(&Event::TemporarilyDisabled { reason: "WRONG_KEY".into() }), Next::Forget);
        assert_eq!(j.stage, Stage::WrongPassword);
        assert_eq!(j.on(&Event::Disconnected), Next::Show);
        assert_eq!(j.stage, Stage::WrongPassword, "what was wrong stays said");
        let mut j = joining();
        assert_eq!(j.on(&Event::TemporarilyDisabled { reason: "CONN_FAILED".into() }), Next::Show);
        assert_eq!(j.stage, Stage::Failed);
    }

    #[test]
    fn a_link_names_the_phones_own_address() {
        let lease = Lease {
            address: Ipv4Addr::new(192, 168, 1, 23),
            mask: Ipv4Addr::new(255, 255, 255, 0),
            router: Some(Ipv4Addr::new(192, 168, 1, 1)),
            dns: vec![Ipv4Addr::new(192, 168, 1, 1)],
            server: Ipv4Addr::new(192, 168, 1, 1),
            seconds: 86400,
            renew: 43200,
            rebind: 75600,
        };
        let link = Link::new(&lease, [0x02, 0x00, 0x00, 0x00, 0x00, 0x04]);
        assert_eq!(link.mac, "02:00:00:00:00:04");
        assert_eq!(link.router, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }
    #[test]
    fn a_network_kept_reads_back_as_it_was_written() {
        let s = Saved {
            ssid: "Skyward 客厅".as_bytes().to_vec(),
            name: "Skyward 客厅".into(),
            security: Security::PskSae,
            password: "pass\"word 密码".into(),
            hidden: true,
        };
        assert_eq!(Saved::of(&s.line()), Some(s), "any byte of a name or a password");
    }

    #[test]
    fn a_line_that_is_not_all_there_is_no_network() {
        for line in ["", "abc", "7573\tpsk", "zz\tpsk\t74657374", "7573\tnone\t74657374", "7573\tpsk\tzz"] {
            assert_eq!(Saved::of(line), None, "{line:?}");
        }
    }

    #[test]
    fn the_networks_a_system_keeps_are_read_with_their_passwords() {
        let text = r#"<WifiConfigStoreData>
            <NetworkList>
                <Network>
                    <WifiConfiguration>
                        <string name="SSID">&quot;Skyward 客厅&quot;</string>
                        <string name="PreSharedKey">&quot;pass word&quot;</string>
                        <boolean name="HiddenSSID" value="false" />
                        <SecurityParamsList><SecurityParams><int name="SecurityType" value="2" /></SecurityParams></SecurityParamsList>
                    </WifiConfiguration>
                </Network>
                <Network>
                    <WifiConfiguration>
                        <string name="SSID">&quot;Open one&quot;</string>
                        <null name="PreSharedKey" />
                        <SecurityParamsList><SecurityParams><int name="SecurityType" value="0" /></SecurityParams></SecurityParamsList>
                    </WifiConfiguration>
                </Network>
                <Network>
                    <WifiConfiguration>
                        <string name="SSID">&quot;Kept as a key&quot;</string>
                        <string name="PreSharedKey">&quot;00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff&quot;</string>
                        <SecurityParamsList><SecurityParams><int name="SecurityType" value="2" /></SecurityParams></SecurityParamsList>
                    </WifiConfiguration>
                </Network>
                <Network>
                    <WifiConfiguration>
                        <string name="SSID">0x00ab</string>
                        <string name="PreSharedKey">&quot;a password&quot;</string>
                        <SecurityParamsList><SecurityParams><int name="SecurityType" value="2" /></SecurityParams></SecurityParamsList>
                    </WifiConfiguration>
                </Network>
                <Network>
                    <WifiConfiguration>
                        <string name="SSID">&quot;A login of its own&quot;</string>
                        <SecurityParamsList><SecurityParams><int name="SecurityType" value="3" /></SecurityParams></SecurityParamsList>
                    </WifiConfiguration>
                </Network>
            </NetworkList>
        </WifiConfigStoreData>"#;
        let kept = system_saved(text);
        assert_eq!(kept.len(), 2, "the two that can be joined with what the system keeps");
        assert_eq!(kept[0].name, "Skyward 客厅");
        assert_eq!((kept[0].security, kept[0].password.as_str()), (Security::Psk, "pass word"));
        assert_eq!((kept[1].name.as_str(), kept[1].security), ("Open one", Security::Open), "one that needs no password");
        assert!(system_saved("not a document").is_empty(), "a file that is not the store has none");
    }

}
