use maxminddb::{Reader, path};
use std::net::Ipv4Addr;

pub type CountryDb = Reader<Vec<u8>>;

pub fn country_code(db: &CountryDb, ip: Ipv4Addr) -> Option<String> {
    let entry = db.lookup(ip.into()).ok()?;
    let code: &str = entry.decode_path(&path!["country", "iso_code"]).ok()??;
    (code.len() == 2 && code.bytes().all(|byte| byte.is_ascii_uppercase())).then(|| code.to_owned())
}
