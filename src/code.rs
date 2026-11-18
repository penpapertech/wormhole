//! Wormhole codes: `<nameplate>-<word>-<word>`.
//!
//! The *nameplate* (the number) is public: it is used to find the peer (mailbox slot, LAN
//! beacon). The *whole code* is the password for the SPAKE2 handshake, which never sends
//! anything derived from it that could be brute-forced offline.

use anyhow::{bail, Result};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::fmt;

pub const WORDS: &[&str] = &[
    "acorn", "anchor", "apple", "arrow", "atlas", "autumn", "badge", "bamboo", "banjo", "basil",
    "beacon", "berry", "bison", "blanket", "blossom", "bonus", "breeze", "bridge", "bronze",
    "bubble", "bucket", "buffalo", "butter", "cabin", "cactus", "camel", "candle", "canoe",
    "canyon", "carbon", "carpet", "castle", "cedar", "cello", "cherry", "chess", "chimney",
    "cider", "cinema", "circus", "citrus", "clover", "cobalt", "coconut", "comet", "copper",
    "coral", "cotton", "cougar", "crayon", "cricket", "crystal", "cupcake", "dahlia", "daisy",
    "delta", "denim", "desert", "diamond", "dolphin", "domino", "dragon", "dream", "dune",
    "eagle", "echo", "eclipse", "ember", "emerald", "falcon", "feather", "fennel", "ferry",
    "fiddle", "flame", "flute", "forest", "fossil", "fountain", "galaxy", "garden", "garlic",
    "gecko", "ginger", "glacier", "globe", "granite", "grape", "gravel", "guitar", "hammer",
    "harbor", "hazel", "hedge", "helmet", "heron", "hickory", "honey", "horizon", "iceberg",
    "igloo", "indigo", "island", "ivory", "jacket", "jaguar", "jasmine", "jelly", "jigsaw",
    "jungle", "juniper", "kayak", "kettle", "kiwi", "koala", "ladder", "lagoon", "lantern",
    "lava", "lemon", "lentil", "lilac", "lily", "lizard", "lobster", "lotus", "magnet", "mango",
    "maple", "marble", "meadow", "melon", "meteor", "mint", "mirror", "mocha", "monsoon",
    "moose", "mosaic", "muffin", "mustard", "nectar", "needle", "nickel", "noodle", "nutmeg",
    "oasis", "ocean", "olive", "onion", "opal", "orbit", "orchid", "otter", "oyster", "paddle",
    "panda", "papaya", "parrot", "peach", "pebble", "pepper", "piano", "pickle", "pigeon",
    "pillow", "pine", "pirate", "pixel", "planet", "plum", "pocket", "polar", "pony", "poppy",
    "potato", "prism", "pumpkin", "puzzle", "quartz", "quill", "rabbit", "radar", "radish",
    "rain", "raven", "reef", "ribbon", "river", "robin", "rocket", "ruby", "saddle", "saffron",
    "salmon", "sapphire", "satin", "scarf", "shadow", "shell", "silver", "sketch", "sloth",
    "snow", "socket", "sonnet", "spice", "spider", "spruce", "squash", "star", "stone", "storm",
    "sugar", "summit", "sunset", "swan", "tango", "temple", "thunder", "tiger", "timber",
    "toast", "tomato", "topaz", "torch", "tulip", "tundra", "turtle", "tuxedo", "umbrella",
    "unicorn", "valley", "vanilla", "velvet", "violet", "violin", "volcano", "waffle", "walnut",
    "walrus", "wasabi", "willow", "window", "winter", "wizard", "yacht", "yarn", "yogurt",
    "zebra", "zephyr", "zigzag", "zinc", "falafel", "harp", "orange", "puffin", "tofu", "lemur",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Code {
    pub nameplate: u32,
    pub words: Vec<String>,
}

impl Code {
    pub fn generate(nameplate: u32) -> Code {
        let mut rng = rand::thread_rng();
        let words = (0..2)
            .map(|_| WORDS[rng.gen_range(0..WORDS.len())].to_string())
            .collect();
        Code { nameplate, words }
    }

    /// Parse a code typed by a human. Accepts `-`, spaces or `_` as separators, any case.
    pub fn parse(input: &str) -> Result<Code> {
        let norm = input.trim().to_lowercase().replace([' ', '_'], "-");
        let mut parts = norm.split('-').filter(|p| !p.is_empty());
        let np = parts.next().unwrap_or("");
        let nameplate: u32 = match np.parse() {
            Ok(n) if n > 0 && np.len() <= 6 => n,
            _ => bail!("invalid code '{}': expected something like 7-purple-sausage", input.trim()),
        };
        let words: Vec<String> = parts.map(str::to_string).collect();
        if words.is_empty() || words.iter().any(|w| !w.chars().all(|c| c.is_ascii_alphanumeric())) {
            bail!("invalid code '{}': expected something like 7-purple-sausage", input.trim());
        }
        Ok(Code { nameplate, words })
    }

    /// Canonical form, used as the PAKE password.
    pub fn password(&self) -> Vec<u8> {
        self.to_string().into_bytes()
    }

    fn tag(&self, label: &str) -> [u8; 16] {
        let mut h = Sha256::new();
        h.update(label.as_bytes());
        h.update(self.nameplate.to_be_bytes());
        let d = h.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&d[..16]);
        out
    }

    /// Public tag used in LAN discovery packets (derived from the nameplate only).
    pub fn lan_id(&self) -> [u8; 16] {
        self.tag("wormhole-lan-v1")
    }

    /// Public tag used in hole-punching probes (derived from the nameplate only).
    pub fn probe_token(&self) -> [u8; 16] {
        self.tag("wormhole-probe-v1")
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.nameplate, self.words.join("-"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn words_unique() {
        let set: HashSet<_> = WORDS.iter().collect();
        assert_eq!(set.len(), WORDS.len());
        assert!(WORDS.len() >= 250);
    }

    #[test]
    fn roundtrip() {
        let c = Code::generate(42);
        assert_eq!(Code::parse(&c.to_string()).unwrap(), c);
        assert_eq!(Code::parse(" 42 Purple_sausage ").unwrap().to_string(), "42-purple-sausage");
        assert!(Code::parse("purple-sausage").is_err());
        assert!(Code::parse("12").is_err());
        assert!(Code::parse("0-a-b").is_err());
        assert!(Code::parse("1-../x").is_err());
    }

    #[test]
    fn tags_depend_only_on_nameplate() {
        let a = Code::parse("5-apple-pie").unwrap();
        let b = Code::parse("5-other-words").unwrap();
        assert_eq!(a.lan_id(), b.lan_id());
        assert_ne!(a.lan_id(), a.probe_token());
    }
}
