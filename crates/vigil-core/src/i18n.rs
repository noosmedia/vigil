//! Zweisprachige Texte (Deutsch und Englisch) für alle Meldungen aus Kern und Helfer.
//!
//! Fehler und Meldungen sind ein [`Text`] mit beiden Sprachen. Gebaut werden sie mit
//! dem Makro [`tr!`](crate::tr): Argumente, die selbst ein `Text` sind, erscheinen
//! in der jeweils passenden Sprache, alle anderen über `Display`.

use std::fmt;

/// Sprache einer Ausgabe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    #[default]
    De,
    En,
}

impl Lang {
    /// Liest `de` oder `en`.
    pub fn parse(s: &str) -> Option<Lang> {
        match s {
            "de" => Some(Lang::De),
            "en" => Some(Lang::En),
            _ => None,
        }
    }

    /// Kürzel wie im Aufruf (`de`, `en`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Lang::De => "de",
            Lang::En => "en",
        }
    }
}

/// Ein Text in beiden Sprachen.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Text {
    pub de: String,
    pub en: String,
}

impl Text {
    /// Text aus beiden Sprachfassungen.
    pub fn new(de: impl Into<String>, en: impl Into<String>) -> Text {
        Text { de: de.into(), en: en.into() }
    }

    /// Gleicher Inhalt in beiden Sprachen (z. B. Pfade oder Ausgaben fremder Programme).
    pub fn same(s: impl Into<String>) -> Text {
        let s = s.into();
        Text { de: s.clone(), en: s }
    }

    /// Leer in beiden Sprachen?
    pub fn is_empty(&self) -> bool {
        self.de.is_empty() && self.en.is_empty()
    }

    /// Deutsche Fassung für Nutzer: Betriebssystemfehler werden übersetzt.
    pub fn de_text(&self) -> String {
        crate::fsutil::localize_os_errors(&self.de)
    }

    /// Englische Fassung für Nutzer: Zusätze wie `(os error 2)` entfallen.
    pub fn en_text(&self) -> String {
        strip_os_error_codes(&self.en)
    }

    /// Fassung in der gewünschten Sprache.
    pub fn get(&self, lang: Lang) -> String {
        match lang {
            Lang::De => self.de_text(),
            Lang::En => self.en_text(),
        }
    }

    /// Verbindet mehrere Texte mit Leerzeichen (leere Teile entfallen).
    pub fn join(parts: &[Text]) -> Text {
        let pick = |f: fn(&Text) -> &str| {
            parts.iter().map(f).filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ")
        };
        Text { de: pick(|t| &t.de), en: pick(|t| &t.en) }
    }
}

/// Deutsche Fassung (für Schnittstellen, die nur einen Text liefern, z. B. für die App).
impl From<Text> for String {
    fn from(t: Text) -> String {
        t.de_text()
    }
}

/// Entfernt `(os error N)` aus englischen Meldungen.
pub fn strip_os_error_codes(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    let mut rest = msg;
    while let Some(pos) = rest.find(" (os error ") {
        let after = &rest[pos + 11..];
        match after.find(')') {
            Some(end) if after[..end].chars().all(|c| c.is_ascii_digit()) => {
                out.push_str(&rest[..pos]);
                rest = &after[end + 1..];
            }
            _ => {
                out.push_str(&rest[..pos + 11]);
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Formatierung je Sprache: `Text` liefert die passende Fassung, alles andere `Display`.
pub trait Bilingual {
    fn fmt_de(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result;
    fn fmt_en(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result;
}

impl<T: fmt::Display + ?Sized> Bilingual for T {
    fn fmt_de(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
    fn fmt_en(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Bilingual for Text {
    fn fmt_de(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.de)
    }
    fn fmt_en(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.en)
    }
}

/// Hilfstyp für [`tr!`](crate::tr): deutsche Fassung eines Arguments.
pub struct De<'a, T: ?Sized>(pub &'a T);
/// Hilfstyp für [`tr!`](crate::tr): englische Fassung eines Arguments.
pub struct En<'a, T: ?Sized>(pub &'a T);

impl<T: Bilingual + ?Sized> fmt::Display for De<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt_de(f)
    }
}

impl<T: Bilingual + ?Sized> fmt::Display for En<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt_en(f)
    }
}

/// Baut einen [`Text`]: `tr!("Deutsch {}", "English {}", arg)`.
/// Jedes Argument wird in beiden Fassungen verwendet und darf daher keine Nebenwirkungen haben.
#[macro_export]
macro_rules! tr {
    ($de:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        $crate::i18n::Text::new(
            format!($de $(, $crate::i18n::De(&$arg))*),
            format!($en $(, $crate::i18n::En(&$arg))*),
        )
    };
}
