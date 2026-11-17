//! The two questions asked of a time zone, in one place: is this a zone, and
//! what is its offset from UTC at this instant.
//!
//! Three sites ask them: a schedule's zone and the zone its cron's next
//! occurrence is computed in (`aegix-schedule-spec`), the host call
//! `local-offset-seconds` of the `datetime` interface (`aegix-worker-runtime`),
//! and that call's stand-in for a module's tests (`aegix-module-testkit`).
//! Until 2026-11-17 each parsed a `chrono_tz::Tz` itself, and the rules behind
//! all three were IANA release 2025b, compiled in by a library that had
//! stopped following the database: by then an hour out for British Columbia,
//! Alberta, the Northwest Territories and Manitoba.
//!
//! # Where the rules come from
//!
//! From the IANA database compiled into the binary by `jiff-tzdb`, and from
//! nowhere else. [`database_release`] says which release. The host's zone
//! files are never read, whether or not it has any: an image without
//! `tzdata`, a laptop whose operating system is a year behind and a
//! container with a read-only root all answer alike, and a module's test
//! answers as the worker will. The cost is that new rules arrive by a
//! dependency bump and a build, never by updating a machine.
//!
//! The database is in every build of this crate: the feature that compiles
//! it in is turned on in this crate's manifest and a feature cannot be turned
//! off from outside. A build cannot answer from an empty one.
//!
//! # What a zone is
//!
//! A name the database lists, written exactly as it lists it:
//! `America/New_York`, `UTC`, `Etc/GMT+5`, and the older names it still
//! carries (`US/Eastern`). Case matters. An offset (`-04:00`), a POSIX rule
//! (`EST5EDT,M3.2.0,M11.1.0`) and a path are not zones. Nor is `Factory`,
//! the database's own entry for a machine whose zone was never set. A name
//! longer than [`MAX_ZONE_NAME_BYTES`] is refused before it is looked up.

use chrono::{
    Datelike, FixedOffset, MappedLocalTime, NaiveDate, NaiveDateTime, NaiveTime, Offset, Timelike,
};
use jiff::tz::{AmbiguousOffset, TimeZone, TimeZoneDatabase};
use std::fmt;
use std::sync::OnceLock;

/// Longest zone name looked up. The longest IANA name is 32 bytes
/// (`America/Argentina/ComodRivadavia`); the bound only keeps a caller from
/// making the lookup compare megabytes.
pub const MAX_ZONE_NAME_BYTES: usize = 64;

/// The database's entry for "no zone was set on this machine": UTC under the
/// abbreviation `-00`. It is listed beside the zones and names no place, so
/// it is not one here.
const NO_ZONE_SET: &str = "Factory";

/// The compiled-in database, and only it: `TimeZoneDatabase::bundled` never
/// consults the host, whatever features another crate in the build turns on
/// in `jiff`.
fn database() -> &'static TimeZoneDatabase {
    static DATABASE: OnceLock<TimeZoneDatabase> = OnceLock::new();
    DATABASE.get_or_init(TimeZoneDatabase::bundled)
}

/// The IANA release the compiled-in rules are, for example `2026f`.
pub fn database_release() -> &'static str {
    jiff_tzdb::VERSION
}

/// Why a name is not a zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAZone {
    /// Longer than [`MAX_ZONE_NAME_BYTES`]; never looked up.
    TooLong {
        /// The name's length in bytes.
        len: usize,
    },
    /// Not a name the database lists, as it lists it.
    Unknown,
}

impl fmt::Display for NotAZone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NotAZone::TooLong { len } => write!(
                f,
                "a time zone name of {len} bytes is longer than {MAX_ZONE_NAME_BYTES}"
            ),
            NotAZone::Unknown => f.write_str("not an IANA time zone name"),
        }
    }
}

impl std::error::Error for NotAZone {}

/// A time zone the database lists.
///
/// Cheap to clone. It is also a [`chrono::TimeZone`], which is how the cron
/// library is given a schedule's zone.
#[derive(Clone)]
pub struct Zone {
    rules: TimeZone,
}

impl Zone {
    /// The zone `name` names, or why it names none.
    pub fn named(name: &str) -> Result<Zone, NotAZone> {
        if name.len() > MAX_ZONE_NAME_BYTES {
            return Err(NotAZone::TooLong { len: name.len() });
        }
        let rules = database().get(name).map_err(|_| NotAZone::Unknown)?;
        // The lookup ignores case and answers two names that are not in the
        // database (`utc` in any case, and `Etc/Unknown`, which has no name).
        // A zone here is a listed name written exactly.
        if rules.iana_name() != Some(name) || name == NO_ZONE_SET {
            return Err(NotAZone::Unknown);
        }
        Ok(Zone { rules })
    }

    /// The zone's name, as it was asked for and as the database lists it.
    pub fn name(&self) -> &str {
        self.rules.iana_name().unwrap_or_default()
    }

    /// Seconds east of UTC in this zone at `unix_seconds`, by the zone's own
    /// rules. `None` for an instant outside the years -9999 to 9999, which is
    /// as far as the rules are computed.
    pub fn offset_seconds_at(&self, unix_seconds: i64) -> Option<i32> {
        let instant = jiff::Timestamp::from_second(unix_seconds).ok()?;
        Some(self.rules.to_offset(instant).seconds())
    }

    fn offset(&self, offset: jiff::tz::Offset) -> Option<ZoneOffset> {
        Some(ZoneOffset {
            zone: self.clone(),
            fixed: FixedOffset::east_opt(offset.seconds())?,
        })
    }
}

impl fmt::Debug for Zone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Seconds east of UTC in the zone named `zone` at `unix_seconds`: both
/// questions at once, for a caller that holds a name and an instant.
///
/// `None` when `zone` is not a zone ([`Zone::named`]) or the instant is
/// outside what [`Zone::offset_seconds_at`] answers. It never guesses: there
/// is no default zone and no nearest name.
pub fn offset_seconds(zone: &str, unix_seconds: u64) -> Option<i32> {
    Zone::named(zone)
        .ok()?
        .offset_seconds_at(i64::try_from(unix_seconds).ok()?)
}

/// A [`Zone`]'s offset at one instant, as `chrono` carries it inside a
/// `DateTime<Zone>`.
#[derive(Clone)]
pub struct ZoneOffset {
    zone: Zone,
    fixed: FixedOffset,
}

impl Offset for ZoneOffset {
    fn fix(&self) -> FixedOffset {
        self.fixed
    }
}

impl fmt::Debug for ZoneOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.fixed, f)
    }
}

impl fmt::Display for ZoneOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.fixed, f)
    }
}

/// The wall-clock reading `local` as the rules' own type, or `None` for a
/// year they do not reach. Fractions of a second are dropped: no zone changes
/// its offset inside one.
fn civil(local: &NaiveDateTime) -> Option<jiff::civil::DateTime> {
    jiff::civil::DateTime::new(
        i16::try_from(local.year()).ok()?,
        i8::try_from(local.month()).ok()?,
        i8::try_from(local.day()).ok()?,
        i8::try_from(local.hour()).ok()?,
        i8::try_from(local.minute()).ok()?,
        i8::try_from(local.second()).ok()?,
        0,
    )
    .ok()
}

/// `chrono`'s view of a zone, which is what `croner` computes a cron's next
/// occurrence through: it asks for the offset of a wall-clock reading, steps
/// forward out of a gap, and takes the first of two readings in a fold.
impl chrono::TimeZone for Zone {
    type Offset = ZoneOffset;

    fn from_offset(offset: &ZoneOffset) -> Zone {
        offset.zone.clone()
    }

    fn offset_from_local_date(&self, local: &NaiveDate) -> MappedLocalTime<ZoneOffset> {
        self.offset_from_local_datetime(&local.and_time(NaiveTime::MIN))
    }

    /// One offset for a reading that happens once, none for a reading the
    /// clocks skip, and for a reading that happens twice both offsets, the
    /// earlier instant's first.
    fn offset_from_local_datetime(&self, local: &NaiveDateTime) -> MappedLocalTime<ZoneOffset> {
        let Some(civil) = civil(local) else {
            return MappedLocalTime::None;
        };
        match self.rules.to_ambiguous_timestamp(civil).offset() {
            AmbiguousOffset::Unambiguous { offset } => match self.offset(offset) {
                Some(offset) => MappedLocalTime::Single(offset),
                None => MappedLocalTime::None,
            },
            AmbiguousOffset::Gap { .. } => MappedLocalTime::None,
            AmbiguousOffset::Fold { before, after } => {
                match (self.offset(before), self.offset(after)) {
                    (Some(first), Some(second)) => MappedLocalTime::Ambiguous(first, second),
                    _ => MappedLocalTime::None,
                }
            }
        }
    }

    fn offset_from_utc_date(&self, utc: &NaiveDate) -> ZoneOffset {
        self.offset_from_utc_datetime(&utc.and_time(NaiveTime::MIN))
    }

    /// `chrono` gives this no way to refuse, and its years run far past the
    /// rules' (262143 against 9999). An instant beyond them is answered with
    /// the offset at the nearest instant the rules reach.
    fn offset_from_utc_datetime(&self, utc: &NaiveDateTime) -> ZoneOffset {
        let seconds = utc.and_utc().timestamp();
        let instant = jiff::Timestamp::from_second(seconds).unwrap_or(if seconds < 0 {
            jiff::Timestamp::MIN
        } else {
            jiff::Timestamp::MAX
        });
        // No zone in the database is a day from UTC (the widest is under 16
        // hours), which is the only way `offset` answers `None`.
        self.offset(self.rules.to_offset(instant))
            .unwrap_or_else(|| ZoneOffset {
                zone: self.clone(),
                fixed: chrono::Utc.fix(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, TimeZone as _, Utc};

    /// 2026-11-15T12:00:00Z and 2026-07-15T12:00:00Z.
    const MID_NOVEMBER: u64 = 1_794_744_000;
    const MID_JULY: u64 = 1_784_116_800;

    const HOUR: i32 = 3600;

    /// The proving test of the move off the frozen rules. Alberta stopped
    /// changing its clocks: -06:00 all year from 2026-11-01 (release 2026c).
    /// Release 2025b put it back to -07:00 that day.
    #[test]
    fn edmonton_is_six_hours_behind_after_november_2026() {
        assert_eq!(
            offset_seconds("America/Edmonton", MID_NOVEMBER),
            Some(-6 * HOUR)
        );
        assert_eq!(
            offset_seconds("America/Edmonton", MID_JULY),
            Some(-6 * HOUR)
        );
    }

    /// The other Canadian zones the database changed for the same day: each
    /// keeps its summer offset through the winter.
    #[test]
    fn the_other_canadian_zones_that_stopped_changing_keep_their_summer_offset() {
        for (zone, hours) in [
            ("America/Vancouver", -7),
            ("America/Inuvik", -6),
            ("America/Winnipeg", -5),
        ] {
            assert_eq!(
                offset_seconds(zone, MID_NOVEMBER),
                Some(hours * HOUR),
                "{zone}"
            );
            assert_eq!(offset_seconds(zone, MID_JULY), Some(hours * HOUR), "{zone}");
        }
    }

    /// Cuba did not put its clocks back on 2026-11-01 (release 2026f, the
    /// first with it): Havana stays at -04:00 through that winter. Every
    /// earlier release answers -05:00 here.
    #[test]
    fn havana_did_not_put_its_clocks_back_in_november_2026() {
        assert_eq!(
            offset_seconds("America/Havana", MID_NOVEMBER),
            Some(-4 * HOUR)
        );
        assert_eq!(offset_seconds("America/Havana", MID_JULY), Some(-4 * HOUR));
    }

    #[test]
    fn a_zone_that_still_changes_its_clocks_changes_them() {
        assert_eq!(
            offset_seconds("America/New_York", MID_JULY),
            Some(-4 * HOUR)
        );
        assert_eq!(
            offset_seconds("America/New_York", MID_NOVEMBER),
            Some(-5 * HOUR)
        );
        assert_eq!(offset_seconds("Asia/Kolkata", MID_JULY), Some(19_800));
        assert_eq!(offset_seconds("UTC", MID_JULY), Some(0));
        assert_eq!(offset_seconds("Etc/GMT+5", MID_JULY), Some(-5 * HOUR));
    }

    #[test]
    fn a_zone_is_a_listed_name_written_exactly() {
        for zone in ["UTC", "America/New_York", "US/Eastern", "Etc/UTC", "GMT"] {
            let found = Zone::named(zone).expect(zone);
            assert_eq!(found.name(), zone);
        }
        for bad in [
            "",
            "utc",
            "america/new_york",
            "AMERICA/NEW_YORK",
            "New York",
            "Etc/Unknown",
            "etc/unknown",
            "Factory",
            "EST5",
            "EST5EDT,M3.2.0,M11.1.0",
            "-04:00",
            "+05:00",
            "America/New_York\n",
            " America/New_York",
            "America/New_York; DROP",
            "../../etc/localtime",
            "/usr/share/zoneinfo/UTC",
            "Not/AZone",
        ] {
            assert_eq!(Zone::named(bad).err(), Some(NotAZone::Unknown), "{bad:?}");
            assert_eq!(offset_seconds(bad, 0), None, "{bad:?}");
        }
    }

    #[test]
    fn a_name_past_the_bound_is_refused_by_its_length() {
        let at_the_bound = "A".repeat(MAX_ZONE_NAME_BYTES);
        assert_eq!(Zone::named(&at_the_bound).err(), Some(NotAZone::Unknown));
        let past_it = "A".repeat(MAX_ZONE_NAME_BYTES + 1);
        assert_eq!(
            Zone::named(&past_it).err(),
            Some(NotAZone::TooLong { len: 65 })
        );
        assert_eq!(offset_seconds(&"A".repeat(10_000), 0), None);
        // The message carries the length and never the name.
        let message = NotAZone::TooLong { len: 65 }.to_string();
        assert!(
            message.contains("65") && !message.contains("AAAA"),
            "{message}"
        );
    }

    #[test]
    fn an_instant_the_rules_do_not_reach_is_refused_not_wrapped() {
        assert_eq!(offset_seconds("UTC", 0), Some(0));
        assert_eq!(offset_seconds("UTC", u64::MAX), None);
        assert_eq!(offset_seconds("UTC", i64::MAX as u64), None);
        // 9999-12-30T22:00:00Z is the last second the rules answer.
        assert_eq!(offset_seconds("UTC", 253_402_207_200), Some(0));
        assert_eq!(offset_seconds("UTC", 253_402_207_201), None);
    }

    /// A build that answered from an empty database would refuse every name
    /// but could not be told from one given bad names. The database is
    /// compiled in, and this is what says so.
    #[test]
    fn the_database_is_compiled_in_and_every_name_it_lists_is_a_zone() {
        assert!(!database().is_definitively_empty());
        let names: Vec<_> = database().available().collect();
        assert!(names.len() >= 590, "only {} names", names.len());
        assert!(names.iter().any(|name| name.as_str() == NO_ZONE_SET));
        for name in &names {
            let name = name.as_str();
            if name == NO_ZONE_SET {
                continue;
            }
            let zone = Zone::named(name).expect(name);
            assert_eq!(zone.name(), name);
            assert!(zone.offset_seconds_at(MID_JULY as i64).is_some(), "{name}");
        }
    }

    /// The release is a property of `Cargo.lock`. One older than the release
    /// this crate was first built on would bring back answers already known
    /// to be wrong; a downgrade stops here.
    #[test]
    fn the_compiled_in_release_is_not_older_than_2026f() {
        let release = database_release();
        assert!(
            release.len() == 5 && release >= "2026f",
            "compiled-in zone rules are release {release:?}"
        );
    }

    fn new_york() -> Zone {
        Zone::named("America/New_York").unwrap()
    }

    fn reading(text: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S").unwrap()
    }

    fn fixed(result: MappedLocalTime<ZoneOffset>) -> MappedLocalTime<i32> {
        result.map(|offset| offset.fix().local_minus_utc())
    }

    /// What `croner` asks. New York, 2027-03-14: 02:00 becomes 03:00.
    #[test]
    fn a_reading_the_clocks_skip_has_no_offset() {
        let zone = new_york();
        assert_eq!(
            fixed(zone.offset_from_local_datetime(&reading("2027-03-14 01:59:59"))),
            MappedLocalTime::Single(-5 * HOUR)
        );
        for skipped in ["2027-03-14 02:00:00", "2027-03-14 02:59:59"] {
            assert_eq!(
                fixed(zone.offset_from_local_datetime(&reading(skipped))),
                MappedLocalTime::None,
                "{skipped}"
            );
        }
        assert_eq!(
            fixed(zone.offset_from_local_datetime(&reading("2027-03-14 03:00:00"))),
            MappedLocalTime::Single(-4 * HOUR)
        );
    }

    /// New York, 2026-11-01: 02:00 becomes 01:00, so 01:00 to 01:59 happens
    /// twice. The earlier instant's offset comes first, which is the one
    /// `croner` takes.
    #[test]
    fn a_reading_that_happens_twice_has_both_offsets_the_earlier_first() {
        let zone = new_york();
        for twice in ["2026-11-01 01:00:00", "2026-11-01 01:59:59"] {
            assert_eq!(
                fixed(zone.offset_from_local_datetime(&reading(twice))),
                MappedLocalTime::Ambiguous(-4 * HOUR, -5 * HOUR),
                "{twice}"
            );
        }
        assert_eq!(
            fixed(zone.offset_from_local_datetime(&reading("2026-11-01 02:00:00"))),
            MappedLocalTime::Single(-5 * HOUR)
        );
        let first = zone
            .from_local_datetime(&reading("2026-11-01 01:30:00"))
            .earliest()
            .unwrap();
        assert_eq!(
            first.with_timezone(&Utc).to_rfc3339(),
            "2026-11-01T05:30:00+00:00"
        );
    }

    #[test]
    fn an_instant_converts_to_the_zones_wall_clock_and_back() {
        let zone = Zone::named("America/Edmonton").unwrap();
        let instant: DateTime<Utc> = "2026-11-15T12:00:00Z".parse().unwrap();
        let local = instant.with_timezone(&zone);
        assert_eq!(local.naive_local(), reading("2026-11-15 06:00:00"));
        assert_eq!(local.timezone().name(), "America/Edmonton");
        assert_eq!(local.with_timezone(&Utc), instant);
        assert_eq!(local.to_rfc3339(), "2026-11-15T06:00:00-06:00");
    }

    /// `chrono`'s years run past the rules'. Neither end panics, and a
    /// reading in a year the rules do not reach has no offset.
    #[test]
    fn the_ends_of_chronos_range_do_not_panic() {
        let zone = new_york();
        let far = zone.offset_from_utc_datetime(&NaiveDateTime::MAX);
        assert_eq!(far.fix().local_minus_utc(), -5 * HOUR);
        let _ = zone.offset_from_utc_datetime(&NaiveDateTime::MIN);
        assert_eq!(
            fixed(zone.offset_from_local_datetime(&NaiveDateTime::MAX)),
            MappedLocalTime::None
        );
        assert_eq!(
            fixed(zone.offset_from_local_datetime(&NaiveDateTime::MIN)),
            MappedLocalTime::None
        );
    }
}
