use std::fmt;

use super::{session::Session, N_SESSIONS};

/// A unique identifier for an instance of [`Tunn`](super::Tunn).
///
/// The top 24 bits are used as a unique, global identifier.
/// The lower 8 bits are used as a rotating session index with a given peer.
///
/// This allows for ~16M unique peers and 256 sessions per peer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Index(u32);

impl Index {
    pub fn new_local(idx: u32) -> Self {
        assert_eq!(idx >> 24, 0, "Must be at most a 24-bit number");

        Self(idx << 8)
    }

    pub fn from_peer(peer: u32) -> Self {
        Self(peer)
    }

    pub(crate) fn wrapping_increment(&mut self) -> Index {
        let index = self.0;
        let idx8 = index as u8;
        self.0 = (index & !0xff) | u32::from(idx8.wrapping_add(1));

        Self(self.0)
    }

    pub(crate) fn wrapping_sub(&self) -> Self {
        let index = self.0;
        let idx8 = index as u8;
        let result = (index & !0xff) | u32::from(idx8.wrapping_sub(1));

        Self(result)
    }

    pub(crate) fn to_le_bytes(&self) -> [u8; 4] {
        self.0.to_le_bytes()
    }

    pub fn global(&self) -> usize {
        (self.0 >> 8) as usize
    }

    pub fn session(&self) -> usize {
        self.0 as u8 as usize
    }
}

impl fmt::Display for Index {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let idx = self.0;

        let global = idx >> 8;
        let session = idx as u8;

        write!(f, "({global}|{session})")
    }
}

impl PartialEq<u32> for Index {
    fn eq(&self, other: &u32) -> bool {
        self.0.eq(other)
    }
}

impl PartialEq<Index> for u32 {
    fn eq(&self, other: &Index) -> bool {
        self.eq(&other.0)
    }
}

impl std::ops::Index<Index> for [Option<Session>; N_SESSIONS] {
    type Output = Option<Session>;

    fn index(&self, index: Index) -> &Self::Output {
        &self[(index.0 as usize) % N_SESSIONS]
    }
}

impl std::ops::IndexMut<Index> for [Option<Session>; N_SESSIONS] {
    fn index_mut(&mut self, index: Index) -> &mut Self::Output {
        &mut self[(index.0 as usize) % N_SESSIONS]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incrementing_never_changes_global_part() {
        let mut index = Index::new_local(rand::random::<u32>() >> 8);

        let global = index.global();

        for _ in 0..23745 {
            index.wrapping_increment();

            assert_eq!(index.global(), global);
        }
    }

    #[test]
    fn incrementing_changes_session_index() {
        let mut index = Index::new_local(rand::random::<u32>() >> 8);

        for i in 0..256 {
            assert_eq!(index.session(), i);

            index.wrapping_increment();
        }

        // Cycling through it again starts on 0
        for i in 0..256 {
            assert_eq!(index.session(), i);

            index.wrapping_increment();
        }
    }
}
