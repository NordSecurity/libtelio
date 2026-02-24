use hashlink::lru_cache::RawOccupiedEntryMut;
use hashlink::{linked_hash_map::RawEntryMut, LinkedHashMap};
use rustc_hash::FxHasher;
use std::hash::BuildHasher;
use std::{
    borrow::Borrow,
    hash::{BuildHasherDefault, Hash},
    time::Duration,
};

#[cfg(any(test, feature = "sn_fake_clock"))]
use sn_fake_clock::FakeClock as Instant;
#[cfg(not(any(test, feature = "sn_fake_clock")))]
type Instant = crate::Instant;

/// A view into a single entry in a map, which may either be vacant or occupied.
pub enum Entry<'a, K, V> {
    /// An occupied entry.
    Occupied(OccupiedEntry<'a, K, V>),
    /// A vacant entry.
    Vacant(VacantEntry<'a, K, V>),
}

/// A view into an occupied entry in a `LruCache`.
pub struct OccupiedEntry<'a, K, V> {
    key: K,
    hash: u64,
    map: &'a mut LinkedHashMap<K, TimedValue<V>, BuildHasherDefault<FxHasher>>,
}

impl<K: Hash + Eq, V> OccupiedEntry<'_, K, V> {
    /// Gets a reference to the key in the entry.
    #[inline(always)]
    pub fn key(&self) -> &K {
        &self.key
    }

    /// Gets a mutable reference to the value in the entry.
    #[inline(always)]
    pub fn get_mut(&mut self) -> &mut V {
        &mut self.occupied_entry().into_mut().data
    }

    /// Gets a immutable reference to the value in the entry.
    #[inline(always)]
    pub fn get(&self) -> &V {
        if let Some((_, tv)) = self
            .map
            .raw_entry()
            .from_key_hashed_nocheck(self.hash, &self.key)
        {
            &tv.data
        } else {
            unreachable!()
        }
    }

    /// Removes the entry from the map.
    #[inline(always)]
    pub fn remove(&mut self) {
        self.occupied_entry().remove();
    }

    fn occupied_entry(
        &'_ mut self,
    ) -> RawOccupiedEntryMut<'_, K, TimedValue<V>, BuildHasherDefault<FxHasher>> {
        if let RawEntryMut::Occupied(e) = self
            .map
            .raw_entry_mut()
            .from_key_hashed_nocheck(self.hash, &self.key)
        {
            e
        } else {
            unreachable!()
        }
    }
}

/// A view into a vacant entry in a `LruCache`.
pub struct VacantEntry<'a, K, V> {
    key: K,
    hash: u64,
    max_map_size: usize,
    map: &'a mut LinkedHashMap<K, TimedValue<V>, BuildHasherDefault<FxHasher>>,
}

impl<K, V> VacantEntry<'_, K, V> {
    /// Gets a reference to the key in the entry.
    #[inline(always)]
    pub fn key(&self) -> &K {
        &self.key
    }

    /// Sets the value of the entry with the VacantEntry’s key, and returns a mutable reference to it.
    #[inline(always)]
    pub fn insert(self, value: V)
    where
        K: Hash + Eq,
    {
        if let RawEntryMut::Vacant(e) = self
            .map
            .raw_entry_mut()
            .from_key_hashed_nocheck(self.hash, &self.key)
        {
            e.insert_hashed_nocheck(self.hash, self.key, TimedValue::new(value));
            if self.map.len() > self.max_map_size {
                self.map.pop_front();
            }
        }
    }
}

#[derive(Debug)]
struct TimedValue<V> {
    data: V,
    last_access: Instant,
}

impl<V> TimedValue<V> {
    fn new(data: V) -> Self {
        Self {
            data,
            last_access: Instant::now(),
        }
    }

    fn update_last_access(&mut self, new_last_access: Instant) {
        self.last_access = new_last_access;
    }

    fn is_expired(&self, ttl: Duration, now: Instant) -> bool {
        self.last_access + ttl < now
    }
}

/// Implementation of a Least Recently Used
/// [caching algorithm](http://en.wikipedia.org/wiki/Cache_algorithms) in a container which may be
/// limited by size or time, ordered by most recently seen.
#[derive(Debug)]
pub struct LruCache<Key, Value> {
    map: LinkedHashMap<Key, TimedValue<Value>, BuildHasherDefault<FxHasher>>,
    ttl: Duration,
    capacity: usize,
}

impl<Key: Clone + Eq + Hash, Value> LruCache<Key, Value> {
    /// Constructor for dual-feature capacity and time based `LruCache`.
    #[inline(always)]
    pub fn new(ttl: Duration, capacity: usize) -> LruCache<Key, Value> {
        LruCache {
            map: LinkedHashMap::default(),
            ttl,
            capacity,
        }
    }

    /// Returns the size of the cache, i.e. the number of cached non-expired key-value pairs.
    /// Also removes expired elements.
    #[inline(always)]
    pub fn len(&mut self) -> usize {
        self.remove_expired();
        self.map.len()
    }

    /// Returns true if the map contains no elements.
    /// Also removes expired elements.
    #[inline(always)]
    pub fn is_empty(&mut self) -> bool {
        self.remove_expired();
        self.map.is_empty()
    }

    /// Returns the number of unexpired entries.
    /// Without removing expired elements.
    #[cfg(test)]
    pub fn len_slow(&mut self) -> usize {
        let now = Instant::now();
        self.map
            .iter()
            .filter(|(_, timed_value)| !timed_value.is_expired(self.ttl, now))
            .count()
    }

    /// Returns true if the map contains no unexpired elements.
    /// Without removing expired elements.
    #[cfg(test)]
    pub fn is_empty_slow(&mut self) -> bool {
        self.len_slow() == 0
    }

    /// Gets the given key’s corresponding entry in the map for in-place manipulation.
    #[inline(always)]
    pub fn entry(&mut self, key: Key, update_last_access_time: bool) -> Entry<'_, Key, Value> {
        let hash = self.map.hasher().hash_one(&key);
        match self.map.raw_entry_mut().from_key_hashed_nocheck(hash, &key) {
            RawEntryMut::Occupied(mut e) => {
                let now = Instant::now();
                if e.get_key_value().1.is_expired(self.ttl, now) {
                    e.remove();
                    return Entry::Vacant(VacantEntry {
                        key,
                        hash,
                        map: &mut self.map,
                        max_map_size: self.capacity,
                    });
                }
                if update_last_access_time {
                    Self::update_last_time(&mut e, now)
                }
                Entry::Occupied(OccupiedEntry {
                    key,
                    hash,
                    map: &mut self.map,
                })
            }
            RawEntryMut::Vacant(_) => Entry::Vacant(VacantEntry {
                key,
                hash,
                map: &mut self.map,
                max_map_size: self.capacity,
            }),
        }
    }

    /// Retrieves a reference to the value stored under `key`, or `None` if the key doesn't exist.
    /// Also removes expired elements and updates the time.
    #[inline(always)]
    pub fn get<Q>(&mut self, key: &Q) -> Option<&Value>
    where
        Key: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.get_mut(key).map(|value| &*value)
    }

    /// Retrieves a mutable reference to the value stored under `key`, or `None` if the key doesn't
    /// exist.  Also removes expired elements and updates the time.
    #[inline(always)]
    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut Value>
    where
        Key: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let now = self.remove_expired().0;

        if let RawEntryMut::Occupied(mut entry) = self.map.raw_entry_mut().from_key(key) {
            Self::update_last_time(&mut entry, now);
            Some(&mut entry.into_mut().data)
        } else {
            None
        }
    }

    /// Inserts a key-value pair into the cache.
    ///
    /// If the key already existed in the cache, the existing value is overwritten in
    /// the cache.  Otherwise, the new key-value pair is inserted.
    #[inline(always)]
    pub fn insert(&mut self, key: Key, value: Value) {
        self.map.insert(key, TimedValue::new(value));

        if self.map.len() > self.capacity {
            self.map.pop_front();
        }
    }

    /// Removes a key-value pair from the cache.
    #[inline(always)]
    pub fn remove(&mut self, key: &Key) -> Option<Value> {
        self.map.remove(key).map(|v| v.data)
    }

    /// Returns a reference to the value with the given `key`, if present and not expired, without
    /// updating the timestamp.
    pub fn peek<Q>(&self, key: &Q) -> Option<&Value>
    where
        Key: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let timed_value = self.map.get(key)?;
        if timed_value.is_expired(self.ttl, Instant::now()) {
            return None;
        }
        Some(&timed_value.data)
    }

    /// Returns an iterator over all (key, value) pairs
    pub fn iter(&self) -> impl Iterator<Item = (&Key, &Value)> {
        self.map.iter().map(|(key, val)| (key, &val.data))
    }

    /// Removes expired items from the cache and returns all removed keys.
    fn remove_expired(&mut self) -> (Instant, Vec<Key>) {
        let now = Instant::now();
        let expired_keys: Vec<_> = self
            .map
            .iter()
            .take_while(|(_, timed_value)| timed_value.is_expired(self.ttl, now))
            .map(|(key, _)| key.clone())
            .collect();

        for k in &expired_keys {
            self.map.remove(k);
        }
        (now, expired_keys)
    }

    fn update_last_time(
        entry: &mut RawOccupiedEntryMut<'_, Key, TimedValue<Value>, BuildHasherDefault<FxHasher>>,
        now: Instant,
    ) {
        entry.get_mut().update_last_access(now);
        entry.to_back();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::distr::{Distribution, StandardUniform};
    use std::time::Duration;

    fn advance_time_by_ms(time: u64) {
        sn_fake_clock::FakeClock::advance_time(time);
    }

    // Tests copied from the lru_time_cache
    #[test]
    fn size_only() {
        let size = 10usize;
        let mut lru_cache = LruCache::<usize, usize>::new(Duration::from_secs(10), size);

        for i in 0..10 {
            assert_eq!(lru_cache.len(), i);
            let _ = lru_cache.insert(i, i);
            assert_eq!(lru_cache.len(), i + 1);
        }

        for i in 10..1000 {
            let _ = lru_cache.insert(i, i);
            assert_eq!(lru_cache.len(), size);
        }

        for _ in (0..1000).rev() {
            assert!(lru_cache.peek(&(1000 - 1)).is_some());
            assert!(lru_cache.get(&(1000 - 1)).is_some());
            assert_eq!(*lru_cache.get(&(1000 - 1)).unwrap(), 1000 - 1);
        }
    }

    #[test]
    fn time_only() {
        let time_to_live = Duration::from_millis(100);
        let mut lru_cache = LruCache::<usize, usize>::new(time_to_live, usize::MAX);

        for i in 0..10 {
            assert_eq!(lru_cache.len(), i);
            let _ = lru_cache.insert(i, i);
            assert_eq!(lru_cache.len(), i + 1);
        }

        advance_time_by_ms(101);
        let _ = lru_cache.insert(11, 11);

        assert_eq!(lru_cache.len(), 1);

        for i in 0..10 {
            assert_eq!(lru_cache.len(), i + 1);
            let _ = lru_cache.insert(i, i);
            assert_eq!(lru_cache.len(), i + 2);
        }

        advance_time_by_ms(101);
        assert_eq!(0, lru_cache.len());
    }

    #[test]
    fn time_only_check() {
        let time_to_live = Duration::from_millis(50);
        let mut lru_cache = LruCache::<usize, usize>::new(time_to_live, usize::MAX);

        assert_eq!(lru_cache.len(), 0);
        let _ = lru_cache.insert(0, 0);
        assert_eq!(lru_cache.len(), 1);

        advance_time_by_ms(101);

        assert!(!lru_cache.peek(&0).is_some());
        assert_eq!(lru_cache.len(), 0);
    }

    #[test]
    fn time_and_size() {
        let size = 10usize;
        let time_to_live = Duration::from_millis(100);
        let mut lru_cache = LruCache::<usize, usize>::new(time_to_live, size);

        for i in 0..1000 {
            if i < size {
                assert_eq!(lru_cache.len(), i);
            }

            let _ = lru_cache.insert(i, i);

            if i < size {
                assert_eq!(lru_cache.len(), i + 1);
            } else {
                assert_eq!(lru_cache.len(), size);
            }
        }

        advance_time_by_ms(101);
        let _ = lru_cache.insert(1, 1);

        assert_eq!(lru_cache.len(), 1);
    }

    #[test]
    fn remove() {
        let time_to_live = Duration::from_millis(50);
        let mut lru_cache = LruCache::<usize, usize>::new(time_to_live, usize::MAX);

        let _ = lru_cache.insert(0, 1);
        assert_eq!(lru_cache.len(), 1);
        assert_eq!(lru_cache.remove(&0), Some(1));
        assert_eq!(lru_cache.len(), 0);
    }

    fn generate_random_vec<T>(len: usize) -> Vec<T>
    where
        StandardUniform: Distribution<T>,
    {
        StandardUniform
            .sample_iter(&mut rand::rng())
            .take(len)
            .collect()
    }

    #[derive(PartialEq, PartialOrd, Ord, Clone, Eq, Hash)]
    struct Temp {
        id: Vec<u8>,
    }

    #[test]
    fn time_size_struct_value() {
        let size = 100usize;
        let time_to_live = Duration::from_millis(100);

        let mut lru_cache = LruCache::<Temp, usize>::new(time_to_live, size);

        for i in 0..1000 {
            if i < size {
                assert_eq!(lru_cache.len(), i);
            }

            let _ = lru_cache.insert(
                Temp {
                    id: generate_random_vec::<u8>(64),
                },
                i,
            );

            if i < size {
                assert_eq!(lru_cache.len(), i + 1);
            } else {
                assert_eq!(lru_cache.len(), size);
            }
        }

        advance_time_by_ms(101);
        let _ = lru_cache.insert(
            Temp {
                id: generate_random_vec::<u8>(64),
            },
            1,
        );

        assert_eq!(lru_cache.len(), 1);
    }

    #[test]
    fn update_time_check() {
        let time_to_live = Duration::from_millis(500);
        let mut lru_cache = LruCache::<usize, usize>::new(time_to_live, usize::MAX);

        assert_eq!(lru_cache.len(), 0);
        let _ = lru_cache.insert(0, 0);
        assert_eq!(lru_cache.len(), 1);

        advance_time_by_ms(300);
        assert_eq!(Some(&0), lru_cache.get(&0));
        advance_time_by_ms(300);
        assert_eq!(Some(&0), lru_cache.peek(&0));
        advance_time_by_ms(300);
        assert_eq!(None, lru_cache.peek(&0));
    }

    #[test]
    fn update_time_check_entry() {
        let time_to_live = Duration::from_millis(500);
        let mut lru_cache = LruCache::<usize, usize>::new(time_to_live, usize::MAX);

        assert_eq!(lru_cache.len(), 0);
        let _ = lru_cache.insert(0, 0);
        assert_eq!(lru_cache.len(), 1);

        advance_time_by_ms(300);
        lru_cache.entry(0, true);
        advance_time_by_ms(300);
        assert_eq!(Some(&0), lru_cache.peek(&0));
        advance_time_by_ms(300);
        assert_eq!(None, lru_cache.peek(&0));
    }

    mod remove_expired {
        use super::*;

        #[test]
        fn it_removes_expired_entries_from_the_map() {
            let ttl = Duration::from_millis(200);
            let mut lru_cache = LruCache::<usize, usize>::new(ttl, usize::MAX);
            let _ = lru_cache.insert(1, 1);
            let _ = lru_cache.insert(2, 2);
            advance_time_by_ms(150);
            let _ = lru_cache.insert(3, 3);
            let _ = lru_cache.insert(4, 4);
            advance_time_by_ms(60);

            let _ = lru_cache.remove_expired();

            assert_eq!(lru_cache.map.len(), 2);
            assert_eq!(lru_cache.map[&3].data, 3);
            assert_eq!(lru_cache.map[&4].data, 4);
        }

        #[test]
        fn it_removes_expired_entries_from_the_list() {
            let ttl = Duration::from_millis(200);
            let mut lru_cache = LruCache::<usize, usize>::new(ttl, usize::MAX);
            let _ = lru_cache.insert(1, 1);
            let _ = lru_cache.insert(2, 2);
            advance_time_by_ms(150);
            let _ = lru_cache.insert(3, 3);
            let _ = lru_cache.insert(4, 4);
            advance_time_by_ms(60);

            let _ = lru_cache.remove_expired();

            assert_eq!(lru_cache.map.len(), 2);
            assert_eq!(*lru_cache.map.iter().nth(0).unwrap().0, 3);
            assert_eq!(*lru_cache.map.iter().nth(1).unwrap().0, 4);
        }

        #[test]
        fn it_returns_expired_entries() {
            let ttl = Duration::from_millis(200);
            let mut lru_cache = LruCache::<usize, usize>::new(ttl, usize::MAX);
            let _ = lru_cache.insert(1, 1);
            let _ = lru_cache.insert(2, 2);
            advance_time_by_ms(150);
            let _ = lru_cache.insert(3, 3);
            advance_time_by_ms(60);

            let (_, expired) = lru_cache.remove_expired();

            assert_eq!(expired.len(), 2);
            assert_eq!(expired[0], 1);
            assert_eq!(expired[1], 2);
        }
    }

    // End of copied tests

    mod proptests {
        use super::*;

        use lru_time_cache::LruCache as OldLruCache;
        use proptest::prelude::*;
        use proptest_derive::Arbitrary;

        // Small set of keys to make it more likely to detect any issues
        #[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        enum Key {
            A,
            B,
            C,
            D,
            E,
        }

        // List of possible operations that can be performed on the lru cache
        #[derive(Arbitrary, Debug)]
        enum Op {
            Insert(Key),
            Get(Key),
            GetMut(Key),
            Peek(Key),
            Remove(Key),
            GetUsingEntry(Key),
            GetMutUsingEntry(Key),
            Sleep(u8),
        }

        fn verify_equality(new: &mut LruCache<Key, u32>, old: &mut OldLruCache<Key, u32>) {
            assert_eq!(new.is_empty_slow(), old.is_empty());
            assert_eq!(new.len_slow(), old.len());
            let keys: Vec<_> = new.map.keys().collect();
            for key in keys {
                assert_eq!(new.peek(&key), old.peek(&key));
            }
        }

        proptest! {
            #[test]
            fn test_same_behaviour_as_the_old_external_lru_cache(init: (u8, u8), ops: Vec<Op>) {
                let ttl = Duration::from_secs(1 + init.0 as u64);
                let capacity = 1 + init.1 as usize;
                let mut new = LruCache::<Key, u32>::new(ttl, capacity);
                let mut old = OldLruCache::<Key, u32>::with_expiry_duration_and_capacity(ttl, capacity);

                for op in ops {
                    match op {
                        Op::Insert(k) => {
                            new.insert(k, k as u32);
                            old.insert(k, k as u32);
                        },
                        Op::Get(k) => {
                            assert_eq!(new.get(&k), old.get(&k));
                        },
                        Op::GetMut(k) => {
                            let new_val = new.get_mut(&k);
                            let old_val = old.get_mut(&k);
                            assert_eq!(new_val, old_val);
                            if let (Some(new_val), Some(old_val)) = (new_val, old_val) {
                                *new_val += 1;
                                *old_val += 1;
                            }
                        },
                        Op::Peek(k) => {
                            assert_eq!(new.peek(&k), old.peek(&k));
                        },
                        Op::Remove(k) => {
                            new.remove(&k);
                            old.remove(&k);
                        },
                        Op::GetUsingEntry(k) => {
                            let new_val = match new.entry(k, true) {
                                Entry::Occupied(mut e) => {
                                    Some(*e.get_mut())
                                },
                                Entry::Vacant(_) => {
                                    None
                                }
                            };
                            assert_eq!(new_val, old.get(&k).copied());
                        },
                        Op::GetMutUsingEntry(k) => {
                            if let Entry::Occupied(mut e) = new.entry(k, true) {
                                *e.get_mut() += 1;
                            }
                            if let Some(v) = old.get_mut(&k) {
                                *v += 1;
                            }
                        },
                        Op::Sleep(t) => {
                            advance_time_by_ms(t as u64 * 1000);
                        }
                    }
                    verify_equality(&mut new, &mut old);
                }
            }
        }
    }
}
