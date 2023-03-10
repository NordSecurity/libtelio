use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
};

/// Usefull extentions for map types.
pub trait MapExt<K, V> {
    /// Update map to have same keys as in provided keys iterator.
    /// If key does not exists use op to create one.
    fn update<I, F>(&mut self, keys: I, op: F)
    where
        I: IntoIterator<Item = K>,
        F: for<'a> FnMut(&'a K) -> V + 'static;
}

impl<K, V> MapExt<K, V> for HashMap<K, V>
where
    K: Clone + Hash + Eq,
{
    fn update<I, F>(&mut self, keys: I, mut op: F)
    where
        I: IntoIterator<Item = K>,
        F: for<'a> FnMut(&'a K) -> V + 'static,
    {
        let from: HashSet<_> = self.keys().cloned().collect();
        let to: HashSet<_> = keys.into_iter().collect();

        let del = &from - &to;
        for k in del {
            self.remove(&k);
        }
        let add = &to - &from;
        for k in add {
            let v = op(&k);
            self.insert(k, v);
        }
    }
}
