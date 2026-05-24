use lru::LruCache;
use std::num::NonZeroUsize;

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
}

impl CacheStats {
    pub fn new() -> Self {
        Self { hits: 0, misses: 0 }
    }
}

impl Default for CacheStats {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AnalysisCache<T> {
    cache: LruCache<String, T>,
    stats: CacheStats,
}

impl<T: Clone> AnalysisCache<T> {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).expect("capacity must be non-zero");
        Self {
            cache: LruCache::new(cap),
            stats: CacheStats::new(),
        }
    }

    pub fn get(&mut self, key: &str) -> Option<T> {
        if let Some(value) = self.cache.get(key) {
            self.stats.hits += 1;
            return Some(value.clone());
        }
        self.stats.misses += 1;
        None
    }

    pub fn put(&mut self, key: String, value: T) {
        self.cache.put(key, value);
    }

    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }
}

