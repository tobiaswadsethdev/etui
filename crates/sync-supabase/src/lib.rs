use etui_core::ports::SyncProvider;

pub struct SupabaseSyncProvider;

impl SupabaseSyncProvider {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for SupabaseSyncProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
fn _assert_trait_object(_: &dyn SyncProvider) {}
