use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

// `main` stays synchronous so we can call `handoff::detect_role()` before
// any tokio worker thread starts. The handoff library mutates env vars
// (HANDOFF_ROLE, LISTEN_FDS, ...) under an unsafe single-threaded-startup
// contract; running it from inside `#[tokio::main]` would violate that.
fn main() -> anyhow::Result<()> {
    beyond_auth::cli::run()
}
