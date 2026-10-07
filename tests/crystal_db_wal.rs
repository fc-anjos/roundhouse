//! Crystal production DB opens with WAL + a sized pool (#17).
//!
//! `runtime/crystal/db.cr::open_production_db` must set journal_mode=WAL
//! (and synchronous=NORMAL) on every pooled connection via the
//! crystal-sqlite3 URI, and size the crystal-db pool from
//! `DATABASE_POOL_SIZE` / CPU count. Without both, readers serialize
//! on the rollback journal or starve on a one-connection idle pool.
//!
//! Requires `crystal` + network for `shards install` (sqlite3 shard).
//! Marked `#[ignore]` like the other crystal toolchain gates.
//!
//!     cargo test --test crystal_db_wal -- --ignored --nocapture

use std::path::PathBuf;
use std::process::Command;

fn scratch_dir() -> PathBuf {
    let base = option_env!("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join(format!("roundhouse-crystal-db-wal-{}", std::process::id()))
}

#[test]
#[ignore]
fn open_production_db_enables_wal_and_honors_pool_size() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let scratch = scratch_dir();
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(scratch.join("src")).unwrap();

    // Minimal shard + driver that pulls in Roundhouse::Db and probes
    // the production open path against a file DB (WAL needs a file).
    std::fs::write(
        scratch.join("shard.yml"),
        "name: crystal_db_wal\nversion: 0.1.0\ndependencies:\n  sqlite3:\n    github: crystal-lang/crystal-sqlite3\n",
    )
    .unwrap();
    std::fs::copy(
        root.join("runtime/crystal/db.cr"),
        scratch.join("src/db.cr"),
    )
    .unwrap();

    let db_path = scratch.join("probe.sqlite3");
    let main = format!(
        r#"
require "./db"

path = {path:?}
Roundhouse::Db.open_production_db(path, "CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY);")

mode = Roundhouse::Db.conn.query_one("PRAGMA journal_mode", as: String)
sync = Roundhouse::Db.conn.query_one("PRAGMA synchronous", as: Int64)
pool = Roundhouse::Db.prod_pool_size

raise "journal_mode=#{{mode}} want wal" unless mode.downcase == "wal"
# NORMAL == 1
raise "synchronous=#{{sync}} want 1 (NORMAL)" unless sync == 1
raise "prod_pool_size=#{{pool}} want 4 from DATABASE_POOL_SIZE" unless pool == 4

puts "OK wal=#{{mode}} sync=#{{sync}} pool=#{{pool}}"
"#,
        path = db_path,
    );
    std::fs::write(scratch.join("src/probe.cr"), main).unwrap();

    let shards = Command::new("shards")
        .arg("install")
        .current_dir(&scratch)
        .output()
        .expect("shards install");
    assert!(
        shards.status.success(),
        "shards install failed:\n{}\n{}",
        String::from_utf8_lossy(&shards.stdout),
        String::from_utf8_lossy(&shards.stderr)
    );

    let out = Command::new("crystal")
        .args(["run", "src/probe.cr"])
        .current_dir(&scratch)
        .env("DATABASE_POOL_SIZE", "4")
        .env("CRYSTAL_CACHE_DIR", scratch.join(".crystal-cache"))
        .output()
        .expect("crystal run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.contains("OK wal="),
        "crystal probe failed:\n=== stdout ===\n{stdout}\n=== stderr ===\n{stderr}"
    );
}
