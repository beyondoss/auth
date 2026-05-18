//! Integration tests for `beyond-auth`'s `handoff` integration.
//!
//! Each scenario spawns the real `beyond-auth` binary as a child process
//! with an inherited listener fd, then drives the handoff protocol through
//! an in-process `handoff::Supervisor`. The point is to exercise the same
//! moving parts production uses — `detect_role`, `DataDirLock`,
//! `Incumbent::serve`, the accept-pause-without-close loop, the
//! `AuthDrainable` bridge — not a toy fixture.
//!
//! Tests are deliberately `#[test]` (not `#[tokio::test]`): the supervisor
//! protocol is synchronous and the HTTP client (`ureq`) is blocking, so
//! pulling in tokio just adds noise.

mod external_supervisor;
mod harness;
mod scenarios;
