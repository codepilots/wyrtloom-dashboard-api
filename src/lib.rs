//! Library surface of `wyrtloom-dashboard-api`, exposed so integration tests can
//! exercise the router, auth middleware, and session machinery without spawning
//! a real server. The binary (`main.rs`) is a thin CLI/bootstrap wrapper over
//! these modules.

pub mod auth;
pub mod routes;
pub mod session;
pub mod state;
