#![cfg_attr(docsrs, feature(doc_cfg))]
mod route;

pub mod endpoint_providers;
pub(crate) mod paths;
pub mod route_type;
pub(crate) mod router;
pub mod routes;

pub use paths::PathSetIo;
pub use router::{Config, ConfigBuilder, Error, Router};

pub use routes::*;

pub use route::{Configure, Error as RouteError, Route, RouteResult};
