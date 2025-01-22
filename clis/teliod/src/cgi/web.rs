//! Code for serving static web ui

use std::{collections::HashMap, fs, str::FromStr};

use lazy_static::lazy_static;
use maud::{html, Markup, Render};
use rust_cgi::{
    http::{header::CONTENT_TYPE, Method},
    Response,
};
use telio::telio_model::mesh::{Node, NodeState};
use tracing::{level_filters::LevelFilter, warn, Level};

use crate::{
    cgi::constants::TELIOD_CFG,
    config::{InterfaceConfig, TeliodDaemonConfigPartial},
};

use super::{
    api::{start_daemon, stop_daemon},
    app::AppState,
    CgiRequest,
};

macro_rules! asset {
    ($path:literal) => {
        &include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/", $path))[..]
    };
}

lazy_static! {
    static ref ASSETS: HashMap<&'static str, (&'static str, &'static [u8])> = {
        [
            ("/static/telio.js", ("text/javascript", asset!("telio.js"))),
            (
                "/static/spinner.svg",
                ("image/svg+xml", asset!("spinner.svg")),
            ),
            ("/static/tailwindcss.js", ("text/javascript", asset!("tailwindcss.js"))),
            ("/static/htmx.js", ("text/javascript", asset!("htmx.js"))),
            ("/static/fonts/Inter_18pt-Regular.ttf", ("font/ttf", asset!("fonts/Inter_18pt-Regular.ttf"))),
            ("/static/fonts/Inter_18pt-Medium.ttf", ("font/ttf", asset!("fonts/Inter_18pt-Medium.ttf"))),
            ("/static/fonts/Inter_18pt-SemiBold.ttf", ("font/ttf", asset!("fonts/Inter_18pt-SemiBold.ttf"))),
        ]
        .into_iter()
        .collect()
    };
}

pub fn handle_web_ui(request: &CgiRequest) -> Option<Response> {
    let render = |markup: Markup| {
        let mut resp = Response::new(markup.render().into_string().into_bytes());
        resp.headers_mut()
            .insert(CONTENT_TYPE, "text/html".parse().ok()?);
        Some(resp)
    };

    match (request.method(), request.route()) {
        (&Method::GET, "" | "/") => {
            let base_ref = format!("{}/teliod.cgi", request.uri().path());
            render(index(base_ref))
        },
        (&Method::GET, "/pannel") => render(pannel(&AppState::collect())),
        (&Method::GET, "/pannel/status") => render(status(&AppState::collect())),
        (&Method::POST, "/pannel") => {
            let mut app = AppState::collect();
            update_config(&mut app, request);

            // TODO: need quite a bit of cleanup, api should probably be mostly removed
            if !app.running {
                let res = start_daemon();
                warn!(
                    "start: {}",
                    std::str::from_utf8(res.body()).unwrap_or_default()
                )
            } else {
                stop_daemon();
            };

            render(pannel(&AppState::collect()))
        }
        (&Method::GET, route) => {
            let (mime, data) = ASSETS.get(route)?;
            let mut resp = Response::new(data.to_vec());
            resp.headers_mut().insert(CONTENT_TYPE, mime.parse().ok()?);
            Some(resp)
        }
        _ => None,
    }
}

fn index(base_ref: String) -> Markup {
    html! {
        html lang="en" {
            head {
                meta charset="UTF-8";
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                title { "Nord Security Meshnet" }
                base href=(base_ref);
                
                script src="static/tailwindcss.js" {}
                script {
                    "tailwind.config = {"
                    "darkMode: 'class',"
                    "theme: {"
                    "extend: {"
                    "colors: {"
                    "'nord-blue': '#5E81AC',"
                    "'nord-green': '#A3BE8C',"
                    "'nord-orange': '#D08770'"
                    "}" "}" "}" "}";
                }
                script src="static/htmx.js" {}
                style {
                    "@font-face { font-family: 'Inter'; src: url('static/fonts/Inter_18pt-Regular.ttf') format('truetype'); font-weight: 400; font-style: normal; }"
                    "@font-face { font-family: 'Inter'; src: url('static/fonts/Inter_18pt-Medium.ttf') format('truetype'); font-weight: 500; font-style: normal; }"
                    "@font-face { font-family: 'Inter'; src: url('static/fonts/Inter-SemiBold.ttf') format('truetype'); font-weight: 600; font-style: normal; }"
                    "body { font-family: 'Inter', sans-serif; }"
                    ".htmx-indicator { display: none; }"
                    ".htmx-request .htmx-indicator { display: inline; }"
                    ".htmx-request.htmx-indicator { display: inline; }"
                }
                script src="static/telio.js" {}
            }
            body class="bg-gray-900 text-gray-100 min-h-screen p-8" {
                div class="max-w-2xl mx-auto space-y-6" {
                    div class="bg-gray-800 rounded-lg p-4 flex items-center justify-between" {
                        div class="flex items-center space-x-3" {
                            div class="w-10 h-10 bg-nord-blue rounded-lg flex items-center justify-center" {
                                svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" {
                                    path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z";
                                }
                            }
                            h1 class="text-xl font-semibold" { "Nord Security Meshnet" }
                        }
                        a href="https://meshnet.nordvpn.com/" class="text-nord-blue hover:underline" { "Docs >" }
                    }
                    div id="pannel" hx-get="pannel" hx-trigger="load" {}
                }
            }
        }
    }
}

fn pannel(app: &AppState) -> Markup {
    html! {
        (config(app))
        @if app.running {
            (status(app))
        }
    }
}

const ACCESS_TOKEN: &str = "access-token";
const TUNNEL_NAME: &str = "interface-name";
const LOG_LEVEL: &str = "log-level";

/// Try to update persisted config
fn update_config(app: &mut AppState, request: &CgiRequest) {
    // TODO: should probably be Result, creating error report for a user in web
    let Some(ctype) = request
        .headers()
        .get("x-cgi-content-type")
        .and_then(|v| v.to_str().ok())
    else {
        warn!("x-cgi-content-type header not found");
        return;
    };

    if ctype != "application/x-www-form-urlencoded" {
        warn!("Expected to recieve form data, got: {}", ctype);
        return;
    }

    let values: HashMap<_, _> = form_urlencoded::parse(request.body()).collect();

    let partial = TeliodDaemonConfigPartial {
        authentication_token: values.get(ACCESS_TOKEN).map(ToString::to_string),
        log_level: values
            .get(LOG_LEVEL)
            .and_then(|v| LevelFilter::from_str(v).ok()),
        interface: values.get(TUNNEL_NAME).map(|name| InterfaceConfig {
            name: name.to_string(),
            config_provider: app.config.interface.config_provider.clone(),
        }),
        ..Default::default()
    };

    warn!("Got new values: {partial:#?}");

    // Build a new temprorary config
    let mut new_config = app.config.clone();
    new_config.update(partial);

    let config = match serde_json::to_string_pretty(&new_config) {
        Ok(c) => c,
        Err(err) => {
            warn!("Failed to serialize config, err: {err}");
            return;
        }
    };

    match fs::write(TELIOD_CFG, config) {
        Ok(_) => {
            app.config = new_config;
        }
        Err(err) => {
            warn!("Failed to persist a new config into {TELIOD_CFG}, err: {err}");
        }
    }
}

fn config(app: &AppState) -> Markup {
    html! {
        div class="bg-gray-800 rounded-lg p-4" {
            div class="flex items-center justify-between mb-4" {
                div class="flex items-center space-x-3" {
                    div class={
                        "w-6 h-6 rounded-full "
                        (if app.running { "bg-nord-green" } else { "bg-nord-orange" })
                        } {}
                    h2 class="text-lg font-medium" { "Configuration" }
                }
                button class="bg-nord-blue
                        text-white 
                        px-4 py-2 
                        rounded-md 
                        hover:bg-blue-600 
                        transition"
                    hx-on:click="htmx.trigger('#config', 'submit')" {
                    span {
                        @if app.running {
                            "Stop"
                        } @else {
                            "Start"
                        }
                    }
                    img #config-load
                        class="htmx-indicator h-6 ml-4"
                        src="static/spinner.svg"
                        {}
                }
            }

            div."space-y-4" {
                (config_form(app))
            }
        }
    }
}

fn config_form(app: &AppState) -> Markup {
    let label_style = "block text-sm font-medium mb-1";
    let input_style = "w-full
        bg-gray-700 
        border border-gray-600 rounded-md 
        px-3 py-2 
        focus:outline-none focus:ring-2 focus:ring-nord-blue
        mb-2";
    let log_options = [
        #[cfg(debug_assertions)]
        Level::TRACE.as_str(),
        #[cfg(debug_assertions)]
        Level::DEBUG.as_str(),
        Level::INFO.as_str(),
        Level::WARN.as_str(),
        Level::ERROR.as_str(),
    ];
    let level = app
        .config
        .log_level
        .into_level()
        .unwrap_or(if cfg!(debug_assertions) {
            Level::TRACE
        } else {
            Level::INFO
        });

    html! {
        form #config hx-post="pannel" hx-target="#pannel" hx-indicator="#config-load" {
            label for=(ACCESS_TOKEN)
                class=(label_style) {
                "Access Token:"
            }
            input type="password"
                class=(input_style)
                id=(ACCESS_TOKEN)
                name=(ACCESS_TOKEN)
                value=(app.config.authentication_token)
                "hx-on:htmx:validation:validate"="telio.validateToken(this)"
                {}

            label for=(TUNNEL_NAME)
                class=(label_style) {
                "Tunnel Name:"
            }
            input type="text"
                class=(input_style)
                id=(TUNNEL_NAME)
                name=(TUNNEL_NAME)
                value=(app.config.interface.name)
                "hx-on:htmx:validation:validate"="telio.validateTunnel(this)"
                {}

            label for=(LOG_LEVEL)
                class=(label_style) {
                "Log Level"
            }
            // Validation not need option ensures correctness
            select class=(input_style)
                name=(LOG_LEVEL)
                id=(LOG_LEVEL) {
                @for option in log_options {
                    @if option == level.as_str() {
                        option value=(option) selected = "true" {
                            (option)
                        }
                    } @else {
                        option value=(option) {
                            (option)
                        }
                    }
                }
            }
        }
    }
}

fn status(app: &AppState) -> Markup {
    let Some(status) = &app.status else {
        return html!();
    };

    let my_ip = status
        .meshnet_ip
        .map(|ip| format!("( {ip} )"))
        .unwrap_or_default();

    let node_name = |node: &Node| match (&node.nickname, &node.hostname) {
        (None, None) => "unknown".to_string(),
        (None, Some(host)) => host.to_string(),
        (Some(nick), None) => nick.to_string(),
        (Some(nick), Some(host)) => format!("{nick} ({host})"),
    };

    let show_address = |node: &Node| {
        node.ip_addresses
            .first()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    };

    let status_color = |node: &Node| match node.state {
        NodeState::Disconnected => "text-nord-orange",
        NodeState::Connecting => "text-nord-orange",
        NodeState::Connected => "text-nord-green",
    };

    let status_text = |node: &Node| match node.state {
        NodeState::Disconnected => "Disconnected",
        NodeState::Connecting => "Connecting",
        NodeState::Connected => "Connected",
    };

    html! {
        div id="status" class="bg-gray-800 rounded-lg p-4 mt-6"
            hx-get="pannel/status"
            hx-trigger="every 2s"
            hx-swap="outerHTML" {
            div class="flex items-center justify-between mb-4" {
                h2 class="text-lg font-medium" {
                    {"Meshnet Status " (my_ip)}
                }
                a href="get-teliod-logs" class="text-nord-blue hover:underline" { "Logs >" }
            }
            div class="space-y-3" {
                @for node in &status.external_nodes {
                    div class="bg-gray-700 rounded-lg p-3 flex items-center justify-between" {
                        div class="flex items-center space-x-3" {
                            div class="w-8 h-8 bg-gray-600 rounded-lg flex items-center justify-center" {
                                (device_icon())
                            }
                            div {
                                div class="font-medium" { ({node_name(node)}) }
                                div class="text-sm text-gray-400" { ({show_address(node)}) }
                            }
                        }
                        div class={"text-nord-green " ({status_color(node)})} {
                            "Status: " ({status_text(node)})
                        }
                    }
                }
            }
        }
    }
}

fn device_icon() -> Markup {
    html! {
        svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" {
            path stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
                {}
        }
    }
}
