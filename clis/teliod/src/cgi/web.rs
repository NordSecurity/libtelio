//! Code for serving static web ui

use std::{collections::HashMap, fs, str::FromStr};
use telio::telio_utils::hidden::Hidden;

use crate::cgi::constants::TELIOD_START_INTENT_FILE;
use crate::TeliodDaemonConfig;
use crate::{
    cgi::constants::TELIOD_CFG,
    config::{InterfaceConfig, TeliodDaemonConfigPartial},
};
use lazy_static::lazy_static;
use maud::{html, Markup, Render};
use rust_cgi::{
    http::{header::CONTENT_TYPE, Method},
    Response,
};
use telio::telio_model::mesh::{Node, NodeState};
use tracing::{error, info, level_filters::LevelFilter, Level};

use super::{
    api::{start_daemon, stop_daemon},
    app::AppState,
    CgiRequest,
};
use anyhow::{anyhow, Result};

macro_rules! asset {
    ($path:literal) => {
        &include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/", $path))[..]
    };
}

lazy_static! {
    static ref ASSETS: HashMap<&'static str, (&'static str, &'static [u8])> = {
        [
            ("/static/telio.js", ("text/javascript", asset!("telio.js"))),
            ("/static/style.css", ("text/css", asset!("style.css"))),
            (
                "/static/meshnet_icon.svg",
                ("image/svg+xml", asset!("meshnet_icon.svg")),
            ),
            ("/static/output.css", ("text/css", asset!("output.css"))),
            (
                "/static/fonts/inter-v18-latin-100.woff2",
                ("font/ttf", asset!("fonts/inter-v18-latin-100.woff2")),
            ),
            (
                "/static/fonts/inter-v18-latin-500.woff2",
                ("font/ttf", asset!("fonts/inter-v18-latin-500.woff2")),
            ),
            (
                "/static/fonts/inter-v18-latin-600.woff2",
                ("font/ttf", asset!("fonts/inter-v18-latin-600.woff2")),
            ),
            (
                "/static/fonts/inter-v18-latin-900.woff2",
                ("font/ttf", asset!("fonts/inter-v18-latin-900.woff2")),
            ),
            (
                "/static/fonts/inter-v18-latin-regular.woff2",
                ("font/ttf", asset!("fonts/inter-v18-latin-regular.woff2")),
            ),
            ("/static/htmx.js", ("text/javascript", asset!("htmx.js"))),
        ]
        .into_iter()
        .collect()
    };
}

fn save_user_intent(enable_meshnet: bool) {
    if enable_meshnet {
        if let Err(e) = std::fs::File::create(TELIOD_START_INTENT_FILE) {
            eprintln!(
                "Error creating intent file at '{}': {}. Not considered a failure",
                TELIOD_START_INTENT_FILE, e
            );
        }
    } else if let Err(e) = std::fs::remove_file(TELIOD_START_INTENT_FILE) {
        if e.kind() != std::io::ErrorKind::NotFound {
            eprintln!(
                "Error deleting intent file at '{}': {}. Not considered a failure",
                TELIOD_START_INTENT_FILE, e
            );
        }
    }
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
        }
        (&Method::GET, "/meshnet") => render(meshnet(&AppState::collect())),
        (&Method::POST, "/meshnet") => {
            let mut app = AppState::collect();

            let mut err_msg: Option<String> = None;

            if !app.running {
                // TODO: For the future improvement it makes sense to have separate
                // endpoints - one for modifying config and another one for daemon control
                let updated_config = update_config(&mut app, request);

                match updated_config {
                    Err(e) => {
                        error!("update config: {:?}", e);
                        err_msg = Some(e.to_string())
                    }
                    Ok(_) => {
                        let res = start_daemon();
                        info!("start: {} -> {}", res.0, res.1);
                        if !res.0.is_success() {
                            err_msg = Some(res.1);
                        } else {
                            save_user_intent(true);
                        }
                    }
                }
            } else {
                let res = stop_daemon();
                info!("stop: {} -> {}", res.0, res.1);
                if !res.0.is_success() {
                    err_msg = Some(res.1);
                } else {
                    save_user_intent(false);
                }
            };

            render(view(&AppState::collect(), err_msg))
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

                link rel="stylesheet" href="static/output.css" {}
                link rel="stylesheet" href="static/style.css" {}
                script src="static/htmx.js" {}
                script src="static/telio.js" {}
                link rel="icon" type="image/svg+xml" href="static/meshnet_icon.svg" {}
            }
            body class="bg-neutral-100 dark:bg-neutral-1000  py-10 flex items-top justify-start justify-center min-h-screen gap-3" {
                (view(&AppState::collect(), None))
            }
        }
    }
}

fn view(app: &AppState, error: Option<String>) -> Markup {
    html! {
        (config_view(app, error))

        @if app.running {
            (meshnet(app))
        }
    }
}

const ACCESS_TOKEN: &str = "access-token";
const TUNNEL_NAME: &str = "interface-name";
const LOG_LEVEL: &str = "log-level";

/// Try to update persisted config
fn update_config(app: &mut AppState, request: &CgiRequest) -> Result<TeliodDaemonConfig> {
    // TODO: should probably be Result, creating error report for a user in web
    let Some(ctype) = request
        .headers()
        .get("x-cgi-content-type")
        .and_then(|v| v.to_str().ok())
    else {
        return Err(anyhow!("x-cgi-content-type header not found"));
    };

    if ctype != "application/x-www-form-urlencoded" {
        return Err(anyhow!("Expected to receive form data, got: {}", ctype));
    }

    let values: HashMap<_, _> = form_urlencoded::parse(request.body()).collect();

    let partial = TeliodDaemonConfigPartial {
        // Empty token submitted means we don't update it.
        // this means we do not provide a way to clear it on this endpoint
        authentication_token: match values.get(ACCESS_TOKEN) {
            Some(token) if !token.to_string().trim().is_empty() => Some(Hidden(token.to_string())),
            _ => None,
        },
        log_level: values
            .get(LOG_LEVEL)
            .and_then(|v| LevelFilter::from_str(v).ok()),
        interface: values.get(TUNNEL_NAME).map(|name| InterfaceConfig {
            name: name.to_string(),
            config_provider: app.config.interface.config_provider.clone(),
        }),
        ..Default::default()
    };

    info!("Got new values: {partial:#?}");

    // Build a new temprorary config
    let mut new_config = app.config.clone();
    new_config.update(partial);

    let config = match serde_json::to_string_pretty(&new_config) {
        Ok(c) => c,
        Err(err) => {
            return Err(anyhow!("Failed to serialize config, err: {err}"));
        }
    };

    match fs::write(TELIOD_CFG, config) {
        Ok(_) => {
            app.config = new_config.clone();
        }
        Err(err) => {
            return Err(anyhow!(
                "Failed to persist a new config into {TELIOD_CFG}, err: {err}"
            ));
        }
    }

    Ok(new_config)
}

fn config_view(app: &AppState, error: Option<String>) -> Markup {
    #[cfg(debug_assertions)]
    let log_options = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"];
    #[cfg(not(debug_assertions))]
    let log_options = ["INFO", "WARN", "ERROR"];

    let curr_level = app
        .config
        .log_level
        .into_level()
        .unwrap_or(Level::INFO)
        .as_str();

    let is_running = app.running;

    let toggle_class = if is_running {
        "relative w-11 h-6 bg-gray-200 darkpeer-focus-visible:outline-none peer-focus-visible:shadow-focus rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"
    } else {
        "relative w-11 h-6 bg-gray-200 darkpeer-focus-visible:outline-none peer-focus-visible:shadow-focus rounded-full peer after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all"
    };

    html! {
        div id="card" class="bg-neutral-0 dark:bg-[#1C1F2B] border border-secondary max-w-[768px] mx-auto w-full p-6 rounded-md flex flex-col gap-6" {
            div class="flex justify-between items-center" {
                div class="flex items-center space-x-3" {
                    svg width="40" height="40" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg" {
                        path d="M0 6C0 2.68629 2.68629 0 6 0H34C37.3137 0 40 2.68629 40 6V34C40 37.3137 37.3137 40 34 40H6C2.68629 40 0 37.3137 0 34V6Z" class="dark:fill-blue-400 fill-blue-100" {}
                        path d="M26.5963 17.1273C26.0157 17.1273 25.4852 17.2974 25.0248 17.5777L22.5024 15.0553C22.8127 14.5849 23.0029 14.0143 23.0029 13.4037C23.0029 11.7422 21.6616 10.4009 20 10.4009C18.3384 10.4009 16.9971 11.7422 16.9971 13.4037C16.9971 14.0243 17.1873 14.5949 17.4976 15.0653L14.9852 17.5777C14.5248 17.2874 13.9843 17.1173 13.4037 17.1173C11.7422 17.1173 10.4009 18.4585 10.4009 20.1201C10.4009 21.7817 11.7422 23.123 13.4037 23.123C14.0543 23.123 14.6449 22.9128 15.1354 22.5724L17.4976 24.9347C17.1773 25.4151 16.9971 25.9757 16.9971 26.5963C16.9971 28.2578 18.3384 29.5991 20 29.5991C21.6616 29.5991 23.0029 28.2578 23.0029 26.5963C23.0029 25.9857 22.8227 25.4252 22.5124 24.9547L24.8746 22.5925C25.3651 22.9328 25.9557 23.143 26.5963 23.143C28.2578 23.143 29.5991 21.8017 29.5991 20.1401C29.5991 18.4786 28.2578 17.1373 26.5963 17.1373V17.1273ZM20 23.5934C19.3894 23.5934 18.8189 23.7736 18.3484 24.0939L15.9562 21.7016C16.2364 21.2412 16.4066 20.7107 16.4066 20.1301C16.4066 19.4895 16.1964 18.899 15.8561 18.4085L18.3484 15.9161C18.8189 16.2264 19.3894 16.4066 19.99 16.4066C20.5906 16.4066 21.1711 16.2164 21.6516 15.9061L24.1439 18.3985C23.7936 18.8889 23.5934 19.4795 23.5934 20.1301C23.5934 20.7107 23.7636 21.2512 24.0539 21.7116L21.6616 24.1039C21.1811 23.7836 20.6106 23.6034 20 23.6034V23.5934ZM20 11.602C20.9909 11.602 21.8017 12.4128 21.8017 13.4037C21.8017 14.3947 20.9909 15.2054 20 15.2054C19.0091 15.2054 18.1983 14.3947 18.1983 13.4037C18.1983 12.4128 19.0091 11.602 20 11.602ZM11.602 20.1301C11.602 19.1392 12.4128 18.3284 13.4037 18.3284C14.3947 18.3284 15.2054 19.1392 15.2054 20.1301C15.2054 21.1211 14.3947 21.9318 13.4037 21.9318C12.4128 21.9318 11.602 21.1211 11.602 20.1301ZM20 28.398C19.0091 28.398 18.1983 27.5872 18.1983 26.5963C18.1983 25.6053 19.0091 24.7946 20 24.7946C20.9909 24.7946 21.8017 25.6053 21.8017 26.5963C21.8017 27.5872 20.9909 28.398 20 28.398ZM26.5963 21.9318C25.6053 21.9318 24.7946 21.1211 24.7946 20.1301C24.7946 19.1392 25.6053 18.3284 26.5963 18.3284C27.5872 18.3284 28.398 19.1392 28.398 20.1301C28.398 21.1211 27.5872 21.9318 26.5963 21.9318Z" class="dark:fill-blue-900 fill-blue-600" {}
                    }
                    span class="text-primary body-md-medium" { "Nord Security Meshnet" }
                }
                a href="https://meshnet.nordvpn.com" class="text-accent body-xs-medium hover:text-blue-400 active:text-blue-700 dark:hover:text-blue-400 dark:active:text-blue-700" {
                    "Docs"
                    span class="ml-2 inline-block" { "›" }
                }
            }
            hr class="border-neutral-200 dark:border-neutral-800";
            div class="flex justify-between items-center" {
                span class="text-primary body-md-medium" { "Configuration" }
                div class="inline-flex items-center cursor-pointer" {
                    span id="toggleLabel" class="mr-2 text-primary body-xs-bold" {( if is_running { "On" } else { "Off" })};
                    input type="checkbox" checked?[is_running] class="sr-only peer" {}
                    div class=({toggle_class}) hx-on:click="htmx.trigger('#config', 'submit'); document.getElementById('config').reportValidity();" {}
                }
            }
            // Inputs
            form id="config" hx-post="meshnet" hx-target="body" class="mb-0" {
                button type="submit" class="hidden" {}
                div class="flex flex-col gap-4" {
                    div class="space-y-2" {
                        label class="block text-primary body-xs-medium" { "Access Token" }
                        (if is_running {
                            html!{input disabled name=(ACCESS_TOKEN) type="password" class="text-disabled w-full px-4 py-3 bg-transparent text-primary border border-input rounded-sm focus-visible:outline-none focus-visible:shadow-focus" "hx-on:htmx:validation:validate"="telio.validateToken(this)";}
                        } else {
                            html!{input name=(ACCESS_TOKEN) type="password" class="w-full px-4 py-3 bg-transparent text-primary border border-input rounded-sm focus-visible:outline-none focus-visible:shadow-focus" "hx-on:htmx:validation:validate"="telio.validateToken(this)";}
                        })
                    }
                    div class="flex flex-col gap-2" {
                        div class="space-y-2" {
                            label class="block text-primary body-xs-medium" { "Tunnel Name" }
                            (if is_running {
                                html!{input disabled name=(TUNNEL_NAME) type="text" class="text-disabled w-full px-4 py-3 bg-transparent text-primary border border-input rounded-sm focus-visible:outline-none focus-visible:shadow-focus" value=(app.config.interface.name) "hx-on:htmx:validation:validate"="telio.validateTunnel(this)";}
                            } else {
                                html!{input name=(TUNNEL_NAME) type="text" class="w-full px-4 py-3 bg-transparent text-primary border border-input rounded-sm focus-visible:outline-none focus-visible:shadow-focus" value=(app.config.interface.name) "hx-on:htmx:validation:validate"="telio.validateTunnel(this)";}
                            })
                        }
                    }
                    div class="space-y-2" {
                        label class="block text-primary body-xs-medium" { "Log Level" }
                        div class="relative" {
                            (if is_running {
                                html! {
                                    select disabled name=(LOG_LEVEL) class="text-disabled w-full px-4 py-3 bg-transparent text-primary border border-input rounded-sm appearance-none focus-visible:outline-none focus-visible:shadow-focus" {
                                        @for opt in &log_options {
                                            @if *opt == curr_level {
                                                option value=(opt) selected="true" { (opt) }
                                            } @else {
                                                option value=(opt) { (opt) }
                                            }
                                        }
                                    }
                                }
                            } else {
                                html! {
                                    select name=(LOG_LEVEL) class="w-full px-4 py-3 bg-transparent text-primary border border-input rounded-sm appearance-none focus-visible:outline-none focus-visible:shadow-focus" {
                                        @for opt in &log_options {
                                            @if *opt == curr_level {
                                                option value=(opt) selected="true" { (opt) }
                                            } @else {
                                                option value=(opt) { (opt) }
                                            }
                                        }
                                }
                                }
                            })

                            div class="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-primary" {
                                svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" {
                                    path fill-rule="evenodd" clip-rule="evenodd" d="M12 14.5L8 9.5L16 9.5L12 14.5Z" fill="#2A2B32" {}
                                }
                            }
                        }
                    }
                }
            }

            // Error message if needed
            @if let Some(error) = error {
                div class="rounded-sm flex items-center p-4 mb-4 text-critical border border-critical rounded-xs bg-critical-subtle" role="alert" {
                    svg class="w-4 h-4 mr-2 text-critical" width="16" height="18" viewBox="0 0 16 18" fill="none" xmlns="http://www.w3.org/2000/svg" {
                      path d="M14.2576 13.0249L8.92513 3.9249C8.72013 3.5749 8.36013 3.3999 8.00013 3.3999C7.64013 3.3999 7.28013 3.5749 7.05263 3.9249L1.72264 13.0249C1.33539 13.7224 1.84641 14.5999 2.66864 14.5999H13.3336C14.1526 14.5999 14.6651 13.7249 14.2576 13.0249ZM2.91464 13.3999L7.97763 4.7199L13.0851 13.3999H2.91464ZM8.00013 11.0274C7.56613 11.0274 7.21413 11.3794 7.21413 11.8134C7.21413 12.2474 7.56688 12.5994 8.00113 12.5994C8.43538 12.5994 8.78613 12.2474 8.78613 11.8134C8.78513 11.3799 8.43513 11.0274 8.00013 11.0274ZM7.40013 7.1999V9.5999C7.40013 9.9324 7.67013 10.1999 8.00013 10.1999C8.33013 10.1999 8.60013 9.93115 8.60013 9.5999V7.1999C8.60013 6.8699 8.33263 6.5999 8.00013 6.5999C7.66763 6.5999 7.40013 6.8699 7.40013 7.1999Z" fill="#9E1C10" {}
                    }

                    span class="body-xs-medium" {({error})}
                }
            }
        }
    }
}

fn meshnet(app: &AppState) -> Markup {
    let Some(status) = &app.status else {
        return html!();
    };

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

    let peer_status = |node: &Node| match node.state {
        NodeState::Disconnected => {
            html! {span class="px-3 py-1 body-xs-medium text-critical bg-critical-subtle rounded-full"{"Disconnected"}}
        }
        NodeState::Connecting => {
            html! {span class="px-3 py-1 body-xs-medium text-primary bg-tertiary rounded-full" {"Connecting..."}}
        }
        NodeState::Connected => {
            html! {span class="px-3 py-1 body-xs-medium text-success bg-success-subtle rounded-full" {"Connected"}}
        }
    };

    let meshnet_status_text = if status.meshnet_ip.is_none() {
        "Connecting..."
    } else {
        &format!(
            "Meshnet Status ({})",
            status
                .meshnet_ip
                .map(|ip| format!("{}", ip))
                .unwrap_or_default()
        )
    };

    html! {
        div class="bg-neutral-0 dark:bg-[#1C1F2B] border border-secondary max-w-[768px] mx-auto w-full p-6 rounded-md flex flex-col gap-6"
            hx-get="meshnet"
            hx-trigger="every 10s"
            hx-swap="outerHTML"
            {
            div class="flex justify-between items-center" {
                span class="text-primary body-md-medium" { ({meshnet_status_text}) }
                a href="get-logs" class="body-xs-medium text-accent hover:text-blue-400 active:text-blue-700 dark:hover:text-blue-400 dark:active:text-blue-700" {"Logs"}
            }

            div class="flex flex-col gap-4" {
                @for node in &status.external_nodes {
                    div class="w-full flex items-center justify-between rounded-sm bg-transparent border border-secondary p-4" {
                    div class="flex items-center space-x-4" {
                        div class="flex items-center justify-center px-2" {
                            svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" {
                                path stroke-linecap="round"
                                    stroke-linejoin="round"
                                    stroke-width="2"
                                    d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
                                    {}
                            }
                        }
                        div {
                            p class="text-primary body-sm-medium" { ({node_name(node)}) }
                            p class="text-tertiary body-xs-medium" { ({show_address(node)}) }
                        }
                    }
                    ({peer_status(node)})
                    }
                }
            }
        }
    }
}
