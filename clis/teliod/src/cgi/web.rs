//! Code for serving static web ui

use std::{collections::HashMap, fs, str::FromStr};

use lazy_static::lazy_static;
use maud::{html, Markup, Render};
use rust_cgi::{
    http::{header::CONTENT_TYPE, Method},
    Response,
};
use telio::telio_model::mesh::{Node, NodeState};
use telio::telio_utils::telio_log_debug;
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
            ("/static/style.css", ("text/css", asset!("style.css"))),
            ("/static/output.css", ("text/css", asset!("output.css"))),
            (
                "/static/tailwind.config.js",
                ("text/javascript", asset!("tailwind.config.js")),
            ),
            (
                "/static/tailwindcss.js",
                ("text/javascript", asset!("tailwindcss.js")),
            ),
            ("/static/fonts/inter-v18-latin-100.woff2", ("font/ttf", asset!("fonts/inter-v18-latin-100.woff2"))),
            ("/static/fonts/inter-v18-latin-900.woff2", ("font/ttf", asset!("fonts/inter-v18-latin-900.woff2"))),
            ("/static/fonts/inter-v18-latin-regular.woff2", ("font/ttf", asset!("fonts/inter-v18-latin-regular.woff2"))),
            ("/static/htmx.js", ("text/javascript", asset!("htmx.js"))),            
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
        }
        (&Method::GET, "/card") => render(card(&AppState::collect())),
        (&Method::POST, "/card") => {
            let mut app = AppState::collect();
            
            update_config(&mut app, request);

            if !app.running {
                let res = start_daemon();
                warn!(
                    "start: {}",
                    std::str::from_utf8(res.body()).unwrap_or_default()
                )
            } else {
                stop_daemon();
            };

            render(card(&AppState::collect()))
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
    let app = AppState::collect();
    html! {
        html lang="en" {
            head {
                meta charset="UTF-8";
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                title { "Nord Security Meshnet" }
                base href=(base_ref);

                script src="static/tailwind.config.js" {}                
                link rel="stylesheet" href="static/output.css" {}
                link rel="stylesheet" href="static/style.css" {}
                script src="static/htmx.js" {}
                script src="static/telio.js" {}
            }
            body class="bg-neutral-100 dark:bg-neutral-1000  py-10 flex items-center justify-center min-h-screen gap-3" {
                (card(&app))
            }
        }
    }
}

fn card(app: &AppState) -> Markup {
    html! {
        (config_card(app))

        // Status Card (only when running)
        @if app.running {
            (status_card(app))
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

fn config_card(app: &AppState) -> Markup {
    let log_options = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"];
    let curr_level = app
        .config
        .log_level
        .into_level()
        .unwrap_or(Level::INFO)
        .as_str();

    let is_running = app.running;    

    let divclass = if is_running {
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
                label class="inline-flex items-center cursor-pointer" {
                    span id="toggleLabel" class="mr-2 text-primary body-xs-bold" {( if is_running { "On" } else { "Off" })};                    
                    input type="checkbox" checked?[is_running] class="sr-only peer" {}
                    div class=({divclass}) hx-on:click="document.getElementById('config').requestSubmit()" {}
                }
            }
            // Inputs
            form id="config" hx-post="card" hx-target="body" {
                div class="flex flex-col gap-4" {
                    div class="space-y-2" {
                        label class="block text-primary body-xs-medium" { "Access Token" }
                        input name=(ACCESS_TOKEN) type="password" class="w-full px-4 py-3 bg-transparent text-primary border border-input rounded-sm focus-visible:outline-none focus-visible:shadow-focus" value=(app.config.authentication_token) "hx-on:htmx:validation:validate"="telio.validateToken(this)";
                    }
                    div class="flex flex-col gap-2" {
                        div class="space-y-2" {
                            label class="block text-primary body-xs-medium" { "Tunnel Name" }
                            input name=(TUNNEL_NAME) type="text" class="w-full px-4 py-3 bg-transparent text-primary border border-input rounded-sm focus-visible:outline-none focus-visible:shadow-focus" value=(app.config.interface.name) "hx-on:htmx:validation:validate"="telio.validateTunnel(this)";
                        }
                    }
                    div class="space-y-2" {
                        label class="block text-primary body-xs-medium" { "Log Level" }
                        div class="relative" {
                            select name=(LOG_LEVEL) class="w-full px-4 py-3 bg-transparent text-primary border border-input rounded-sm appearance-none focus-visible:outline-none focus-visible:shadow-focus" {
                                @for opt in &log_options {
                                    @if *opt == curr_level {
                                        option value=(opt) selected="true" { (opt) }
                                    } @else {
                                        option value=(opt) { (opt) }
                                    }
                                }
                            }
                            div class="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-primary" {
                                svg class="fill-current h-4 w-4" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" {
                                    path d="M9.293 12.95l.707.707L15.657 8l-1.414-1.414L10 10.828 5.757 6.586 4.343 8z" {}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn status_card(app: &AppState) -> Markup {
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

    let meshnet_status_text = format!(
        "Meshnet Status ({})",
        status
            .meshnet_ip
            .map(|ip| format!("{}", ip))
            .unwrap_or_default()
    );

    html! {
                div class="bg-neutral-0 dark:bg-[#1C1F2B] border border-secondary max-w-[768px] mx-auto w-full p-6 rounded-md flex flex-col gap-6" {
                    div class="flex justify-between items-center" {
                      span class="text-primary body-md-medium" { ({meshnet_status_text}) }
                      a href="get-teliod-logs" class="body-xs-medium text-accent hover:text-blue-400 active:text-blue-700 dark:hover:text-blue-400 dark:active:text-blue-700" {"Logs"}
                    }

                    @for node in &status.external_nodes {
                    div class="flex flex-col gap-4" {
                      div class="w-full flex items-center justify-between rounded-sm bg-transparent border border-secondary p-4" {
                        div class="flex items-center space-x-4" {
                          div class="flex items-center justify-center" {
                             svg width="40" height="40" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg" {
                              path
                                d="M26 14H14C13.4477 14 13 14.4477 13 15H12C12 13.8954 12.8954 13 14 13H26C27.1046 13 28 13.8954 28 15V25H29C29.5523 25 30 25.4477 30 26C30 26.5523 29.5523 27 29 27H22V25H27V15C27 14.4477 26.5523 14 26 14Z"
                                class="dark:fill-neutral-0 fill-neutral-1000" {}
                              path
                                d="M20 26C20 25.4477 20.4477 25 21 25H29C29.5523 25 30 25.4477 30 26C30 26.5523 29.5523 27 29 27H21C20.4477 27 20 26.5523 20 26Z"
                                class="dark:fill-neutral-0 fill-neutral-1000" {}
                              path d="M12.5 17C12.2239 17 12 16.7761 12 16.5L12 15H13V16.5C13 16.7761 12.7761 17 12.5 17Z"
                              class="dark:fill-neutral-0 fill-neutral-1000" {}
                              path fill-rule="evenodd" clip-rule="evenodd"
                                d="M15.395 19.2798C15.7355 18.9339 15.9062 18.5603 15.9062 18.1601C15.9062 18.107 15.9034 18.0535 15.8964 18C15.6593 18.0105 15.4071 18.072 15.1405 18.1833C14.8734 18.2961 14.6531 18.4377 14.4798 18.6079C14.1329 18.9441 13.9375 19.3552 13.9375 19.7394C13.9375 19.7925 13.9415 19.843 13.9483 19.891C14.4872 19.9285 14.9842 19.6909 15.395 19.2798ZM17.2073 25.845C17.4012 25.5697 17.5686 25.2703 17.71 24.945C17.7682 24.8071 17.8231 24.6634 17.875 24.5134C17.6355 24.4134 17.4203 24.2726 17.2275 24.0904C16.8022 23.6979 16.5858 23.2035 16.5794 22.6094C16.5725 21.8467 16.9205 21.2521 17.624 20.8276C17.231 20.2713 16.64 19.9625 15.8534 19.8992C15.5632 19.8747 15.2088 19.937 14.789 20.0875C14.345 20.2497 14.0832 20.3311 14.0059 20.3311C13.9025 20.3311 13.6668 20.2615 13.2996 20.1242C12.9315 19.9875 12.6352 19.9179 12.4092 19.9179C11.9963 19.9247 11.6129 20.0316 11.2581 20.2414C10.9032 20.4512 10.6197 20.7369 10.4066 21.0992C10.1354 21.5501 10 22.0883 10 22.7123C10 23.257 10.1004 23.8197 10.3007 24.4007C10.4878 24.9387 10.7265 25.4105 11.0169 25.8174C11.2876 26.1985 11.5135 26.4675 11.6941 26.6244C11.9771 26.8864 12.2606 27.0112 12.5451 26.9991C12.7321 26.9928 12.9768 26.929 13.2804 26.8066C13.5836 26.6847 13.8671 26.6244 14.1314 26.6244C14.3834 26.6244 14.659 26.6847 14.959 26.8066C15.2579 26.929 15.5147 26.9893 15.7276 26.9893C16.0243 26.9824 16.3013 26.8612 16.5598 26.6244C16.7266 26.4801 16.943 26.2203 17.2073 25.845Z"
                                class="dark:fill-neutral-0 fill-neutral-1000" {}
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
