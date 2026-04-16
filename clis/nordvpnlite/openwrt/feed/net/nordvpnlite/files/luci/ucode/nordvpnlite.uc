'use strict';

const CONFIG_FILE = '/etc/nordvpnlite/config.json';
const INIT_SCRIPT = '/etc/init.d/nordvpnlite';
const SERVICE_NAME = 'nordvpnlite';
const SERVERS_API_URL = 'https://api.nordvpn.com/v1/servers?limit=20000';
const VALID_ACTIONS = ['start', 'stop', 'restart', 'reload', 'enable', 'disable'];
const SERVER_LOOKUP_TIMEOUT = 45;
let fs = require('fs');
let log = require('log');

function has_service() {
	let st = fs.stat(INIT_SCRIPT);
	return st && st.type == 'file' && st.user_exec != false;
}

function service_action(action) {
	return system(sprintf('env -i %s %s >/dev/null 2>&1', INIT_SCRIPT, action));
}

function shell_quote(value) {
	if (value == null || value == '')
		return "''";

	return "'" + replace(value, "'", "'\\''") + "'";
}

function has_command(command) {
	return system(sprintf('command -v %s >/dev/null 2>&1', command)) == 0;
}

function read_command_output(command) {
	let pp = fs.popen(command, 'r');
	if (!pp)
		return null;

	let output = pp.read('all');
	let exit_code = pp.close();

	if (exit_code != 0 || output == null)
		return null;

	return trim(output);
}

function fetch_server_data_with_jq(hostname) {
	let url = shell_quote(SERVERS_API_URL);
	let jq_filter = shell_quote(
		'first(.[] | select(.hostname == $h) | {' +
			'hostname,' +
			'address: .station,' +
			'supports_wireguard_udp: ([.technologies[] | select(.identifier == "wireguard_udp")] | length > 0),' +
			'public_key: ([.technologies[] | select(.identifier == "wireguard_udp") | .metadata[] | select(.name == "public_key") | .value][0])' +
		'})'
	);
	let quoted_hostname = shell_quote(hostname);
	let commands = [];

	if (!has_command('jq'))
		return {
			server: null,
			error: 'jq is required for NordVPN server lookup.'
		};

	if (has_command('curl')) {
		push(commands, sprintf(
			'curl --connect-timeout 10 --max-time %d -sS %s 2>/dev/null | jq -c -r --arg h %s %s 2>/dev/null',
			SERVER_LOOKUP_TIMEOUT, url, quoted_hostname, jq_filter
		));
	}

	if (has_command('uclient-fetch')) {
		push(commands, sprintf(
			'uclient-fetch -qO- %s 2>/dev/null | jq -c -r --arg h %s %s 2>/dev/null',
			url, quoted_hostname, jq_filter
		));
	}

	if (has_command('wget')) {
		push(commands, sprintf(
			'wget -T %d -qO- %s 2>/dev/null | jq -c -r --arg h %s %s 2>/dev/null',
			SERVER_LOOKUP_TIMEOUT, url, quoted_hostname, jq_filter
		));
	}

	if (!length(commands)) {
		return {
			server: null,
			error: 'No supported HTTP client found (curl, uclient-fetch or wget).'
		};
	}

	for (let command in commands) {
		let output = read_command_output(command);

		if (!output)
			continue;

		try {
			return {
				server: json(output),
				error: null
			};
		} catch (e) {
			log.ERR('Failed to parse NordVPN server lookup response: %J', e);
		}
	}

	return {
		server: null,
		error: sprintf('Lookup timed out or failed for %s.', hostname)
	};
}

function fetch_countries() {
	if (!has_command(SERVICE_NAME)) {
		return {
			countries: null,
			error: sprintf('%s command not found.', SERVICE_NAME)
		};
	}

	let output = read_command_output(sprintf('%s countries 2>/dev/null', SERVICE_NAME));
	let countries = [];

	if (!output) {
		return {
			countries: null,
			error: sprintf('Unable to read available countries from %s.', SERVICE_NAME)
		};
	}

	for (let line in split(output, /\r?\n/)) {
		let entry = trim(line);
		let parts = null;

		if (entry == '')
			continue;

		parts = match(entry, /^(.*):\s*([A-Z]{2})$/);
		if (!parts)
			continue;

		push(countries, {
			name: trim(parts[1]),
			code: parts[2]
		});
	}

	if (!length(countries)) {
		return {
			countries: null,
			error: sprintf('No countries returned by %s.', SERVICE_NAME)
		};
	}

	return {
		countries: countries,
		error: null
	};
}

function fetch_runtime_status() {
	if (!has_command(SERVICE_NAME)) {
		return {
			status: null,
			error: sprintf('%s command not found.', SERVICE_NAME)
		};
	}

	let output = read_command_output(sprintf('%s status 2>/dev/null', SERVICE_NAME));

	if (!output) {
		return {
			status: null,
			error: sprintf('Unable to read %s runtime status.', SERVICE_NAME)
		};
	}

	try {
		return {
			status: json(output),
			error: null
		};
	} catch (e) {
		log.ERR('Failed to parse nordvpnlite status output: %J', e);
		return {
			status: null,
			error: sprintf('Unable to parse %s status output.', SERVICE_NAME)
		};
	}
}

return {
	nordvpnlite: {
		get_config: {
			call: function() {
				let content = null;
				try {
					content = json(fs.readfile(CONFIG_FILE));
				} catch (e) {
					log.ERR("Failed to read config file: %J", e);
				}
				return { config: content };
			}
		},

		set_config: {
			args: { config: {} },
			call: function(req) {
				const tmp = CONFIG_FILE + '.tmp';
				if (fs.writefile(tmp, sprintf('%.2J', req.args.config)) == null) {
					log.ERR("Failed to write temp file");
					fs.unlink(tmp);
					return { success: false, error: fs.error() };
				}
				if (fs.rename(tmp, CONFIG_FILE) == null) {
					log.ERR("Failed to move temp file");
					fs.unlink(tmp);
					return { success: false, error: fs.error() };
				}
				return { success: true };
			}
		},

		get_service_status: {
			call: function() {
				if (!has_service()) {
					return {
						installed: false,
						enabled: false,
						running: false
					};
				}

				return {
					installed: true,
					enabled: service_action('enabled') == 0,
					running: service_action('running') == 0
				};
			}
		},

		set_service_action: {
			args: { action: 'action' },
			call: function(req) {
				let action = null;

				if (req && req.args)
					action = req.args.action;

				if (index(VALID_ACTIONS, action) < 0) {
					return {
						success: false,
						error: sprintf('Invalid action: %s', action || '')
					};
				}

				if (!has_service()) {
					return {
						success: false,
						error: sprintf('Init script not found: %s', INIT_SCRIPT)
					};
				}

				let result = service_action(action);

				return {
					success: result == 0,
					action: action,
					exit_code: result,
					service: SERVICE_NAME
				};
			}
		},

		get_server_data: {
			args: { hostname: '' },
			call: function(req) {
				let hostname = '';
				let fetch_result = null;
				let server = null;
				let fetch_error = null;

				if (req && req.args && req.args.hostname != null)
					hostname = trim(req.args.hostname);

				if (hostname == '') {
					return {
						success: false,
						error: 'Server hostname is required.'
					};
				}

				fetch_result = fetch_server_data_with_jq(hostname);
				server = fetch_result ? fetch_result.server : null;
				fetch_error = fetch_result ? fetch_result.error : null;

				if (fetch_error) {
					return {
						success: false,
						error: fetch_error
					};
				}

				if (!server) {
					return {
						success: false,
						error: sprintf('Server not found or lookup timed out for %s.', hostname)
					};
				}

				if (server.supports_wireguard_udp !== true) {
					return {
						success: false,
						error: sprintf('Server %s does not support wireguard_udp.', hostname)
					};
				}

				if (!server.public_key) {
					return {
						success: false,
						error: sprintf('No WireGuard public key found for %s.', hostname)
					};
				}

				return {
					success: true,
					hostname: server.hostname,
					address: server.address,
					public_key: server.public_key
				};
			}
		},

		get_countries: {
			call: function() {
				let result = fetch_countries();
				let countries = result ? result.countries : null;
				let error = result ? result.error : null;

				if (error || !countries) {
					return {
						success: false,
						error: error || sprintf('Unable to query available countries from %s.', SERVICE_NAME)
					};
				}

				return {
					success: true,
					countries: countries
				};
			}
		},

		get_runtime_status: {
			call: function() {
				let result = fetch_runtime_status();
				let status = result ? result.status : null;
				let error = result ? result.error : null;

				if (error || !status) {
					return {
						success: false,
						error: error || sprintf('Unable to query %s runtime status.', SERVICE_NAME)
					};
				}

				return {
					success: true,
					telio_is_running: status.telio_is_running == true,
					ip_address: status.ip_address || '',
					exit_node: {
						identifier: status.exit_node && status.exit_node.identifier ? status.exit_node.identifier : '',
						public_key: status.exit_node && status.exit_node.public_key ? status.exit_node.public_key : '',
						hostname: status.exit_node && status.exit_node.hostname ? status.exit_node.hostname : '',
						endpoint: status.exit_node && status.exit_node.endpoint ? status.exit_node.endpoint : '',
						state: status.exit_node && status.exit_node.state ? status.exit_node.state : ''
					}
				};
			}
		}
	}
};
