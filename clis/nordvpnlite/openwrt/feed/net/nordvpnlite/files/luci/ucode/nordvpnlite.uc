'use strict';

const CONFIG_FILE = '/etc/nordvpnlite/config.json';
const INIT_SCRIPT = '/etc/init.d/nordvpnlite';
const SERVICE_NAME = 'nordvpnlite';
const UCI_CONFIG = 'nordvpnlite';
const UCI_SECTION = 'settings';
const VALID_ACTIONS = ['start', 'stop', 'restart', 'reload', 'enable', 'disable'];
let fs = require('fs');
let log = require('log');

function has_service() {
	let st = fs.stat(INIT_SCRIPT);
	return st && st.type == 'file' && st.user_exec != false;
}

function service_action(action) {
	return system(sprintf('env -i %s %s >/dev/null 2>&1', INIT_SCRIPT, action));
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

function config_enabled() {
	let value = read_command_output(sprintf('uci -q get %s.%s.enabled 2>/dev/null', UCI_CONFIG, UCI_SECTION));

	if (value == null || value == '')
		return true;

	switch (lc(trim(value))) {
		case '0':
		case 'off':
		case 'false':
		case 'no':
		case 'disabled':
			return false;
		default:
			return true;
	}
}

function write_config_enabled(enabled) {
	let value = enabled ? '1' : '0';

	return system(sprintf(
		"uci -q set %s.%s=settings >/dev/null 2>&1 && " +
		"uci -q set %s.%s.enabled='%s' >/dev/null 2>&1 && " +
		"uci -q commit %s >/dev/null 2>&1",
		UCI_CONFIG, UCI_SECTION,
		UCI_CONFIG, UCI_SECTION, value,
		UCI_CONFIG
	)) == 0;
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

		get_config_enabled: {
			call: function() {
				return { enabled: config_enabled() };
			}
		},

		set_config_enabled: {
			args: { enabled: true },
			call: function(req) {
				let enabled = true;

				if (req && req.args)
					enabled = (req.args.enabled == true || req.args.enabled == 1 || req.args.enabled == '1');

				if (!write_config_enabled(enabled)) {
					return {
						success: false,
						error: sprintf('Unable to write /etc/config/%s.', UCI_CONFIG)
					};
				}

				return {
					success: true,
					enabled: enabled
				};
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
					config_enabled: config_enabled(),
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
