'use strict';

const CONFIG_FILE = '/etc/nordvpnlite/config.json';
const INIT_SCRIPT = '/etc/init.d/nordvpnlite';
const NORDVPNLITE_BIN = '/usr/sbin/nordvpnlite';
const SERVICE_NAME = 'nordvpnlite';
const COMMAND_TIMEOUT_SECONDS = 30;
const VALID_ACTIONS = ['start', 'stop', 'restart', 'reload', 'enable', 'disable'];
let fs = require('fs');
let log = require('log');

function has_service() {
	let st = fs.stat(INIT_SCRIPT);
	return st && st.type == 'file' && st.perm && st.perm.user_exec;
}

function service_action(action) {
	return system(sprintf('env -i %s %s >/dev/null 2>&1', INIT_SCRIPT, action));
}

function has_nordvpnlite() {
	let st = fs.stat(NORDVPNLITE_BIN);
	return st && st.type == 'file' && st.perm && st.perm.user_exec;
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

function fetch_countries() {
	if (!has_nordvpnlite()) {
		return {
			countries: null,
			error: sprintf('%s command not found.', NORDVPNLITE_BIN)
		};
	}

	let output = read_command_output(sprintf(
		'timeout %d %s countries 2>/dev/null',
		COMMAND_TIMEOUT_SECONDS, NORDVPNLITE_BIN
	));
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
	if (!has_nordvpnlite()) {
		return {
			status: null,
			error: sprintf('%s command not found.', NORDVPNLITE_BIN)
		};
	}

	let output = read_command_output(sprintf(
		'timeout %d %s status 2>/dev/null',
		COMMAND_TIMEOUT_SECONDS, NORDVPNLITE_BIN
	));

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

		login: {
			args: { token: '' },
			call: function(req) {
				const token = req.args.token;
				if (type(token) != 'string' || length(token) == 0)
					return { success: false, error: 'Missing authentication token' };

				// Pass the token through stdin so it is not visible in /proc/*/cmdline.
				const cmd = sprintf(
					'%s login --config-file %s --token "$(cat)"',
					NORDVPNLITE_BIN, CONFIG_FILE
				);
				let proc = fs.popen(cmd, 'w');
				if (proc == null) {
					log.ERR('Failed to spawn login command: %J', fs.error());
					return { success: false, error: fs.error() };
				}

				proc.write(token);
				const rc = proc.close();
				if (rc != 0) {
					log.ERR('login command failed with code %d', rc);
					return { success: false, error: sprintf('login command failed (code %d)', rc) };
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
				if (!has_service()) {
					return {
						success: false,
						error: sprintf('Init script not found: %s', INIT_SCRIPT)
					};
				}

				if (service_action('running') != 0) {
					return {
						success: true,
						running: false,
						telio_is_running: false,
						ip_address: '',
						exit_node: {}
					};
				}

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
					running: true,
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
