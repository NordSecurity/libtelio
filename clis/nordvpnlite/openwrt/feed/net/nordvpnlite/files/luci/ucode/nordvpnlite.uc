'use strict';

const CONFIG_FILE = '/etc/nordvpnlite/config.json';
const NORDVPNLITE_BIN = '/usr/bin/nordvpnlite';
let fs = require('fs');
let log = require('log');

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
				if (type(token) != 'string' || length(token) == 0) {
					return { success: false, error: 'Missing authentication token' };
				}

				// Store the token in the separate auth file via the login command.
				// The token is passed on stdin to avoid exposing it in the process
				// list (argv is world-readable via /proc).
				const cmd = sprintf(
					"%s login --config-file %s --token \"$(cat)\"",
					NORDVPNLITE_BIN, CONFIG_FILE
				);
				let proc = fs.popen(cmd, 'w');
				if (proc == null) {
					log.ERR("Failed to spawn login command: %J", fs.error());
					return { success: false, error: fs.error() };
				}
				proc.write(token);
				const rc = proc.close();
				if (rc != 0) {
					log.ERR("login command failed with code %d", rc);
					return { success: false, error: sprintf('login command failed (code %d)', rc) };
				}
				return { success: true };
			}
		},

		logout: {
			call: function() {
				const cmd = sprintf("%s logout --config-file %s", NORDVPNLITE_BIN, CONFIG_FILE);
				let proc = fs.popen(cmd, 'r');
				if (proc == null) {
					log.ERR("Failed to spawn logout command: %J", fs.error());
					return { success: false, error: fs.error() };
				}
				proc.read('all');
				const rc = proc.close();
				if (rc != 0) {
					log.ERR("logout command failed with code %d", rc);
					return { success: false, error: sprintf('logout command failed (code %d)', rc) };
				}
				return { success: true };
			}
		}
	}
};
