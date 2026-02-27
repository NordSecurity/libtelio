'use strict';

const CONFIG_FILE = '/etc/nordvpnlite/config.json';
let fs = require('fs');

return {
	nordvpnlite: {
		get_config: {
			call: function() {
				let content = null;
				try {
					content = json(fs.readfile(CONFIG_FILE));
				} catch (e) {}
				return { config: content };
			}
		},

		set_config: {
			args: { config: {} },
			call: function(req) {
				const tmp = CONFIG_FILE + '.tmp';
				if (fs.writefile(tmp, sprintf('%.2J', req.args.config)) == null)
					fs.unlink(tmp);
					return { success: false, error: fs.error() };
				if (fs.rename(tmp, CONFIG_FILE) == null)
					fs.unlink(tmp);
					return { success: false, error: fs.error() };
				return { success: true };
			}
		}
	}
};
