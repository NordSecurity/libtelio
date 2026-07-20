'use strict';
'require view';
'require form';
'require rpc';
'require ui';

var callGetConfig = rpc.declare({
    object: 'nordvpnlite',
    method: 'get_config'
});

var callSetConfig = rpc.declare({
    object: 'nordvpnlite',
    method: 'set_config',
    params: ['config']
});

var callLogin = rpc.declare({
    object: 'nordvpnlite',
    method: 'login',
    params: ['token']
});

var callLogout = rpc.declare({
    object: 'nordvpnlite',
    method: 'logout'
});

var defaultConfig = {
    auth_file_path: '/etc/nordvpnlite/auth.json',
    vpn: 'recommended',
    log_level: 'error',
    log_file_path: '/var/log/nordvpnlite.log',
    log_file_count: 0,
    adapter_type: 'linux-native',
    interface: {
        name: 'nordvpnlite',
        max_route_priority: 6000,
        config_provider: 'uci'
    }
};

return view.extend({
    load: function () {
        return callGetConfig().then(function (result) {
            return result.config || defaultConfig;
        });
    },

    render: function (config) {
        this.config = config;

        var form_data = {
            auth: {
                authentication_token: ""
            },
            config: {
                vpn: this.config.vpn === "recommended" ? "" : this.config.vpn.country
            }
        };

        var m = new form.JSONMap(form_data, _('NordVPN Lite'),
            _('Configure your NordVPN Lite connection settings.'));

        var auth_section = m.section(form.NamedSection, 'auth', 'auth', _('Authentication'));

        var o = this.authentication_token_option = auth_section.option(form.Value, 'authentication_token', _('Authentication Token'));
        o.password = true;
        o.placeholder = _('Enter your Nord Account authentication token');
        o.description = _('Leave empty to keep the currently stored token, or enter a new token to replace it.');

        var s = m.section(form.NamedSection, 'config', 'config', _('Settings'));

        o = this.vpn_option = s.option(form.Value, 'vpn', _('Country Code'));
        o.placeholder = _('recommended');
        o.description = _('Leave empty for recommended server, or enter a country code (e.g., US, DE, GB).');
        o.validate = function (_, value) {
            return (value.length === 0 || value.length === 2) ? true : 'Please provide a two-letter country code.';
        }

        return m.render();
    },

    handleSave: async function () {
        if (!this.vpn_option.isValid('config')) {
            ui.addNotification(_('Save failed'), E('p', _('Incorrect format of the country code')));
            return
        }

        const token = String(this.authentication_token_option.formvalue('auth') || '').trim();
        const vpn = String(this.vpn_option.formvalue('config') || '').trim();

        delete this.config.authentication_token;

        if (vpn === '') {
            this.config.vpn = 'recommended';
        } else {
            this.config.vpn = { country: vpn };
        }

        try {
            const res = await callSetConfig(this.config);
            if (!res || res.success !== true) {
                ui.addNotification(_('Save failed'), E('p', _('Could not write config file.')));
                return;
            }
        } catch (err) {
            ui.addNotification(_('Save failed'), E('p', err ? String(err) : _('Unknown error')));
            return;
        }

        // Store the token separately via the login command, which writes it to the auth file.
        // An empty field keeps the previously stored token.
        if (token !== '') {
            try {
                const authRes = await callLogin(token);
                if (!authRes || authRes.success !== true) {
                    ui.addNotification(_('Save failed'), E('p',
                        (authRes && authRes.error) ? String(authRes.error) : _('Could not store authentication token.')));
                    return;
                }
            } catch (err) {
                ui.addNotification(_('Save failed'), E('p', err ? String(err) : _('Unknown error')));
                return;
            }
        }

        ui.addNotification(_('Saved'), E('p', _('Configuration updated.')));
    },

    handleSaveApply: null,
    handleReset: null
});
