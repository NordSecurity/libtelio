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

var defaultConfig = {
    authentication_token: '<REPLACE_WITH_YOUR_TOKEN>',
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
            config: {
                authentication_token: this.config.authentication_token === "<REPLACE_WITH_YOUR_TOKEN>" ? "" : this.config.authentication_token,
                vpn: this.config.vpn === "recommended" ? "" : this.config.vpn
            }
        };

        var m = new form.JSONMap(form_data, _('NordVPN Lite'),
            _('Configure your NordVPN Lite connection settings.'));

        var s = m.section(form.NamedSection, 'config');

        var o = this.authentication_token_option = s.option(form.Value, 'authentication_token', _('Authentication Token'));
        o.password = true;
        o.placeholder = _('Enter your Nord Account authentication token');

        o = this.vpn_option = s.option(form.Value, 'vpn', _('Country Code'));
        o.placeholder = _('recommended');
        o.description = _('Leave empty for recommended server, or enter a country code (e.g., US, DE, UK).');
        o.validate = function (_, value) {
            return value.length === 2 ? true : 'Please provide a two-letter country code.';
        }

        return m.render();
    },

    handleSave: async function () {
        const token = String(this.authentication_token_option.formvalue('config') || '').trim();
        const vpn = String(this.vpn_option.formvalue('config') || '').trim().toUpperCase();

        if (token) {
            this.config.authentication_token = token;
        }

        if (vpn) {
            this.config.vpn = vpn;
        }

        try {
            const res = await callSetConfig(this.config);
            if (!res || res.success !== true)
                ui.addNotification(_('Save failed'), E('p', _('Could not write config file.')));
            else
                ui.addNotification(_('Saved'), E('p', _('Configuration updated.')));
        } catch (err) {
            ui.addNotification(_('Save failed'), E('p', err ? String(err) : _('Unknown error')));
        }

        return callSetConfig(config);
    },

    handleSaveApply: null,
    handleReset: null
});
