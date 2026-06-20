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

var callGetConfigEnabled = rpc.declare({
    object: 'nordvpnlite',
    method: 'get_config_enabled'
});

var callSetConfigEnabled = rpc.declare({
    object: 'nordvpnlite',
    method: 'set_config_enabled',
    params: ['enabled']
});

var callGetServiceStatus = rpc.declare({
    object: 'nordvpnlite',
    method: 'get_service_status'
});

var callSetServiceAction = rpc.declare({
    object: 'nordvpnlite',
    method: 'set_service_action',
    params: ['action']
});

var callGetCountries = rpc.declare({
    object: 'nordvpnlite',
    method: 'get_countries'
});

var callGetRuntimeStatus = rpc.declare({
    object: 'nordvpnlite',
    method: 'get_runtime_status'
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

function isObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function callGetCountriesWithTimeout() {
    var previousTimeout = L.env.rpctimeout;

    L.env.rpctimeout = Math.max(L.env.rpctimeout || 20, 30);

    return Promise.resolve(callGetCountries()).finally(function () {
        L.env.rpctimeout = previousTimeout;
    });
}

function callGetRuntimeStatusWithTimeout() {
    var previousTimeout = L.env.rpctimeout;

    L.env.rpctimeout = Math.max(L.env.rpctimeout || 20, 30);

    return Promise.resolve(callGetRuntimeStatus()).finally(function () {
        L.env.rpctimeout = previousTimeout;
    });
}

return view.extend({
    getCountryChoices: function (selectedCode) {
        var countries = Array.isArray(this.countryChoices) ? this.countryChoices : [];
        var code = String(selectedCode || '').trim().toUpperCase();
        var choices = {
            '': this.countryChoicesLoaded === true
                ? _('Select a country')
                : _('Type a country code or click Get country list')
        };
        var seen = {};

        countries.forEach(function (country) {
            var countryCode;
            var countryName;

            if (!isObject(country))
                return;

            countryCode = String(country.code || '').trim().toUpperCase();
            countryName = String(country.name || '').trim();

            if (countryCode === '' || seen[countryCode] === true)
                return;

            seen[countryCode] = true;
            choices[countryCode] = countryName !== '' ? countryName + ' (' + countryCode + ')' : countryCode;
        });

        if (code !== '' && !choices.hasOwnProperty(code))
            choices[code] = code;

        return choices;
    },

    resetOptionChoices: function (option, choices) {
        option.keylist = [];
        option.vallist = [];

        Object.keys(choices || {}).forEach(function (key) {
            option.value(key, choices[key]);
        });
    },

    updateCountryChoices: function (selectedCode) {
        var code = String(selectedCode || '').trim().toUpperCase();
        var choices = this.getCountryChoices(code);
        var widget = this.vpn_country_option.getUIElement('config');
        var keys = Object.keys(choices);

        this.resetOptionChoices(this.vpn_country_option, choices);

        if (!widget)
            return;

        if (typeof widget.clearChoices === 'function')
            widget.clearChoices(true);

        if (typeof widget.addChoices === 'function')
            widget.addChoices(keys, choices);

        widget.setValue(code !== '' ? code : '');
    },

    handleCountryCodeChange: function (section_id, value) {
        var normalized = String(value || '').trim().toUpperCase();
        var widget = this.vpn_country_option.getUIElement(section_id);

        if (!widget || normalized === String(value || ''))
            return;

        widget.setValue(normalized);
    },

    updateVpnModeVisibility: function (section_id) {
        var sid = section_id || 'config';
        var mode = String(this.vpn_mode_option.formvalue(sid) || '').trim();
        var showCountry = mode === 'country';
        var showServer = mode === 'server';

        if (this.vpn_country_option)
            this.vpn_country_option.setActive(sid, showCountry);

        if (this.server_address_option)
            this.server_address_option.setActive(sid, showServer);

        if (this.server_public_key_option)
            this.server_public_key_option.setActive(sid, showServer);
    },

    handleGetCountries: function () {
        ui.showModal(null, [
            E('p', { 'class': 'spinning' }, _('Fetching available NordVPN countries'))
        ]);

        return callGetCountriesWithTimeout().then(function (res) {
            var currentCountry = String(this.vpn_country_option.formvalue('config') || '').trim().toUpperCase();

            ui.hideModal();

            if (!res || res.success !== true || !Array.isArray(res.countries)) {
                ui.addNotification(_('Country lookup failed'), E('p', (res && res.error) ? String(res.error) : _('Unable to fetch the country list.')));
                return;
            }

            this.countryChoicesLoaded = true;
            this.countryChoices = res.countries;
            this.updateCountryChoices(currentCountry);

            ui.addNotification(_('Countries loaded'), E('p', _('Country list has been updated.')));
        }.bind(this)).catch(function (err) {
            ui.hideModal();
            ui.addNotification(_('Country lookup failed'), E('p', err ? String(err) : _('Unknown error')));
        });
    },

    getRuntimeStatusDisplayData: function (status) {
        var exitNode = isObject(status) && isObject(status.exit_node) ? status.exit_node : {};

        return {
            telio_running: status && status.telio_is_running === true ? _('Yes') : (status && status.telio_is_running === false ? _('No') : ''),
            ip_address: status && status.ip_address ? String(status.ip_address) : '',
            identifier: exitNode.identifier ? String(exitNode.identifier) : '',
            hostname: exitNode.hostname ? String(exitNode.hostname) : '',
            endpoint: exitNode.endpoint ? String(exitNode.endpoint) : '',
            state: exitNode.state ? String(exitNode.state) : '',
            public_key: exitNode.public_key ? String(exitNode.public_key) : ''
        };
    },

    setRuntimeStatusField: function (id, value) {
        var node = document.getElementById(id);

        if (!node)
            return;

        node.textContent = value != null ? String(value) : '';
    },

    updateRuntimeStatusPanel: function (status) {
        var data = this.getRuntimeStatusDisplayData(status);

        this.runtimeStatus = status || null;
        this.setRuntimeStatusField('nordvpnlite-runtime-telio', data.telio_running);
        this.setRuntimeStatusField('nordvpnlite-runtime-ip', data.ip_address);
        this.setRuntimeStatusField('nordvpnlite-runtime-identifier', data.identifier);
        this.setRuntimeStatusField('nordvpnlite-runtime-hostname', data.hostname);
        this.setRuntimeStatusField('nordvpnlite-runtime-endpoint', data.endpoint);
        this.setRuntimeStatusField('nordvpnlite-runtime-state', data.state);
        this.setRuntimeStatusField('nordvpnlite-runtime-public-key', data.public_key);
    },

    getRuntimeStatusFingerprint: function (status) {
        var exitNode = isObject(status) && isObject(status.exit_node) ? status.exit_node : {};

        return JSON.stringify({
            telio_is_running: status && status.telio_is_running === true,
            ip_address: status && status.ip_address ? String(status.ip_address) : '',
            identifier: exitNode.identifier ? String(exitNode.identifier) : '',
            hostname: exitNode.hostname ? String(exitNode.hostname) : '',
            endpoint: exitNode.endpoint ? String(exitNode.endpoint) : '',
            state: exitNode.state ? String(exitNode.state) : '',
            public_key: exitNode.public_key ? String(exitNode.public_key) : ''
        });
    },

    handleGetRuntimeStatus: function () {
        ui.showModal(null, [
            E('p', { 'class': 'spinning' }, _('Fetching NordVPN Lite runtime status'))
        ]);

        return callGetRuntimeStatusWithTimeout().then(function (res) {
            ui.hideModal();

            if (!res || res.success !== true) {
                ui.addNotification(_('Status lookup failed'), E('p', (res && res.error) ? String(res.error) : _('Unable to fetch NordVPN Lite runtime status.')));
                return;
            }

            this.updateRuntimeStatusPanel(res);
            ui.addNotification(_('Status loaded'), E('p', _('NordVPN Lite runtime status has been updated.')));
        }.bind(this)).catch(function (err) {
            ui.hideModal();
            ui.addNotification(_('Status lookup failed'), E('p', err ? String(err) : _('Unknown error')));
        });
    },

    load: function () {
        return Promise.all([
            L.resolveDefault(callGetConfig(), null).then(function (result) {
                return {
                    rpcAvailable: isObject(result),
                    config: (isObject(result) && isObject(result.config)) ? result.config : defaultConfig
                };
            }),
            L.resolveDefault(callGetServiceStatus(), null).then(function (result) {
                if (isObject(result)) {
                    result.rpcAvailable = true;
                    return result;
                }

                return {
                    rpcAvailable: false,
                    installed: false,
                    enabled: false,
                    running: false
                };
            }),
            L.resolveDefault(callGetRuntimeStatusWithTimeout(), null).then(function (result) {
                return (isObject(result) && result.success === true) ? result : null;
            }),
            L.resolveDefault(callGetConfigEnabled(), null).then(function (result) {
                return {
                    rpcAvailable: isObject(result),
                    enabled: !isObject(result) || result.enabled !== false
                };
            })
        ]);
    },

    renderServicePanel: function (status) {
        var buttonStyle = 'margin-right:0.5rem; margin-bottom:0.25rem;';
        var enableStyle = buttonStyle + ' margin-left:1rem;';
        var valueStyle = 'display:flex; align-items:center; min-height:2.3em;';
        var runtimeData = this.getRuntimeStatusDisplayData(this.runtimeStatus);
        var configEnabled = status.config_enabled !== false;
        var statusText;
        var canStart = false;
        var canRestart = false;
        var canStop = false;
        var canEnable = false;
        var canDisable = false;

        if (status.rpcAvailable === false)
            statusText = _('RPC backend unavailable');
        else if (!status.installed)
            statusText = _('Not installed or not found');
        else if (!configEnabled && status.running)
            statusText = _('Running (service disabled)');
        else if (!configEnabled)
            statusText = _('Stopped (service disabled)');
        else if (status.running)
            statusText = _('Running');
        else if (status.enabled)
            statusText = _('Stopped');
        else
            statusText = _('Stopped (autostart disabled)');

        if (status.installed) {
            canEnable = !status.enabled;
            canDisable = status.enabled;

            if (status.running) {
                canRestart = configEnabled;
                canStop = true;
            } else {
                canStart = configEnabled;
            }
        }

        var btnStart = E('button', {
            'class': 'btn cbi-button cbi-button-apply',
            'type': 'button',
            'style': buttonStyle,
            'disabled': canStart ? null : true,
            'click': function (ev) {
                ev.preventDefault();
                return this.handleServiceAction('start');
            }.bind(this)
        }, _('Start'));

        var btnRestart = E('button', {
            'class': 'btn cbi-button cbi-button-apply',
            'type': 'button',
            'style': buttonStyle,
            'disabled': canRestart ? null : true,
            'click': function (ev) {
                ev.preventDefault();
                return this.handleServiceAction('restart');
            }.bind(this)
        }, _('Restart'));

        var btnStop = E('button', {
            'class': 'btn cbi-button cbi-button-reset',
            'type': 'button',
            'style': buttonStyle,
            'disabled': canStop ? null : true,
            'click': function (ev) {
                ev.preventDefault();
                return this.handleServiceAction('stop');
            }.bind(this)
        }, _('Stop'));

        var btnEnable = E('button', {
            'class': 'btn cbi-button cbi-button-apply',
            'type': 'button',
            'style': enableStyle,
            'disabled': canEnable ? null : true,
            'click': function (ev) {
                ev.preventDefault();
                return this.handleServiceAction('enable');
            }.bind(this)
        }, _('Enable autostart'));

        var btnDisable = E('button', {
            'class': 'btn cbi-button cbi-button-reset',
            'type': 'button',
            'style': buttonStyle,
            'disabled': canDisable ? null : true,
            'click': function (ev) {
                ev.preventDefault();
                return this.handleServiceAction('disable');
            }.bind(this)
        }, _('Disable autostart'));

        var btnGetStatus = E('button', {
            'class': 'btn cbi-button cbi-button-apply',
            'type': 'button',
            'style': buttonStyle,
            'disabled': status.rpcAvailable === false ? true : null,
            'click': function (ev) {
                ev.preventDefault();
                return this.handleGetRuntimeStatus();
            }.bind(this)
        }, _('Get status'));

        return E('div', { 'class': 'cbi-section' }, [
            E('div', { 'class': 'cbi-value' }, [
                E('label', { 'class': 'cbi-value-title' }, _('Service Status')),
                E('div', { 'class': 'cbi-value-field', 'style': valueStyle }, statusText)
            ]),
            E('div', { 'class': 'cbi-value' }, [
                E('label', { 'class': 'cbi-value-title' }, _('Service Control')),
                E('div', { 'class': 'cbi-value-field' }, E('div', {}, [
                    btnStart,
                    btnRestart,
                    btnStop,
                    btnEnable,
                    btnDisable
                ]))
            ]),
            E('div', { 'class': 'cbi-value' }, [
                E('label', { 'class': 'cbi-value-title' }, _('Runtime Status')),
                E('div', { 'class': 'cbi-value-field' }, E('div', {}, [
                    btnGetStatus
                ]))
            ]),
            E('div', { 'class': 'cbi-value' }, [
                E('label', { 'class': 'cbi-value-title' }, _('Telio Running')),
                E('div', { 'class': 'cbi-value-field', 'style': valueStyle, 'id': 'nordvpnlite-runtime-telio' }, runtimeData.telio_running)
            ]),
            E('div', { 'class': 'cbi-value' }, [
                E('label', { 'class': 'cbi-value-title' }, _('Tunnel IP Address')),
                E('div', { 'class': 'cbi-value-field', 'style': valueStyle, 'id': 'nordvpnlite-runtime-ip' }, runtimeData.ip_address)
            ]),
            E('div', { 'class': 'cbi-value' }, [
                E('label', { 'class': 'cbi-value-title' }, _('Exit Node Identifier')),
                E('div', { 'class': 'cbi-value-field', 'style': valueStyle, 'id': 'nordvpnlite-runtime-identifier' }, runtimeData.identifier)
            ]),
            E('div', { 'class': 'cbi-value' }, [
                E('label', { 'class': 'cbi-value-title' }, _('Exit Node Hostname')),
                E('div', { 'class': 'cbi-value-field', 'style': valueStyle, 'id': 'nordvpnlite-runtime-hostname' }, runtimeData.hostname)
            ]),
            E('div', { 'class': 'cbi-value' }, [
                E('label', { 'class': 'cbi-value-title' }, _('Exit Node Endpoint')),
                E('div', { 'class': 'cbi-value-field', 'style': valueStyle, 'id': 'nordvpnlite-runtime-endpoint' }, runtimeData.endpoint)
            ]),
            E('div', { 'class': 'cbi-value' }, [
                E('label', { 'class': 'cbi-value-title' }, _('Exit Node State')),
                E('div', { 'class': 'cbi-value-field', 'style': valueStyle, 'id': 'nordvpnlite-runtime-state' }, runtimeData.state)
            ]),
            E('div', { 'class': 'cbi-value' }, [
                E('label', { 'class': 'cbi-value-title' }, _('Exit Node Public Key')),
                E('div', { 'class': 'cbi-value-field', 'style': valueStyle + ' word-break:break-all;', 'id': 'nordvpnlite-runtime-public-key' }, runtimeData.public_key)
            ])
        ]);
    },

    pollServiceStatus: function (expectRunning) {
        var attempts = 0;
        var maxAttempts = 30;

        var poll = function () {
            attempts++;

            return L.resolveDefault(callGetServiceStatus(), {}).then(function (status) {
                if ((expectRunning && status.running === true) || (!expectRunning && status.running !== true)) {
                    ui.hideModal();
                    location.reload();
                    return;
                }

                if (attempts >= maxAttempts) {
                    ui.hideModal();
                    ui.addNotification(
                        _('Service status'),
                        E('p', expectRunning
                            ? _('The service did not reach the running state. Check the authentication token and system log.')
                            : _('The service did not stop within the expected time.'))
                    );
                    return;
                }

                window.setTimeout(poll, 1000);
            }).catch(function () {
                if (attempts >= maxAttempts) {
                    ui.hideModal();
                    ui.addNotification(_('Service status'), E('p', _('Unable to read the updated service state.')));
                    return;
                }

                window.setTimeout(poll, 1000);
            });
        };

        window.setTimeout(poll, 1000);
    },

    handleServiceAction: function (action) {
        var messages = {
            start: _('Starting NordVPN Lite service'),
            restart: _('Restarting NordVPN Lite service'),
            stop: _('Stopping NordVPN Lite service'),
            enable: _('Enabling NordVPN Lite autostart'),
            disable: _('Disabling NordVPN Lite autostart')
        };

        var runAction = function () {
            ui.showModal(null, [
                E('p', { 'class': 'spinning' }, messages[action] || _('Updating NordVPN Lite service'))
            ]);

            return callSetServiceAction(action);
        };
        var actionPromise;

        if (action === 'start' || action === 'restart') {
            actionPromise = this.saveConfig(false).then(function (saved) {
                if (!saved)
                    return null;

                if (this.configEnabled === false) {
                    ui.addNotification(
                        _('Service disabled'),
                        E('p', _('Enable the service and save the configuration before starting it.'))
                    );
                    return null;
                }

                return runAction();
            }.bind(this));
        } else {
            actionPromise = runAction();
        }

        return actionPromise.then(function (res) {
            if (res === null)
                return;

            if (!res || res.success !== true) {
                ui.hideModal();
                ui.addNotification(_('Action failed'), E('p', (res && res.error) ? String(res.error) : _('Could not control the service.')));
                return;
            }

            if (action === 'start' || action === 'restart')
                return this.pollServiceStatus(true);

            if (action === 'stop')
                return this.pollServiceStatus(false);

            ui.hideModal();
            location.reload();
        }.bind(this)).catch(function (err) {
            ui.hideModal();
            ui.addNotification(_('Action failed'), E('p', err ? String(err) : _('Unknown error')));
        });
    },

    pollAppliedStatus: function (previousFingerprint) {
        var serviceAttempts = 0;
        var runtimeAttempts = 0;
        var maxServiceAttempts = 45;
        var maxRuntimeAttempts = 20;
        var latestServiceStatus = null;
        var latestRuntimeStatus = null;
        var pollService;
        var pollRuntime;

        pollRuntime = function (resolve) {
            runtimeAttempts++;

            return L.resolveDefault(callGetRuntimeStatusWithTimeout(), null).then(function (runtimeStatus) {
                var fingerprint;
                var exitState;
                var shouldReload = false;

                if (isObject(runtimeStatus) && runtimeStatus.success === true) {
                    latestRuntimeStatus = runtimeStatus;
                    this.runtimeStatus = runtimeStatus;

                    fingerprint = this.getRuntimeStatusFingerprint(runtimeStatus);
                    exitState = String((runtimeStatus.exit_node && runtimeStatus.exit_node.state) || '').trim().toLowerCase();

                    shouldReload = (exitState === 'connected') ||
                        (runtimeAttempts >= 3 && runtimeStatus.telio_is_running === true) ||
                        (previousFingerprint !== '' && fingerprint !== previousFingerprint);
                }

                if (shouldReload || runtimeAttempts >= maxRuntimeAttempts) {
                    if (latestServiceStatus)
                        this.serviceStatus = latestServiceStatus;

                    if (latestRuntimeStatus)
                        this.runtimeStatus = latestRuntimeStatus;

                    ui.hideModal();
                    location.reload();
                    resolve();
                    return;
                }

                window.setTimeout(function () {
                    pollRuntime.call(this, resolve);
                }.bind(this), 1000);
            }.bind(this)).catch(function () {
                if (runtimeAttempts >= maxRuntimeAttempts) {
                    ui.hideModal();
                    location.reload();
                    resolve();
                    return;
                }

                window.setTimeout(function () {
                    pollRuntime.call(this, resolve);
                }.bind(this), 1000);
            }.bind(this));
        }.bind(this);

        pollService = function (resolve) {
            serviceAttempts++;

            return L.resolveDefault(callGetServiceStatus(), null).then(function (serviceStatus) {
                if (isObject(serviceStatus)) {
                    serviceStatus.rpcAvailable = true;
                    latestServiceStatus = serviceStatus;
                }

                if (latestServiceStatus && latestServiceStatus.running === true)
                    return pollRuntime.call(this, resolve);

                if (serviceAttempts >= maxServiceAttempts) {
                    ui.hideModal();
                    location.reload();
                    resolve();
                    return;
                }

                window.setTimeout(function () {
                    pollService.call(this, resolve);
                }.bind(this), 1000);
            }.bind(this)).catch(function () {
                if (serviceAttempts >= maxServiceAttempts) {
                    ui.hideModal();
                    location.reload();
                    resolve();
                    return;
                }

                window.setTimeout(function () {
                    pollService.call(this, resolve);
                }.bind(this), 1000);
            }.bind(this));
        }.bind(this);

        return new Promise(function (resolve) {
            window.setTimeout(function () {
                pollService.call(this, resolve);
            }.bind(this), 1000);
        }.bind(this));
    },

    handleSaveApplyRestart: function () {
        var previousFingerprint = this.getRuntimeStatusFingerprint(this.runtimeStatus);

        ui.showModal(null, [
            E('p', { 'class': 'spinning' }, _('Restarting NordVPN Lite service and refreshing runtime status'))
        ]);

        return callSetServiceAction('restart').then(function (res) {
            if (!res || res.success !== true) {
                ui.hideModal();
                ui.addNotification(_('Action failed'), E('p', (res && res.error) ? String(res.error) : _('Could not restart the service.')));
                return;
            }

            return this.pollAppliedStatus(previousFingerprint);
        }.bind(this)).catch(function (err) {
            ui.hideModal();
            ui.addNotification(_('Action failed'), E('p', err ? String(err) : _('Unknown error')));
        });
    },

    getVpnFormData: function (config) {
        var data = {
            authentication_token: config.authentication_token === '<REPLACE_WITH_YOUR_TOKEN>' ? '' : String(config.authentication_token || ''),
            vpn_mode: 'recommended',
            vpn_country: '',
            server_address: '',
            server_public_key: ''
        };

        if (config.vpn && config.vpn !== 'recommended') {
            if (config.vpn.country != null) {
                data.vpn_mode = 'country';
                data.vpn_country = String(config.vpn.country || '').trim().toUpperCase();
            } else if (config.vpn.server != null) {
                data.vpn_mode = 'server';
                data.server_address = String(config.vpn.server.address || '');
                data.server_public_key = String(config.vpn.server.public_key || '');
            }
        }

        return data;
    },

    render: function (data) {
        var configState = data[0] || {
            rpcAvailable: false,
            config: defaultConfig
        };
        var config = configState.config;
        var serviceStatus = data[1] || {
            rpcAvailable: false,
            installed: false,
            enabled: false,
            running: false
        };
        var runtimeStatus = data[2] || null;
        var configEnabledState = data[3] || {
            rpcAvailable: false,
            enabled: true
        };
        var view = this;

        this.config = config;
        this.serviceStatus = serviceStatus;
        this.runtimeStatus = runtimeStatus;
        this.configEnabled = configEnabledState.enabled !== false;
        this.configEnabledState = configEnabledState;
        this.countryChoices = [];
        this.countryChoicesLoaded = false;
        this.serviceStatus.config_enabled = this.configEnabled;

        var form_data = {
            config: Object.assign(this.getVpnFormData(this.config), {
                enabled: this.configEnabled ? '1' : '0'
            })
        };

        var m = new form.JSONMap(form_data, _('NordVPN Lite'),
            _('Configure your NordVPN Lite connection settings.'));

        var s = m.section(form.NamedSection, 'config');

        var o = this.enabled_option = s.option(form.Flag, 'enabled', _('Enable service'));
        o.default = '1';
        o.rmempty = false;
        o.description = _('Allow NordVPN Lite to start. This setting is independent of boot-time autostart.');

        o = this.authentication_token_option = s.option(form.Value, 'authentication_token', _('Authentication Token'));
        o.password = true;
        o.placeholder = _('Enter your Nord Account authentication token');

        o = this.vpn_mode_option = s.option(form.ListValue, 'vpn_mode', _('VPN Selection'));
        o.value('recommended', _('Recommended server'));
        o.value('country', _('Country code'));
        o.value('server', _('Specific server'));
        o.rmempty = false;
        o.onchange = function (ev, section_id) {
            view.updateVpnModeVisibility(section_id);
            window.setTimeout(function () {
                m.checkDepends(ev);
            }, 0);
        };

        o = this.vpn_country_option = s.option(form.Value, 'vpn_country', _('Country'));
        o.depends('vpn_mode', 'country');
        o.placeholder = _('IE');
        o.description = _('Type a two-letter country code or load the country list and choose one from the dropdown.');
        o.validate = function (_, value) {
            if (view.vpn_mode_option.formvalue('config') !== 'country')
                return true;

            value = String(value || '').trim().toUpperCase();
            return /^[A-Z]{2}$/.test(value) ? true : _('Please provide a two-letter country code.');
        };
        this.resetOptionChoices(o, this.getCountryChoices(form_data.config.vpn_country));
        o.onchange = function (ev, section_id, value) {
            view.handleCountryCodeChange(section_id, value);
        };
        o.renderWidget = function (section_id, option_index, cfgvalue) {
            var input = form.Value.prototype.renderWidget.call(this, section_id, option_index, cfgvalue);
            var button = E('button', {
                'class': 'btn cbi-button cbi-button-apply',
                'type': 'button',
                'style': 'white-space:nowrap;',
                'click': function (ev) {
                    ev.preventDefault();
                    return view.handleGetCountries();
                }
            }, _('Get country list'));

            return E('div', { 'style': 'display:flex; align-items:center; gap:0.5rem; max-width:34rem;' }, [
                E('div', { 'style': 'flex:1 1 auto;' }, input),
                button
            ]);
        };

        o = this.server_address_option = s.option(form.Value, 'server_address', _('Server IP Address'));
        o.depends('vpn_mode', 'server');
        o.datatype = 'ipaddr';
        o.placeholder = '';
        o.description = _('Enter the IP address of the NordVPN server.');
        o.validate = function (section_id, value) {
            if (view.vpn_mode_option.formvalue('config') !== 'server')
                return true;

            value = String(value || '').trim();
            if (value === '')
                return _('Please provide the server IP address.');

            return form.Value.prototype.validate.apply(this, [section_id, value]);
        };

        o = this.server_public_key_option = s.option(form.Value, 'server_public_key', _('Server Public Key'));
        o.depends('vpn_mode', 'server');
        o.placeholder = '';
        o.description = _('Enter the WireGuard public key of the NordVPN server.');
        o.validate = function (_, value) {
            if (view.vpn_mode_option.formvalue('config') !== 'server')
                return true;

            return String(value || '').trim() !== '' ? true : _('Please provide the server public key.');
        };

        return m.render().then(function (nodes) {
            var servicePanel = this.renderServicePanel(serviceStatus);
            var pageTitle = nodes.querySelector('.cbi-map-descr');
            var pageActions = nodes.querySelector('.cbi-page-actions');

            if (configState.rpcAvailable === false && pageTitle && pageTitle.parentNode) {
                pageTitle.parentNode.insertBefore(E('div', { 'class': 'alert-message warning' }, [
                    _('The NordVPN Lite RPC backend is unavailable. LuCI is showing default values until rpcd loads the backend again.')
                ]), pageTitle.nextSibling);
            }

            if (pageActions)
                nodes.insertBefore(servicePanel, pageActions);
            else
                nodes.appendChild(servicePanel);

            window.setTimeout(function () {
                view.updateVpnModeVisibility('config');
            }, 0);

            return nodes;
        }.bind(this));
    },

    saveConfig: async function (showSuccessNotification) {
        const token = String(this.authentication_token_option.formvalue('config') || '<REPLACE_WITH_YOUR_TOKEN>').trim();
        const vpnMode = String(this.vpn_mode_option.formvalue('config') || 'recommended').trim();
        const vpnCountry = String(this.vpn_country_option.formvalue('config') || '').trim().toUpperCase();
        const serverAddress = String(this.server_address_option.formvalue('config') || '').trim();
        const serverPublicKey = String(this.server_public_key_option.formvalue('config') || '').trim();
        const enabled = this.enabled_option.formvalue('config') !== '0';

        this.config.authentication_token = token;

        if (vpnMode === 'country') {
            if (!this.vpn_country_option.isValid('config')) {
                ui.addNotification(_('Save failed'), E('p', this.vpn_country_option.getValidationError('config') || _('Please choose a country.')));
                return false;
            }

            this.config.vpn = { country: vpnCountry };
        } else if (vpnMode === 'server') {
            if (!this.server_address_option.isValid('config')) {
                ui.addNotification(_('Save failed'), E('p', _('Please provide a valid server IP address.')));
                return false;
            }

            if (!this.server_public_key_option.isValid('config')) {
                ui.addNotification(_('Save failed'), E('p', _('Please provide the server public key.')));
                return false;
            }

            this.config.vpn = {
                server: {
                    address: serverAddress,
                    public_key: serverPublicKey
                }
            };
        } else {
            this.config.vpn = 'recommended';
        }

        try {
            const enabledRes = await callSetConfigEnabled(enabled);
            if (!enabledRes || enabledRes.success !== true) {
                ui.addNotification(_('Save failed'), E('p', (enabledRes && enabledRes.error) ? String(enabledRes.error) : _('Could not write service enabled flag.')));
                return false;
            }

            const res = await callSetConfig(this.config);
            if (!res || res.success !== true) {
                ui.addNotification(_('Save failed'), E('p', _('Could not write config file.')));
                return false;
            }

            this.configEnabled = enabled;
            this.configEnabledState = {
                rpcAvailable: true,
                enabled: enabled
            };

            if (showSuccessNotification !== false)
                ui.addNotification(_('Saved'), E('p', _('Configuration updated.')));

            return true;
        } catch (err) {
            ui.addNotification(_('Save failed'), E('p', err ? String(err) : _('Unknown error')));
            return false;
        }
    },

    handleSave: null,

    handleSaveApply: function () {
        return this.saveConfig(false).then(function (saved) {
            if (!saved)
                return;

            if (!this.serviceStatus || this.serviceStatus.rpcAvailable === false) {
                ui.addNotification(_('Saved'), E('p', _('Configuration updated, but the RPC backend is unavailable so the service could not be restarted.')));
                return;
            }

            if (!this.serviceStatus.installed) {
                ui.addNotification(_('Saved'), E('p', _('Configuration updated, but the service is not installed or not found.')));
                return;
            }

            if (this.configEnabled === false) {
                if (this.serviceStatus.running)
                    return this.handleServiceAction('stop');

                location.reload();
                return;
            }

            return this.handleSaveApplyRestart();
        }.bind(this));
    },

    handleReset: null
});
