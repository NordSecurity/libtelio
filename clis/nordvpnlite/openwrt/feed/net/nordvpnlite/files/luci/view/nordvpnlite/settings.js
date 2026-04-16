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

var callGetServiceStatus = rpc.declare({
    object: 'nordvpnlite',
    method: 'get_service_status'
});

var callSetServiceAction = rpc.declare({
    object: 'nordvpnlite',
    method: 'set_service_action',
    params: ['action']
});

var callGetServerData = rpc.declare({
    object: 'nordvpnlite',
    method: 'get_server_data',
    params: ['hostname']
});

var callGetCountries = rpc.declare({
    object: 'nordvpnlite',
    method: 'get_countries'
});

var callGetRuntimeStatus = rpc.declare({
    object: 'nordvpnlite',
    method: 'get_runtime_status'
});

var serverHostnameSuffix = '.nordvpn.com';

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

function normalizeServerHostname(value) {
    value = String(value || '').trim().toLowerCase();

    if (value.slice(-1) === '.')
        value = value.slice(0, -1);

    if (value.slice(-serverHostnameSuffix.length) === serverHostnameSuffix)
        value = value.slice(0, -serverHostnameSuffix.length);

    return value;
}

function buildServerHostname(value) {
    value = normalizeServerHostname(value);
    return value !== '' ? value + serverHostnameSuffix : '';
}

function callGetServerDataWithTimeout(hostname) {
    var previousTimeout = L.env.rpctimeout;

    L.env.rpctimeout = Math.max(L.env.rpctimeout || 20, 60);

    return Promise.resolve(callGetServerData(hostname)).finally(function () {
        L.env.rpctimeout = previousTimeout;
    });
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

        if (this.server_hostname_option)
            this.server_hostname_option.setActive(sid, showServer);

        if (this.server_lookup_option)
            this.server_lookup_option.setActive(sid, showServer);

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
            })
        ]);
    },

    renderServicePanel: function (status) {
        var buttonStyle = 'margin-right:0.5rem; margin-bottom:0.25rem;';
        var enableStyle = buttonStyle + ' margin-left:1rem;';
        var runtimeData = this.getRuntimeStatusDisplayData(this.runtimeStatus);
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
        else if (status.running)
            statusText = _('Running');
        else if (status.enabled)
            statusText = _('Stopped.');
        else
            statusText = _('Stopped (Disabled).');

        if (status.installed) {
            if (status.enabled) {
                canDisable = true;

                if (status.running) {
                    canRestart = true;
                    canStop = true;
                } else {
                    canStart = true;
                }
            } else {
                canEnable = true;
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
        }, _('Enable'));

        var btnDisable = E('button', {
            'class': 'btn cbi-button cbi-button-reset',
            'type': 'button',
            'style': buttonStyle,
            'disabled': canDisable ? null : true,
            'click': function (ev) {
                ev.preventDefault();
                return this.handleServiceAction('disable');
            }.bind(this)
        }, _('Disable'));

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
                E('div', { 'class': 'cbi-value-field' }, E('div', {}, statusText))
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
                E('div', { 'class': 'cbi-value-field' }, E('div', { 'id': 'nordvpnlite-runtime-telio' }, runtimeData.telio_running))
            ]),
            E('div', { 'class': 'cbi-value' }, [
                E('label', { 'class': 'cbi-value-title' }, _('Tunnel IP Address')),
                E('div', { 'class': 'cbi-value-field' }, E('div', { 'id': 'nordvpnlite-runtime-ip' }, runtimeData.ip_address))
            ]),
            E('div', { 'class': 'cbi-value' }, [
                E('label', { 'class': 'cbi-value-title' }, _('Exit Node Identifier')),
                E('div', { 'class': 'cbi-value-field' }, E('div', { 'id': 'nordvpnlite-runtime-identifier' }, runtimeData.identifier))
            ]),
            E('div', { 'class': 'cbi-value' }, [
                E('label', { 'class': 'cbi-value-title' }, _('Exit Node Hostname')),
                E('div', { 'class': 'cbi-value-field' }, E('div', { 'id': 'nordvpnlite-runtime-hostname' }, runtimeData.hostname))
            ]),
            E('div', { 'class': 'cbi-value' }, [
                E('label', { 'class': 'cbi-value-title' }, _('Exit Node Endpoint')),
                E('div', { 'class': 'cbi-value-field' }, E('div', { 'id': 'nordvpnlite-runtime-endpoint' }, runtimeData.endpoint))
            ]),
            E('div', { 'class': 'cbi-value' }, [
                E('label', { 'class': 'cbi-value-title' }, _('Exit Node State')),
                E('div', { 'class': 'cbi-value-field' }, E('div', { 'id': 'nordvpnlite-runtime-state' }, runtimeData.state))
            ]),
            E('div', { 'class': 'cbi-value' }, [
                E('label', { 'class': 'cbi-value-title' }, _('Exit Node Public Key')),
                E('div', { 'class': 'cbi-value-field' }, E('div', { 'id': 'nordvpnlite-runtime-public-key', 'style': 'word-break:break-all;' }, runtimeData.public_key))
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
                    location.reload();
                    return;
                }

                window.setTimeout(poll, 1000);
            }).catch(function () {
                if (attempts >= maxAttempts) {
                    ui.hideModal();
                    location.reload();
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
            enable: _('Enabling NordVPN Lite service'),
            disable: _('Disabling NordVPN Lite service')
        };

        ui.showModal(null, [
            E('p', { 'class': 'spinning' }, messages[action] || _('Updating NordVPN Lite service'))
        ]);

        return callSetServiceAction(action).then(function (res) {
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
            server_hostname: '',
            server_address: '',
            server_public_key: ''
        };

        if (config.vpn && config.vpn !== 'recommended') {
            if (config.vpn.country != null) {
                data.vpn_mode = 'country';
                data.vpn_country = String(config.vpn.country || '').trim().toUpperCase();
            } else if (config.vpn.server != null) {
                data.vpn_mode = 'server';
                data.server_hostname = normalizeServerHostname(config.vpn.server.hostname || '');
                data.server_address = String(config.vpn.server.address || '');
                data.server_public_key = String(config.vpn.server.public_key || '');
            }
        }

        return data;
    },

    handleServerHostnameChange: function (section_id, value) {
        var normalized = normalizeServerHostname(value);
        var widget = this.server_hostname_option.getUIElement(section_id);
        var node = widget ? (widget.node.querySelector('input, textarea, select') || widget.node) : null;
        var serverAddress = String(this.server_address_option.formvalue(section_id) || '').trim();
        var serverPublicKey = String(this.server_public_key_option.formvalue(section_id) || '').trim();

        if (widget && node && node.value !== normalized)
            widget.setValue(normalized);

        if (normalized === this.serverDataHostname)
            return;

        if (serverAddress === '' && serverPublicKey === '')
            return;

        this.serverDataHostname = '';
        this.setOptionValue(this.server_address_option, '');
        this.setOptionValue(this.server_public_key_option, '');
    },

    setOptionValue: function (option, value) {
        var widget = option.getUIElement('config');
        var node = widget ? (widget.node.querySelector('input, textarea, select') || widget.node) : null;

        if (!widget || !node)
            return;

        widget.setValue(value != null ? String(value) : '');
        node.dispatchEvent(new Event('input', { bubbles: true }));
        node.dispatchEvent(new Event('change', { bubbles: true }));
    },

    handleGetServerData: function () {
        var hostname = normalizeServerHostname(this.server_hostname_option.formvalue('config'));
        var fullHostname = buildServerHostname(hostname);

        if (hostname === '') {
            ui.addNotification(_('Lookup failed'), E('p', _('Please enter a server hostname first.')));
            return Promise.resolve();
        }

        if (!this.server_hostname_option.isValid('config')) {
            ui.addNotification(_('Lookup failed'), E('p', _('Please provide a valid server hostname.')));
            return Promise.resolve();
        }

        ui.showModal(null, [
            E('p', { 'class': 'spinning' }, _('Fetching NordVPN server data'))
        ]);

        return callGetServerDataWithTimeout(fullHostname).then(function (res) {
            ui.hideModal();

            if (!res || res.success !== true) {
                ui.addNotification(_('Lookup failed'), E('p', (res && res.error) ? String(res.error) : _('Unable to fetch NordVPN server data.')));
                return;
            }

            this.serverDataHostname = hostname;
            this.setOptionValue(this.server_hostname_option, normalizeServerHostname(res.hostname || fullHostname));
            this.setOptionValue(this.server_address_option, res.address || '');
            this.setOptionValue(this.server_public_key_option, res.public_key || '');

            ui.addNotification(_('Server data loaded'), E('p', _('Server IP address and public key have been filled in.')));
        }.bind(this)).catch(function (err) {
            ui.hideModal();
            ui.addNotification(_('Lookup failed'), E('p', err ? String(err) : _('Unknown error')));
        });
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
        var view = this;

        this.config = config;
        this.serviceStatus = serviceStatus;
        this.runtimeStatus = runtimeStatus;
        this.countryChoices = [];
        this.countryChoicesLoaded = false;

        var form_data = {
            config: this.getVpnFormData(this.config)
        };

        this.serverDataHostname = form_data.config.server_hostname;

        var m = new form.JSONMap(form_data, _('NordVPN Lite'),
            _('Configure your NordVPN Lite connection settings.'));

        var s = m.section(form.NamedSection, 'config');

        var o = this.authentication_token_option = s.option(form.Value, 'authentication_token', _('Authentication Token'));
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

        o = this.server_hostname_option = s.option(form.Value, 'server_hostname', _('Server Hostname'));
        o.depends('vpn_mode', 'server');
        o.placeholder = _('uk2222');
        o.description = _('Enter only the server prefix. The .nordvpn.com suffix is added automatically. Use Get data to fill the IP and public key.');
        o.validate = function (_, value) {
            if (view.vpn_mode_option.formvalue('config') !== 'server')
                return true;

            value = normalizeServerHostname(value);

            if (value === '')
                return true;

            return /^[a-z0-9-]+$/.test(value) ? true : _('Please enter only the server prefix, for example uk2222.');
        };
        o.onchange = function (ev, section_id, value) {
            view.handleServerHostnameChange(section_id, value);
        };
        o.renderWidget = function (section_id, option_index, cfgvalue) {
            var input = form.Value.prototype.renderWidget.call(this, section_id, option_index, cfgvalue);

            return E('div', { 'style': 'display:flex; align-items:center; gap:0.5rem; max-width:30rem;' }, [
                E('div', { 'style': 'flex:1 1 auto;' }, input),
                E('span', { 'style': 'white-space:nowrap;' }, serverHostnameSuffix)
            ]);
        };

        o = this.server_lookup_option = s.option(form.Button, '_get_server_data', _('Server Lookup'));
        o.depends('vpn_mode', 'server');
        o.inputtitle = _('Get data');
        o.inputstyle = 'apply';
        o.onclick = function () {
            return view.handleGetServerData();
        };

        o = this.server_address_option = s.option(form.Value, 'server_address', _('Server IP Address'));
        o.depends('vpn_mode', 'server');
        o.readonly = true;
        o.datatype = 'ipaddr';
        o.placeholder = '';
        o.validate = function (section_id, value) {
            if (view.vpn_mode_option.formvalue('config') !== 'server')
                return true;

            value = String(value || '').trim();
            if (value === '')
                return _('Use Get data to load the server IP address.');

            return form.Value.prototype.validate.apply(this, [section_id, value]);
        };

        o = this.server_public_key_option = s.option(form.Value, 'server_public_key', _('Server Public Key'));
        o.depends('vpn_mode', 'server');
        o.readonly = true;
        o.placeholder = '';
        o.validate = function (_, value) {
            if (view.vpn_mode_option.formvalue('config') !== 'server')
                return true;

            return String(value || '').trim() !== '' ? true : _('Use Get data to load the server public key.');
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
        const serverHostname = normalizeServerHostname(this.server_hostname_option.formvalue('config'));
        const fullServerHostname = buildServerHostname(serverHostname);
        const serverAddress = String(this.server_address_option.formvalue('config') || '').trim();
        const serverPublicKey = String(this.server_public_key_option.formvalue('config') || '').trim();

        this.config.authentication_token = token;

        if (vpnMode === 'country') {
            if (!this.vpn_country_option.isValid('config')) {
                ui.addNotification(_('Save failed'), E('p', this.vpn_country_option.getValidationError('config') || _('Please choose a country.')));
                return false;
            }

            this.config.vpn = { country: vpnCountry };
        } else if (vpnMode === 'server') {
            if (serverHostname !== '' && !this.server_hostname_option.isValid('config')) {
                ui.addNotification(_('Save failed'), E('p', _('Please provide a valid server hostname prefix.')));
                return false;
            }

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

            if (fullServerHostname !== '')
                this.config.vpn.server.hostname = fullServerHostname;
        } else {
            this.config.vpn = 'recommended';
        }

        try {
            const res = await callSetConfig(this.config);
            if (!res || res.success !== true) {
                ui.addNotification(_('Save failed'), E('p', _('Could not write config file.')));
                return false;
            }

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

            return this.handleSaveApplyRestart();
        }.bind(this));
    },

    handleReset: null
});
