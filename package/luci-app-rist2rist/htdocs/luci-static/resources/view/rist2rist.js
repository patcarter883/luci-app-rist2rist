'use strict';
'require view';
'require form';
'require rpc';
'require poll';
'require fs';

var callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: ['name'],
	filter: function(res) {
		var instances = ((res['rist2rist'] || {}).instances) || {};
		var running = false;
		var pid = null;
		Object.keys(instances).forEach(function(k) {
			if (instances[k].running) {
				running = true;
				pid = instances[k].pid;
			}
		});
		return { running: running, pid: pid };
	}
});

function updateStatusWidget(status) {
	var dot   = document.getElementById('rist2rist-status-dot');
	var label = document.getElementById('rist2rist-status-label');
	if (!dot || !label) return;
	dot.style.backgroundColor = status.running ? '#4caf50' : '#f44336';
	label.textContent = status.running
		? _('Running') + (status.pid ? ' (PID ' + status.pid + ')' : '')
		: _('Stopped');
}

function updateLogWidget(result) {
	var el = document.getElementById('rist2rist-log');
	if (!el) return;
	var content = (result && result.stdout) ? result.stdout : '';
	var lines = content.trimEnd().split('\n');
	el.textContent = lines.slice(-100).join('\n') || _('(no output yet)');
	el.scrollTop = el.scrollHeight;
}

function renderStatusSection(status, log) {
	return E('div', {'class': 'cbi-section'}, [
		E('legend', {}, _('Service Status')),
		E('div', {'class': 'cbi-value'}, [
			E('label', {'class': 'cbi-value-title'}, _('Status')),
			E('div', {'class': 'cbi-value-field'}, [
				E('span', {
					'id': 'rist2rist-status-dot',
					'style': 'display:inline-block;width:12px;height:12px;border-radius:50%;' +
					         'vertical-align:middle;margin-right:6px;background-color:' +
					         (status.running ? '#4caf50' : '#f44336')
				}),
				E('span', {'id': 'rist2rist-status-label'}, status.running
					? _('Running') + (status.pid ? ' (PID ' + status.pid + ')' : '')
					: _('Stopped'))
			])
		]),
		E('div', {'class': 'cbi-value'}, [
			E('label', {'class': 'cbi-value-title'}, _('Log Output')),
			E('div', {'class': 'cbi-value-field'}, [
				E('pre', {
					'id': 'rist2rist-log',
					'style': 'max-height:300px;overflow-y:auto;white-space:pre-wrap;' +
					         'background:#1a1a1a;color:#e0e0e0;padding:8px;' +
					         'font-size:12px;border-radius:4px;margin:0'
				}, log || _('(no output yet)'))
			])
		])
	]);
}

return view.extend({
	load: function() {
		return Promise.all([
			callServiceList('rist2rist'),
			fs.exec('/sbin/logread', ['-e', 'rist2rist']).catch(function() { return { stdout: '' }; })
		]);
	},

	render: function(data) {
		var status = data[0];
		var logResult = data[1] || { stdout: '' };
		var log = (logResult.stdout || '').trimEnd().split('\n').slice(-100).join('\n');
		var m, s, o;

		poll.add(function() {
			return Promise.all([
				callServiceList('rist2rist').then(updateStatusWidget),
				fs.exec('/sbin/logread', ['-e', 'rist2rist']).then(updateLogWidget).catch(function() {})
			]);
		}, 5);

		m = new form.Map('rist2rist',
			_('RIST Multi-Path Engine & Telemetry Bridge'),
			_('Manages multi-WAN stream replication using librist socket-level interface binding. Status shifts on WAN legs are analyzed and injected backward into the local LAN segment via RIST Out-of-Band (OOB) control blocks to achieve dynamic, reactive encoder bitrate adaptation.'));

		// -------------------------------------------------------------
		// GLOBAL INGEST & LAN TELEMETRY CONFIGURATION
		// -------------------------------------------------------------
		s = m.section(form.TypedSection, 'rist2rist', _('Local Ingest Settings (LAN Receiver)'));
		s.anonymous = true;

		o = s.option(form.Flag, 'enabled', _('Enable Ingest Engine'));
		o.rmempty = false;

		o = s.option(form.Value, 'listen_url', _('Input Listen URL'),
			_('The local address and port where your custom hardware encoder delivers the primary RIST feed over the stable segment.'));
		o.placeholder = 'rist://@0.0.0.0:1234';
		o.datatype = 'string';
		o.rmempty = false;

		o = s.option(form.ListValue, 'profile', _('RIST Receive Profile'),
			_('Must match the encoder. The encoder sends Advanced, and the OOB ' +
			  'telemetry backpressure channel only exists in Main/Advanced — a ' +
			  'Simple-profile listener will never authenticate the feed.'));
		o.value('0', _('Simple'));
		o.value('1', _('Main'));
		o.value('2', _('Advanced (recommended)'));
		o.default = '2';
		o.rmempty = false;

		o = s.option(form.ListValue, 'out_profile', _('RIST Output Profile'),
			_('Profile used for the downstream replication outputs (WAN senders). ' +
			  'Must match the downstream receiver. Independent of the receive ' +
			  'profile above.'));
		o.value('0', _('Simple'));
		o.value('1', _('Main'));
		o.value('2', _('Advanced (recommended)'));
		o.default = '2';
		o.rmempty = false;

		// -------- Recovery tuning for the receive (encoder-facing) leg --------
		o = s.option(form.Value, 'buffer_min', _('Recovery Buffer Min (ms)'),
			_('Floor for the retransmission buffer. Must be several times the link ' +
			  'RTT so lost packets can be re-requested and re-sent before playout. ' +
			  'Too small starves retransmission. Adds end-to-end latency.'));
		o.placeholder = '1000';
		o.datatype = 'uinteger';
		o.rmempty = true;

		o = s.option(form.Value, 'buffer_max', _('Recovery Buffer Max (ms)'),
			_('Ceiling the buffer can grow to as measured RTT rises.'));
		o.placeholder = '5000';
		o.datatype = 'uinteger';
		o.rmempty = true;

		o = s.option(form.Value, 'reorder_buffer', _('Reorder Hold-off (ms)'),
			_('How long to wait for out-of-order packets before requesting a ' +
			  'retransmit. Keep SMALL (tens of ms) and well below Buffer Min — a ' +
			  'large value eats the recovery window and disables retransmission.'));
		o.placeholder = '30';
		o.datatype = 'uinteger';
		o.rmempty = true;

		o = s.option(form.Value, 'rtt_min', _('Recovery RTT Min (ms)'));
		o.placeholder = '40';
		o.datatype = 'uinteger';
		o.rmempty = true;

		o = s.option(form.Value, 'rtt_max', _('Recovery RTT Max (ms)'));
		o.placeholder = '500';
		o.datatype = 'uinteger';
		o.rmempty = true;

		o = s.option(form.Flag, 'verbose_log', _('Verbose Logging'),
			_('Enable info-level logging to /tmp/rist2rist.log. Leave off in normal operation to reduce log volume.'));
		o.default = o.disabled;
		o.rmempty = false;

		o = s.option(form.Flag, 'telemetry_enabled', _('Enable LAN OOB Backpressure'),
			_('Instructs the proxy receiver to intercept cellular WAN metrics and push state updates backward to the encoder.'));
		o.default = o.enabled;
		o.rmempty = false;

		o = s.option(form.Value, 'rtt_hysteresis', _('RTT Change Hysteresis (ms)'),
			_('Filters out high-frequency cellular jitter. Telemetry updates are only fired if the round-trip latency shifts by more than this value.'));
		o.placeholder = '15';
		o.datatype = 'uinteger';
		o.default = '15';
		o.depends('telemetry_enabled', '1');

		// -------------------------------------------------------------
		// DYNAMIC MULTI-PATH REPLICAS ARRAY (WAN SENDERS)
		// -------------------------------------------------------------
		s = m.section(form.GridSection, 'destination', _('WAN Replication Outputs (SMPTE ST 2022-7 Mode)'));
		s.anonymous = true;
		s.addremove = true;

		o = s.option(form.Value, 'address', _('Remote Receiver Address'),
			_('Enter a RIST URL (rist://host:port) or bare host:port. Hostnames and IPv4 addresses are both accepted.'));
		o.placeholder = 'rist://1.2.3.4:5678';
		o.datatype = 'string';
		o.rmempty = false;
		o.validate = function(section_id, value) {
			if (!value) return true;
			// Accept rist://host:port or host:port (hostname or IPv4)
			var urlPat  = /^rist:\/\/[a-zA-Z0-9._-]+(:\d{1,5})?(\/.*)?(\?.*)?$/;
			var hostPat = /^[a-zA-Z0-9._-]+:\d{1,5}$/;
			if (urlPat.test(value) || hostPat.test(value)) return true;
			return _('Must be a RIST URL (rist://host:port) or host:port');
		};

		o = s.option(form.Value, 'interface', _('Bind to Physical WAN Interface'),
			_('Forces this replica out of the designated physical cellular link, bypassing system-level Policy Based Routing (PBR).'));
		o.placeholder = 'wwan0';
		o.datatype = 'string';
		o.rmempty = false;

		o = s.option(form.Value, 'weight', _('Path Weight'),
			_('librist load-balancing weight for this path. 0 = duplicate the full ' +
			  'stream to this path (SMPTE 2022-7 redundancy); >0 = load-balance, ' +
			  'splitting traffic across paths in proportion to their weights.'));
		o.placeholder = '5';
		o.datatype = 'uinteger';
		o.rmempty = true;

		return m.render().then(function(node) {
			node.insertBefore(renderStatusSection(status, log), node.firstChild);
			return node;
		});
	}
});
