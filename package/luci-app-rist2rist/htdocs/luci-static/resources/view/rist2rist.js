'use strict';
'use ui';

return view.extend({
	render: function() {
		var m, s, o;

		// Initialize the primary map linked directly to /etc/config/rist2rist
		m = new form.Map('rist2rist', 
			_('RIST Multi-Path Engine & Telemetry Bridge'),
			_('Manages multi-WAN stream replication using librist socket-level interface binding. Status shifts on WAN legs are analyzed and injected backward into the local LAN segment via RIST Out-of-Band (OOB) control blocks to achieve dynamic, reactive encoder bitrate adaptation.'));

		// -------------------------------------------------------------
		// GLOBAL INGEST & LAN TELEMETRY CONFIGURATION
		// -------------------------------------------------------------
		s = m.section(form.TypedSection, 'rist2rist', _('Local Ingest Settings (LAN Receiver)'));
		s.anonymous = true;

		// Master activation engine toggle
		o = s.option(form.Flag, 'enabled', _('Enable Ingest Engine'));
		o.rmempty = false;

		// Input listen URL for incoming LAN frames
		o = s.option(form.Value, 'listen_url', _('Input Listen URL'), 
			_('The local address and port where your custom hardware encoder delivers the primary RIST feed over the stable segment.'));
		o.placeholder = 'rist://@0.0.0.0:1234';
		o.datatype = 'string';
		o.rmempty = false;

		// Toggle to activate/deactivate the backward OOB channel
		o = s.option(form.Flag, 'telemetry_enabled', _('Enable LAN OOB Backpressure'), 
			_('Instructs the proxy receiver to intercept cellular WAN metrics and push state updates backward to the encoder.'));
		o.default = o.enabled;
		o.rmempty = false;

		// RTT Hysteresis configuration to prevent local network chatter
		o = s.option(form.Value, 'rtt_hysteresis', _('RTT Change Hysteresis (ms)'), 
			_('Filters out high-frequency cellular jitter. Telemetry updates are only fired if the round-trip latency shifts by more than this value.'));
		o.placeholder = '15';
		o.datatype = 'uinteger';
		o.default = '15';
		o.depends('telemetry_enabled', '1'); // Field displays only if OOB loop is enabled


		// -------------------------------------------------------------
		// DYNAMIC MULTI-PATH REPLICAS ARRAY (WAN SENDERS)
		// -------------------------------------------------------------
		s = m.section(form.GridSection, 'destination', _('WAN Replication Outputs (SMPTE ST 2022-7 Mode)'));
		s.anonymous = true;
		s.addremove = true; // Renders dynamic "+" and "-" buttons for on-the-fly path addition

		// Remote destination target IP/Domain and Port
		o = s.option(form.Value, 'address', _('Remote Receiver Address (IP:Port)'));
		o.placeholder = '1.2.3.4:5678';
		o.datatype = 'ip4addrport';
		o.rmempty = false;

		// Physical WAN binding selector (e.g., wwan0, wwan1, usb0)
		o = s.option(form.Value, 'interface', _('Bind to Physical WAN Interface'), 
			_('Forces this replica out of the designated physical cellular link, bypassing system-level Policy Based Routing (PBR).'));
		o.placeholder = 'wwan0';
		o.datatype = 'string';
		o.rmempty = false;

		return m.render();
	}
});