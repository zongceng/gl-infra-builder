'use strict';
'require view';
'require ui';
'require rpc';
'require uci';
'require form';
'require tools.transip as tools'

return view.extend({
	callHostHints: rpc.declare({
		object: 'luci-rpc',
		method: 'getHostHints',
		expect: { '': {} }
	}),

	callNetworkDevices: rpc.declare({
		object: 'luci-rpc',
		method: 'getNetworkDevices',
		expect: { '': {} }
	}),

	getServerConfig: rpc.declare({
		object: 'luci.transip',
		method: 'get_server_config'
	}),

	reloadTransip: rpc.declare({
		object: 'luci.transip',
		method: 'reload_transip'
	}),

	bindToken: rpc.declare({
		object: 'luci.transip',
		method: 'bind_token',
	}),

	load: function() {
		return Promise.all([
		]);
	},

	handleSaveApply: async function(ev) {
		await this.handleSave()
		await ui.changes.apply()
		await this.sleep(1000);
		await this.bindToken()
	},

	sleep: function(ms) {
		return new Promise(resolve => setTimeout(resolve, ms));
	},

  render: function(data) {
		var s,o,m;
    m = new form.Map('transip', _('TransIP - 住宅IP代理'),
			_('通过TransIP的住宅IP代理服务，您可以以家庭网络的IP地址访问互联网。'));

    s = m.section(form.TypedSection, 'info', _('设备绑定'));
		s.anonymous = true;
		s.addremove = false;

		o = s.option(form.Value, "is_bind", _("绑定状态"));
		o.readonly = true
		o.editable = false
		o.modalonly = true

		o = s.option(form.Value, "token", _("token"));
		o.rmempty = false;
		o.optional = true;

  return m.render();
  }
});