
'use strict';
'require baseclass';
'require dom';
'require ui';
'require uci';
'require form';
'require network';
'require validation';

return baseclass.extend({
	transformHostHints: function(family, hosts) {
		var choice_values = [],
		    choice_labels = {},
		    ip6addrs = {},
		    ipaddrs = {};

		for (var mac in hosts) {
			L.toArray(hosts[mac].ipaddrs || hosts[mac].ipv4).forEach(function(ip) {
				ipaddrs[ip] = mac;
			});

			L.toArray(hosts[mac].ip6addrs || hosts[mac].ipv6).forEach(function(ip) {
				ip6addrs[ip] = mac;
			});
		}

		if (!family || family == 'ipv4') {
			L.sortedKeys(ipaddrs, null, 'addr').forEach(function(ip) {
				var val = ip,
				    txt = hosts[ipaddrs[ip]].name || ipaddrs[ip];

				choice_values.push(val);
				choice_labels[val] = E([], [ val, ' (', E('strong', {}, [txt]), ')' ]);
			});
		}

		if (!family || family == 'ipv6') {
			L.sortedKeys(ip6addrs, null, 'addr').forEach(function(ip) {
				var val = ip,
				    txt = hosts[ip6addrs[ip]].name || ip6addrs[ip];

				choice_values.push(val);
				choice_labels[val] = E([], [ val, ' (', E('strong', {}, [txt]), ')' ]);
			});
		}

		return [choice_values, choice_labels];
	},

  CBIDynamicMultiValueList: form.DynamicList.extend({
		renderWidget: function(/* ... */) {
			var dl = form.DynamicList.prototype.renderWidget.apply(this, arguments),
			    inst = dom.findClassInstance(dl);

			inst.addItem = function(dl, value, text, flash) {
				var values = L.toArray(value);
				for (var i = 0; i < values.length; i++)
					ui.DynamicList.prototype.addItem.call(this, dl, values[i], null, true);
			};

			return dl;
		}
	}),

  addIPOption: function(s, name, label, description, family, hosts, multiple) {
		var o = s.option(multiple ? this.CBIDynamicMultiValueList : form.Value, name, label, description);

		o.modalonly = null;
		o.datatype = 'list(neg(ipmask("true")))';
		o.placeholder = multiple ? _('-- add IP --') : _('any');

		if (family != null) {
			var choices = this.transformHostHints(family, hosts);

			for (var i = 0; i < choices[0].length; i++)
				o.value(choices[0][i], choices[1][choices[0][i]]);
		}

		/* force combobox rendering */
		o.transformChoices = function() {
			return this.super('transformChoices', []) || {};
		};

		return o;
	},

	addMACOption: function(s, name, label, description, hosts) {
		var o = s.option(this.CBIDynamicMultiValueList, name, label, description);

		o.modalonly = null;
		o.datatype = 'list(macaddr)';
		o.placeholder = _('-- add MAC --');

		L.sortedKeys(hosts).forEach(function(mac) {
			o.value(mac, E([], [ mac, ' (', E('strong', {}, [
				hosts[mac].name ||
				L.toArray(hosts[mac].ipaddrs || hosts[mac].ipv4)[0] ||
				L.toArray(hosts[mac].ip6addrs || hosts[mac].ipv6)[0] ||
				'?'
			]), ')' ]));
		});

		return o;
	},
});