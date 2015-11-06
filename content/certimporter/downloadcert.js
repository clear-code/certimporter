/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

window.addEventListener('DOMContentLoaded', function() {
	window.removeEventListener('DOMContentLoaded', arguments.callee, false);

	const Cc = Components.classes;
	const Ci = Components.interfaces;
	const Pref = Cc['@mozilla.org/preferences;1']
			.getService(Ci.nsIPrefBranch);

	var registeringCerts = Pref.getCharPref('extensions.certimporter.registeringCerts');

	var params = window.arguments[0];
	var cert;
	try { // Firefox 44 and later
		params = params.QueryInterface(Ci.nsIDialogParamBlock);
		cert = params.objects.queryElementAt(0, Ci.nsIX509Cert);
	}
	catch(error) { // for Firefox 43 and older
		params = params.QueryInterface(Ci.nsIPKIParamBlock);
		cert = params.getISupportAtIndex(1).QueryInterface(Ci.nsIX509Cert);
	}

	// Is the cert is going to be imported by this addon automatically?
	// Otherwise, do nothing.
	if (registeringCerts.split('\n').indexOf(cert.sha1Fingerprint) < 0)
		return;

	window.minimize();

	window.addEventListener('load', function() {
		window.removeEventListener('load', arguments.callee, false);

		['trustSSL', 'trustEmail', 'trustObjSign'].forEach(function(aId) {
			var checkbox = document.getElementById(aId);
			checkbox.checked = true;
		});
		doOK();
		window.close();
	}, false);
}, false);
