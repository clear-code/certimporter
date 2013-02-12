const DEBUG = false;

const ID = 'certimporter@clear-code.com';

const Cc = Components.classes;
const Ci = Components.interfaces;

const kCID  = Components.ID('{b0e74752-55c5-4d1a-b675-67726df8c273}'); 
const kID   = '@clear-code.com/certimporter/startup;1';
const kNAME = 'CertImporterStartupService';

const ObserverService = Cc['@mozilla.org/observer-service;1']
		.getService(Ci.nsIObserverService);

const DirectoryService = Cc['@mozilla.org/file/directory_service;1']
		.getService(Ci.nsIProperties);

const Pref = Cc['@mozilla.org/preferences;1']
		.getService(Ci.nsIPrefBranch)

var certdb;
var certOverride;

const nsIX509CertDB = Ci.nsIX509CertDB;
const nsIX509Cert   = Ci.nsIX509Cert;
const nsIX509Cert2  = 'nsIX509Cert2' in Ci ? Ci.nsIX509Cert2 : null ;
const nsIX509Cert3  = 'nsIX509Cert3' in Ci ? Ci.nsIX509Cert3 : null ;

const certTypes = [
		nsIX509Cert.CA_CERT,
		nsIX509Cert.SERVER_CERT,
		nsIX509Cert.EMAIL_CERT,
		nsIX509Cert.USER_CERT
	];

var certTrusts = {};
certTrusts[nsIX509Cert.CA_CERT] = nsIX509CertDB.TRUSTED_SSL | nsIX509CertDB.TRUSTED_EMAIL | nsIX509CertDB.TRUSTED_OBJSIGN;
certTrusts[nsIX509Cert.SERVER_CERT] = nsIX509CertDB.TRUSTED_SSL;
certTrusts[nsIX509Cert.EMAIL_CERT] = nsIX509CertDB.TRUSTED_EMAIL;
certTrusts[nsIX509Cert.USER_CERT] = nsIX509CertDB.TRUSTED_EMAIL | nsIX509CertDB.TRUSTED_OBJSIGN;

const nsICertOverrideService = Ci.nsICertOverrideService;

var importAs = { '*' : 0 };
var allowRegisterAgain = false;


function mydump()
{
	if (!DEBUG) return;
	var str = Array.slice(arguments).join('\n');
	if (str.charAt(str.length-1) != '\n') str += '\n';
	dump(str);
	log(str);
}
var gLog = [];
function log(aMessage)
{
	gLog.push(aMessage);
	ObserverService.notifyObservers(null, 'log', aMessage.replace(/[\r\n]+$/, '').replace(/^/gm, '[certimporter] '));
}
 
function CertImporterStartupService() { 
}
CertImporterStartupService.prototype = {
	classID          : kCID,
	contractID       : kID,
	classDescription : kNAME,
	 
	observe : function(aSubject, aTopic, aData) 
	{
		switch (aTopic)
		{
			case 'app-startup':
			case 'profile-after-change':
				ObserverService.addObserver(this, 'final-ui-startup', false);
				return;

			case 'final-ui-startup':
				ObserverService.removeObserver(this, 'final-ui-startup');
				this.init();
				return;
		}
	},
 
	init : function() 
	{
		certdb = Cc['@mozilla.org/security/x509certdb;1']
				.getService(nsIX509CertDB);
		try {
			certOverride = Cc['@mozilla.org/security/certoverride;1']
					.getService(nsICertOverrideService);
		}
		catch(e) {
		}

		this.ensureSilent();
		this.loadPrefs();
		this.registerCerts();
	},

	ensureSilent : function()
	{
		if (!Pref.getBoolPref('extensions.certimporter.silent')) return;
		const NEWADDONS = 'extensions.newAddons';
		try {
			var list = Pref.getCharPref(NEWADDONS).split(',');
			var index = list.indexOf(ID);
			if (index > -1) {
				list.splice(index, 1);
				if (list.length)
					Pref.setCharPref(NEWADDONS, list.join(','));
				else
					Pref.clearUserPref(NEWADDONS);
			}
		}
		catch(e) {
		}
	},

	loadPrefs : function()
	{
		const prefix = 'extensions.certimporter.importAs.';
		Pref.getChildList(prefix, {}).forEach(function(aPref) {
			try {
				importAs[aPref.replace(prefix, '')] = Pref.getIntPref(aPref);
			}
			catch(e) {
			}
		}, this);

		try {
			allowRegisterAgain = Pref.getBoolPref('extensions.certimporter.allowRegisterAgain');
		}
		catch(e) {
		}
	},
 
	registerCerts : function() 
	{
		var defaults = DirectoryService.get('CurProcD', Ci.nsIFile);
		defaults.append('defaults');
		this.registerCertsInDirectory(defaults);

		var profile = DirectoryService.get('ProfD', Ci.nsIFile);
		this.registerCertsInDirectory(profile);
	},
 
	registerCertsInDirectory : function(aDirectory) 
	{
		var certCounts = {};

		var installed = {};
		certTypes.forEach(function(aType) {
			try {
				var nicknames = {};
				certdb.findCertNicknames(null, aType, {}, nicknames);
				certCounts[aType] = nicknames.value.length;
				nicknames.value.forEach(function(aNickname) {
					aNickname = aNickname.split('\x01')[1];
					var cert = certdb.findCertByNickname(null, aNickname);
					var serialized = this.serializeCert(cert);
					installed[serialized] = true;
				}, this);
			}
			catch(e) {
				// there is no cert.
			}
		}, this);

		var toBeTrusted = {};
		var toBeTrustedCount = 0;
		var certFiles = {};

		var toBeAddedToException = {};
		var toBeAddedToExceptionCount = 0;
		var overrideRules = {};

		var files = aDirectory.directoryEntries;
		while (files.hasMoreElements())
		{
			var file = files.getNext().QueryInterface(Ci.nsIFile);
			if (
				!file.isFile() ||
				!/\.(cer|crt|pem)$/i.test(file.leafName)
				)
				continue;

			mydump('CHECK '+file.path);

			var certName = file.leafName.replace(/^\s+|\s+$/g, '');
			var certDate = '';
			var lastCertDate = '';
			try {
				certDate = String(file.lastModifiedTime);
				try {
					lastCertDate = Pref.getCharPref('extensions.certimporter.certs.'+certName+'.lastDate');
				}
				catch(e) {
				}
			}
			catch(e) {
				mydump(e);
			}

			var overrideFile = file.parent;
			overrideFile.append(certName+'.override');
			mydump('CHECK '+overrideFile.path+'\n exists: '+overrideFile.exists());
			var overrideDate = '';
			var lastOverrideDate = '';
			try {
				if (certOverride && overrideFile.exists())
					overrideDate = String(overrideFile.lastModifiedTime);
				try {
					lastOverrideDate = Pref.getCharPref('extensions.certimporter.certs.'+certName+'.lastOverrideDate');
				}
				catch(e) {
				}
			}
			catch(e) {
				mydump(e);
			}

			if ((!allowRegisterAgain && lastCertDate == certDate) &&
				lastOverrideDate == overrideDate)
				continue;

			var contents = this.readFrom(file);
			if (!contents) continue;
			Pref.setCharPref('extensions.certimporter.certs.'+certName+'.lastDate', certDate);

			var count = 0;

			var overrideRule = [];
			try {
				if (certOverride) {
					if (overrideFile.exists()) {
						overrideRule = this.readFrom(overrideFile).replace(/^\s+|\s+$/g, '');
						Pref.setCharPref('extensions.certimporter.certs.'+certName+'.lastOverrideDate', overrideDate);
					}
					else {
						try {
							overrideRule = Pref.getCharPref('extensions.certimporter.override.'+certName);
						} catch(e) {
							overrideRule = null;
						}
					}
					overrideRule = overrideRule ? overrideRule.split(/\s+/) : [] ;
				}
			}
			catch(e) {
				mydump(e);
			}

			var certs = [];
			contents.split(/-+(?:BEGIN|END) CERTIFICATE-+/).forEach(function(aCert) {
				aCert = aCert.replace(/\s/g, '');
				if (!aCert) return;

				try {
					var cert = certdb.constructX509FromBase64(aCert);
					if (nsIX509Cert2) cert = cert.QueryInterface(nsIX509Cert2);

					var serialized = this.serializeCert(cert);
					var overrideCount = certOverride ? certOverride.isCertUsedForOverrides(cert, false, true) : 0 ;
					mydump("====================CERT DETECTED=======================\n");
					mydump('TYPE: '+cert.certType);
					mydump('FINGERPRINT: '+cert.sha1Fingerprint);
					mydump(serialized.split('\n')[0]);

					certFiles[serialized] = certName;
					certs.push(cert);

					var fingerprints = Pref.getCharPref('extensions.certimporter.registeringCerts');
					fingerprints = fingerprints ? fingerprints+'\n'+cert.sha1Fingerprint : cert.sha1Fingerprint ;
					Pref.setCharPref('extensions.certimporter.registeringCerts', fingerprints);

					overrideRules[serialized] = overrideRule;
					mydump('exceptions: registered='+overrideCount+', defined='+overrideRule.length);
					if (certOverride && overrideRule.length) {
						toBeAddedToException[serialized] = true;
						toBeAddedToExceptionCount++;
					}
					mydump("========================================================\n");

					try {
						if (certTypes.some(function(aType) {
								return certdb.isCertTrusted(cert, aType, certTrusts[aType]);
							}, this)) {
							mydump('already installed\n');
							return;
						}
					}
					catch(e) {
						dump(e+'\n');
					}
					mydump('to be installed\n');
					toBeTrusted[serialized] = true;
					toBeTrustedCount++;

					count++;

					importAs[certName] = cert.certType || importAs[certName] || 0;
				}
				catch(e) {
					dump(e+'\n');
				}
			}, this);

			if (!count) {
				mydump('SKIP '+file.path+' (no count)');
				continue;
			}

			mydump('certName '+certName);
			let type = certName in importAs ?
					importAs[certName] :
					importAs['*'] ;
			mydump('type '+type);
			try {
				if (type) {
					if (type & nsIX509Cert.CA_CERT) {
						mydump('IMPORT '+file.path+' as a CA cert');
						certdb.importCertsFromFile(null, file, nsIX509Cert.CA_CERT);
					}
					else {
						certTypes.forEach(function(aType) {
							if (type & aType) {
								mydump('IMPORT '+file.path+' as '+aType);
								certdb.importCertsFromFile(null, file, aType);
							}
						});
					}
				}
				else {
					mydump('SKIP '+file.path);
				}
			}
			catch(e) {
				dump('TYPE:'+type+'\n'+e+'\n');
			}
		}

		Pref.clearUserPref('extensions.certimporter.registeringCerts');

		if (!toBeTrustedCount && !toBeAddedToExceptionCount) return;

		certTypes.forEach(function(aType) {
			var nicknames = {};
			certdb.findCertNicknames(null, aType, {}, nicknames);

			if (certCounts[aType] == nicknames.value.length && !toBeAddedToExceptionCount) return;

			nicknames.value.forEach(function(aNickname) {
				aNickname = aNickname.split('\x01')[1];
				var cert;
				var serialized;
				try {
					cert = certdb.findCertByNickname(null, aNickname);
					serialized = this.serializeCert(cert);
					if (!(serialized in toBeTrusted) &&
						!(serialized in toBeAddedToException))
						return;
				}
				catch(e) {
					return;
				}

				mydump('========= '+aNickname+' ===========');
				if (nsIX509Cert2) {
					cert = cert.QueryInterface(nsIX509Cert2);
					mydump('TYPE: '+cert.certType);
				}

				if (serialized in toBeTrusted) {
					certTypes.forEach(function(aType) {
						try {
							if (!nsIX509Cert2 || cert.certType & aType) {
								mydump('register as type '+aType+': '+aNickname);
								certdb.setCertTrust(cert, aType, certTrusts[aType]);
							}
						}
						catch(e) {
							dump('TYPE:'+aType+'\n'+e+'\n');
						}
					}, this)
				}

				if (serialized in toBeAddedToException) {
					var overrideRule = overrideRules[serialized];
					if (overrideRule) {
						overrideRule.forEach(function(aPart) {
							var host, port, newFlags;
							[host, port, newFlags] = aPart.split(':');
							port     = parseInt(port);
							newFlags = parseInt(newFlags);

							var hash = {}, fingerprint = {}, flags = {}, temporary = {};
							if (
								certOverride.getValidityOverride(
									host, port,
									hash, fingerprint, flags, temporary
								) &&
								flags.value != newFlags
								) {
								certOverride.clearValidityOverride(host, port);
							}

							if (newFlags) {
								certOverride.rememberValidityOverride(
									host, port,
									cert,
									newFlags,
									false
								);
							}
						}, this);
					}
				}
			}, this);
		}, this);

		if (DEBUG)
			Cc['@mozilla.org/embedcomp/prompt-service;1'].getService(Ci.nsIPromptService).alert(null, 'log', gLog.join('\n'));
	},

	serializeCert : function(aCert)
	{
		return [
			aCert.subjectName,
			aCert.commonName,
			aCert.organization,
			aCert.organizationalUnit,
			aCert.sha1Fingerprint,
			aCert.md5Fingerprint,
			aCert.tokenName,
			aCert.issuerName,
			aCert.serialNumber,
			aCert.issuerCommonName,
			aCert.issuerOrganization,
			aCert.issuerOrganizationalUnit
		].join('\n');
	},

	readFrom : function(aFile)
	{
		var fileContents = '';

		var stream = Cc['@mozilla.org/network/file-input-stream;1']
						.createInstance(Ci.nsIFileInputStream);
		try {
			stream.init(aFile, 1, 0, false); // open as "read only"

			var scriptableStream = Cc['@mozilla.org/scriptableinputstream;1']
									.createInstance(Ci.nsIScriptableInputStream);
			scriptableStream.init(stream);

			var fileSize = scriptableStream.available();
			fileContents = scriptableStream.read(fileSize);

			scriptableStream.close();
			stream.close();
		}
		catch(e) {
			dump(e+'\n');
			return fileContents;
		}

		return fileContents;
	},
	

  
	QueryInterface : function(aIID) 
	{
		if (!aIID.equals(Ci.nsIObserver) &&
			!aIID.equals(Ci.nsISupports)) {
			throw Components.results.NS_ERROR_NO_INTERFACE;
		}
		return this;
	}
 
}; 
 	 
var gModule = { 
	registerSelf : function(aCompMgr, aFileSpec, aLocation, aType)
	{
		aCompMgr = aCompMgr.QueryInterface(Ci.nsIComponentRegistrar);
		aCompMgr.registerFactoryLocation(
			kCID,
			kNAME,
			kID,
			aFileSpec,
			aLocation,
			aType
		);

		var catMgr = Cc['@mozilla.org/categorymanager;1']
					.getService(Ci.nsICategoryManager);
		catMgr.addCategoryEntry('app-startup', kNAME, kID, true, true);
	},

	getClassObject : function(aCompMgr, aCID, aIID)
	{
		return this.factory;
	},

	factory : {
		QueryInterface : function(aIID)
		{
			if (!aIID.equals(Ci.nsISupports) &&
				!aIID.equals(Ci.nsIFactory)) {
				throw Components.results.NS_ERROR_NO_INTERFACE;
			}
			return this;
		},
		createInstance : function(aOuter, aIID)
		{
			return new CertImporterStartupService();
		}
	},

	canUnload : function(aCompMgr)
	{
		return true;
	}
};

try {
	Components.utils.import('resource://gre/modules/XPCOMUtils.jsm');
	var NSGetFactory = XPCOMUtils.generateNSGetFactory([CertImporterStartupService]);
}
catch(e) {
	var NSGetModule = function(aCompMgr, aFileSpec) {
			return gModule;
		};
}
 
