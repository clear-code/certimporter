const DEBUG = false;

const Cc = Components.classes;
const Ci = Components.interfaces;

const kCID  = Components.ID('{b0e74752-55c5-4d1a-b675-67726df8c273}'); 
const kID   = '@clear-code.com/certimporter/startup;1';
const kNAME = "Cert Importer Startup Service";

const ObserverService = Cc['@mozilla.org/observer-service;1']
		.getService(Ci.nsIObserverService);

const DirectoryService = Cc['@mozilla.org/file/directory_service;1']
		.getService(Ci.nsIProperties);

const Pref = Cc['@mozilla.org/preferences;1']
		.getService(Ci.nsIPrefBranch)

var certdb;

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


function mydump()
{
	if (!DEBUG) return;
	var str = Array.slice(arguments).join('\n');
	if (str.charAt(str.length-1) != '\n') str += '\n';
	dump(str);
}
 
function CertImporterStartupService() { 
}
CertImporterStartupService.prototype = {
	 
	observe : function(aSubject, aTopic, aData) 
	{
		switch (aTopic)
		{
			case 'app-startup':
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

		this.registerCerts();
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

		var files = aDirectory.directoryEntries;
		while (files.hasMoreElements())
		{
			var file = files.getNext().QueryInterface(Ci.nsIFile);
			if (
				!file.isFile() ||
				!/\.(cer|crt|pem)$/i.test(file.leafName)
				)
				continue;

			var contents = this.readFrom(file);
			if (!contents) continue;

			var count = 0;
			var counts = {};
			counts[nsIX509Cert.CA_CERT] = 0;
			counts[nsIX509Cert.SERVER_CERT] = 0;
			counts[nsIX509Cert.EMAIL_CERT] = 0;
			counts[nsIX509Cert.USER_CERT] = 0;

			contents.split(/-+(?:BEGIN|END) CERTIFICATE-+/).forEach(function(aCert) {
				aCert = aCert.replace(/\s/g, '');
				if (!aCert) return;

				try {
					var cert = certdb.constructX509FromBase64(aCert);
					if (nsIX509Cert2) cert = cert.QueryInterface(nsIX509Cert2);

					var serialized = this.serializeCert(cert);
					mydump("====================CERT DETECTED=======================\n");
					mydump('TYPE: '+cert.certType);
					mydump(serialized.split('\n')[0]);
					mydump("========================================================\n");
					if (serialized in installed) {
						if (certTypes.some(function(aType) {
								certdb.isCertTrusted(cert, aType, certTrusts[aType])
							}, this)) {
							mydump('already installed\n');
							return;
						}
					}
					mydump('to be installed\n');
					toBeTrusted[serialized] = true;
					count++;
					toBeTrustedCount++;

					certTypes.forEach(function(aType) {
						if (!nsIX509Cert2 ||
							!cert.certType ||
							cert.certType & aType)
							counts[aType]++;
					}, this)
					// hack to force-detect CA certs
					if (cert.certType == nsIX509Cert.CA_CERT)
						counts[nsIX509Cert.SERVER_CERT]++;
				}
				catch(e) {
					dump(e+'\n');
				}
			}, this);

			if (!count) {
				mydump('SKIP '+file.path+' (no count)');
				continue;
			}

			var type = null;
			certTypes.some(function(aType) {
				if (aType == nsIX509Cert.CA_CERT) return false;
				if (!nsIX509Cert2 || counts[aType]) {
					type = aType;
					return true;
				}
				return false;
			}, this)
			try {
				if (type) {
					mydump('IMPORT '+file.path+' as '+type);
					certdb.importCertsFromFile(null, file, type);
				}
				else {
					mydump('SKIP '+file.path);
				}
			}
			catch(e) {
				dump('TYPE:'+type+'\n'+e+'\n');
			}
		}

		if (!toBeTrustedCount) return;

		var importAsCACert = false;
		try {
			importAsCACert = Pref.getBoolPref('extensions.certimporter.importAsCACert');
		}
		catch(e) {
		}

		certTypes.forEach(function(aType) {
			var nicknames = {};
			certdb.findCertNicknames(null, aType, {}, nicknames);

			if (certCounts[aType] == nicknames.value.length) return;

			nicknames.value.forEach(function(aNickname) {
				aNickname = aNickname.split('\x01')[1];
				var cert;
				try {
					cert = certdb.findCertByNickname(null, aNickname);
					if (!(this.serializeCert(cert) in toBeTrusted)) return;
				}
				catch(e) {
					return;
				}

				mydump('========= '+aNickname+' ===========');
				if (nsIX509Cert2) {
					cert = cert.QueryInterface(nsIX509Cert2);
					mydump('TYPE: '+cert.certType);
				}

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

				if (!importAsCACert) return;
				try {
					var cacert = null;
					var issuer = cert;
					var lastIssuer = '';
					while (issuer)
					{
						mydump('CA check: '+issuer.subjectName);
						if ((nsIX509Cert2 && (issuer.certType & nsIX509Cert.CA_CERT)) ||
							issuer.subjectName == lastIssuer) {
							mydump(issuer.subjectName+' is CA');
							if (nsIX509Cert2) mydump('  (type: '+issuer.certType+')');
							cacert = issuer;
							break;
						}
						lastIssuer = issuer.subjectName;
						issuer = issuer.issuer;
						if (issuer && nsIX509Cert2) issuer = issuer.QueryInterface(nsIX509Cert2);
					}
					if (cacert) {
						mydump('register '+cacert.subjectName+' as a CA cert\n');
						certdb.setCertTrust(cacert, nsIX509Cert.CA_CERT, certTrusts[nsIX509Cert.CA_CERT]);
					}
				}
				catch(e) {
					dump(e+'\n');
				}
			}, this);
		}, this);
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

	readFrom : function(aFile, aEncoding)
	{
		var fileContents;

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
			return null;
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

function NSGetModule(aCompMgr, aFileSpec) {
	return gModule;
}
 
