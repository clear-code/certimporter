const kCID  = Components.ID('{b0e74752-55c5-4d1a-b675-67726df8c273}'); 
const kID   = '@clear-code.com/certimporter/startup;1';
const kNAME = "Cert Importer Startup Service";

const ObserverService = Components
		.classes['@mozilla.org/observer-service;1']
		.getService(Components.interfaces.nsIObserverService);

const DirectoryService = Components
		.classes['@mozilla.org/file/directory_service;1']
		.getService(Components.interfaces.nsIProperties);


const DEBUG = false;

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
		this.registerCerts();
	},
 
	registerCerts : function() 
	{
		const nsIX509CertDB = Components.interfaces.nsIX509CertDB;
		const nsIX509Cert = Components.interfaces.nsIX509Cert;

		var certdb = Components
				.classes['@mozilla.org/security/x509certdb;1']
				.getService(nsIX509CertDB);

		var installed = {};
		var nicknames = {};
		try {
			certdb.findCertNicknames(null, nsIX509Cert.SERVER_CERT, {}, nicknames);
			nicknames.value.forEach(function(aNickname) {
				aNickname = aNickname.split('\x01')[1];
				var cert = this.serializeCert(certdb.findCertByNickname(null, aNickname));
				installed[cert] = true;
			}, this);
		}
		catch(e) {
			// there is no cert.
		}

		var toBeTrusted = {};

		var defaults = DirectoryService.get('CurProcD', Components.interfaces.nsIFile);
		defaults.append('defaults');
		var files = defaults.directoryEntries;
		while (files.hasMoreElements())
		{
			var file = files.getNext().QueryInterface(Components.interfaces.nsIFile);
			if (!file.isFile() || !/\.(cer|crt)$/i.test(file.leafName)) continue;

			var contents = this.readFrom(file);
			if (!contents) continue;

			var count = 0;
			contents.split(/-+(?:BEGIN|END) CERTIFICATE-+/).forEach(function(aCert) {
				aCert = aCert.replace(/\s/g, '');
				if (!aCert) return;

				try {
					var cert = certdb.constructX509FromBase64(aCert);
					var serialized = this.serializeCert(cert);
					mydump("====================CERT DETECTED=======================\n");
					mydump(serialized+'\n');
					mydump("========================================================\n");
					if (serialized in installed &&
						certdb.isCertTrusted(cert, nsIX509Cert.SERVER_CERT, nsIX509CertDB.TRUSTED_SSL)) {
						mydump('already installed\n');
						return;
					}
					mydump('to be installed\n');
					toBeTrusted[serialized] = true;
					count++;
				}
				catch(e) {
					dump(e+'\n');
				}
			}, this);
			if (!count) continue;

			try {
				certdb.importCertsFromFile(null, file, nsIX509Cert.SERVER_CERT);
			}
			catch(e) {
				dump(e+'\n');
			}
		}

		nicknames = {};
		certdb.findCertNicknames(null, nsIX509Cert.SERVER_CERT, {}, nicknames);
		nicknames.value.forEach(function(aNickname) {
			aNickname = aNickname.split('\x01')[1];
			var cert = certdb.findCertByNickname(null, aNickname);
			if (!(this.serializeCert(cert) in toBeTrusted)) return;
			try {
				mydump('register '+aNickname+' as a SSL server cert\n');
				certdb.setCertTrust(cert, nsIX509Cert.SERVER_CERT, nsIX509CertDB.TRUSTED_SSL);

				var cacert = null;
				var issuer = cert;
				var lastIssuer = '';
				while (issuer)
				{
					if (issuer.type == nsIX509Cert.CA_CERT ||
						issuer.subjectName == lastIssuer) {
						cacert = issuer;
						break;
					}
					lastIssuer = issuer.subjectName;
					issuer = issuer.issuer;
				}
				if (cacert) {
					mydump('register '+aNickname+' as a CA cert\n');
					certdb.setCertTrust(cacert, nsIX509Cert.CA_CERT, nsIX509CertDB.TRUSTED_SSL);
				}
			}
			catch(e) {
				dump(e+'\n');
			}
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

		var stream = Components
						.classes['@mozilla.org/network/file-input-stream;1']
						.createInstance(Components.interfaces.nsIFileInputStream);
		try {
			stream.init(aFile, 1, 0, false); // open as "read only"

			var scriptableStream = Components
									.classes['@mozilla.org/scriptableinputstream;1']
									.createInstance(Components.interfaces.nsIScriptableInputStream);
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
		if(!aIID.equals(Components.interfaces.nsIObserver) &&
			!aIID.equals(Components.interfaces.nsISupports)) {
			throw Components.results.NS_ERROR_NO_INTERFACE;
		}
		return this;
	}
 
}; 
 	 
var gModule = { 
	registerSelf : function(aCompMgr, aFileSpec, aLocation, aType)
	{
		aCompMgr = aCompMgr.QueryInterface(Components.interfaces.nsIComponentRegistrar);
		aCompMgr.registerFactoryLocation(
			kCID,
			kNAME,
			kID,
			aFileSpec,
			aLocation,
			aType
		);

		var catMgr = Components.classes['@mozilla.org/categorymanager;1']
					.getService(Components.interfaces.nsICategoryManager);
		catMgr.addCategoryEntry('app-startup', kNAME, kID, true, true);
	},

	getClassObject : function(aCompMgr, aCID, aIID)
	{
		return this.factory;
	},

	factory : {
		QueryInterface : function(aIID)
		{
			if (!aIID.equals(Components.interfaces.nsISupports) &&
				!aIID.equals(Components.interfaces.nsIFactory)) {
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
 
