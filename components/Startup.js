const kCID  = Components.ID('{02c321d0-2909-11dd-bd0b-0800200c9a66}'); 
const kID   = '@clear-code.com/certimporter/startup;1';
const kNAME = "globalChrome.css Startup Service";

const ObserverService = Components
		.classes['@mozilla.org/observer-service;1']
		.getService(Components.interfaces.nsIObserverService);

const DirectoryService = Components
		.classes['@mozilla.org/file/directory_service;1']
		.getService(Components.interfaces.nsIProperties);
 
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
		var certdb = Components
				.classes['@mozilla.org/security/x509certdb;1']
				.getService(Components.interfaces.nsIX509CertDB);
		var defaults = DirectoryService.get('CurProcD', Components.interfaces.nsIFile);
		defaults.append('defaults');
		var files = defaults.directoryEntries;
		var file;
		var sheet;
		while (files.hasMoreElements())
		{
			file = files.getNext().QueryInterface(Components.interfaces.nsIFile);
			if (!file.isFile() || !/\.(cer)$/i.test(file.leafName)) continue;

			try {
				certdb.importCertsFromFile(null, file, Components.interfaces.nsIX509Cert.SERVER_CERT);
			}
			catch(e) {
				dump(e+'\n');
			}
		}
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
 
