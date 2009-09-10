/* Logging Service for debug
   usage:
     ObserverService.notifyObservers(null, 'log', 'message to be logged');
*/

const LOG_DIRECTORY_KEY = 'ProfD'; // 'CurProcD';

const ObserverService = Components 
		.classes['@mozilla.org/observer-service;1']
		.getService(Components.interfaces.nsIObserverService);

function LoggingService() { 
}
LoggingService.prototype = {

	disabled : true,

	kCID  : Components.ID('{e6f309e0-e76a-11dd-ba2f-0800200c9a66}'),
	kID   : '@clear-code.com/logging/server;1',
	kNAME : 'Logging Service',
	 
	observe : function(aSubject, aTopic, aData) 
	{
		switch (aTopic)
		{
			case 'app-startup':
				this.logFile = Components 
					.classes['@mozilla.org/file/directory_service;1']
					.getService(Components.interfaces.nsIProperties)
					.get(LOG_DIRECTORY_KEY, Components.interfaces.nsIFile);
				this.logFile.append('log.txt');
				if (!this.disabled) {
					if (this.logFile.exists()) this.logFile.remove(true);
					return;
				}
				if (!this.logFile.exists()) {
					this.logFile.create(this.logFile.NORMAL_FILE_TYPE, 0666);
				}

				ObserverService.addObserver(this, 'log', false);
				ObserverService.addObserver(this, 'quit-application', false);

				this.log('');
				this.log('===========================START===========================');
				var date = new Date();
				this.log(
					date.getFullYear()+
					'.'+
					this.fillWithZero(date.getMonth()+1, 2)+
					'.'+
					this.fillWithZero(date.getDate(), 2)
					);
				this.logWithDate('LoggingService starts');

				return;

			case 'quit-application':
				this.logWithDate('LoggingService finishes');
				this.log('============================END============================');
				this.log('');
				ObserverService.removeObserver(this, 'log');
				ObserverService.removeObserver(this, 'quit-application');
				return;

			case 'log':
				this.logWithDate((aSubject ? aSubject+' ' : '')+aData);
				break;
		}
	},

	logFile : null,

	logWithDate : function(aMessage) 
	{
		var output = [];
		var date = new Date();
		output.push(this.fillWithZero(date.getHours(), 2));
		output.push(':');
		output.push(this.fillWithZero(date.getMinutes(), 2));
		output.push(':');
		output.push(this.fillWithZero(date.getSeconds(), 2));
		output.push('.');
		output.push(this.fillWithZero(date.getMilliseconds(), 3));
		output.push(' ');
		output.push(aMessage);
		this.log(output.join(''));
	},

	log : function(aMessage)
	{
		aMessage = aMessage.replace(/[\r\n]+$/g, '') + '\r\n';
		try {
			var stream = Components
					.classes['@mozilla.org/network/file-output-stream;1']
					.createInstance(Components.interfaces.nsIFileOutputStream);
			stream.init(this.logFile, 0x02 | 0x10, 0x200, false);
			var converterStream = Components
					.classes['@mozilla.org/intl/converter-output-stream;1']
					.createInstance(Components.interfaces.nsIConverterOutputStream);
			converterStream.init(stream, 'UTF-8', aMessage.length,
				Components.interfaces.nsIConverterInputStream.DEFAULT_REPLACEMENT_CHARACTER);
			converterStream.writeString(aMessage);
			converterStream.close();
			stream.close();
		}
		catch(e) {
			dump(e);
		}
	},

	fillWithZero : function(aSource, aLength)
	{
		var string = String(aSource);
		while (aLength > string.length)
		{
			string = '0' + string;
		}
		return string;
	},
 
	QueryInterface : function(aIID) 
	{
		if (!aIID.equals(Components.interfaces.nsIObserver) &&
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
		var catMgr = Components.classes['@mozilla.org/categorymanager;1']
					.getService(Components.interfaces.nsICategoryManager);
		for (var key in this._objects) {
			var obj = this._objects[key];
			aCompMgr.registerFactoryLocation(obj.CID, obj.className, obj.contractID, aFileSpec, aLocation, aType);
			if (obj.category)
				catMgr.addCategoryEntry(obj.category, obj.entry || obj.className, obj.contractID, true, true);
		}
	},

	getClassObject : function(aCompMgr, aCID, aIID)
	{
		if (!aIID.equals(Components.interfaces.nsIFactory))
			throw Components.results.NS_ERROR_NOT_IMPLEMENTED;

		for (var key in this._objects) {
			if (aCID.equals(this._objects[key].CID))
				return this._objects[key].factory;
		}

		throw Components.results.NS_ERROR_NO_INTERFACE;
	},

	_objects : {
		LoggingService : {
			CID        : LoggingService.prototype.kCID,
			contractID : LoggingService.prototype.kID,
			className  : LoggingService.prototype.kNAME,
			factory    : {
				createInstance : function (aOuter, aIID)
				{
					if (aOuter != null)
						throw Components.results.NS_ERROR_NO_AGGREGATION;
					return (new LoggingService()).QueryInterface(aIID);
				}
			},
			category   : 'app-startup'
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
 
