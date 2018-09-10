{// Cert Importer, for Firefox 52/Thunderbird 52 and later
  const { classes: Cc, interfaces: Ci, utils: Cu } = Components;
  const { Services } = Cu.import('resource://gre/modules/Services.jsm', {});

  const ID = 'certimporter@clear-code.com';

  const ObserverService = Cc['@mozilla.org/observer-service;1']
    .getService(Ci.nsIObserverService);

  const DirectoryService = Cc['@mozilla.org/file/directory_service;1']
      .getService(Ci.nsIProperties);

  const Pref = Cc['@mozilla.org/preferences;1']
      .getService(Ci.nsIPrefBranch)

  let certdb;
  let certOverride;

  const nsIX509CertDB = Ci.nsIX509CertDB;
  const nsIX509Cert   = Ci.nsIX509Cert;
  const nsIX509Cert2  = 'nsIX509Cert2' in Ci ? Ci.nsIX509Cert2 : null ;

  const certTypes = [
    nsIX509Cert.CA_CERT,
    nsIX509Cert.SERVER_CERT,
    nsIX509Cert.EMAIL_CERT,
    nsIX509Cert.USER_CERT
  ];

  const certTrusts = {};
  certTrusts[nsIX509Cert.CA_CERT] = nsIX509CertDB.TRUSTED_SSL | nsIX509CertDB.TRUSTED_EMAIL | nsIX509CertDB.TRUSTED_OBJSIGN;
  certTrusts[nsIX509Cert.SERVER_CERT] = nsIX509CertDB.TRUSTED_SSL;
  certTrusts[nsIX509Cert.EMAIL_CERT] = nsIX509CertDB.TRUSTED_EMAIL;
  certTrusts[nsIX509Cert.USER_CERT] = nsIX509CertDB.TRUSTED_EMAIL | nsIX509CertDB.TRUSTED_OBJSIGN;

  const nsICertOverrideService = Ci.nsICertOverrideService;

  const importAs = { '*' : 0 };
  let allowRegisterAgain = false;

  const DEBUG_KEY = 'extensions.certimporter.debug';
  let DEBUG = false;

  const mydump = () => {
    if (!DEBUG)
      return;
    const str = Array.slice(arguments).join('\n');
    Cc['@mozilla.org/consoleservice;1']
      .getService(Ci.nsIConsoleService)
      .logStringMessage('[certimporter] ' + str);
  };

  const observer = {
    observe(aSubject, aTopic, aData) {
      switch (aTopic) {
        case 'final-ui-startup':
          ObserverService.removeObserver(this, 'final-ui-startup');
          this.init();
          return;
      }
    },
 
    init() {
      DEBUG = Pref.getBoolPref(DEBUG_KEY);
      mydump('initialize');

      certdb = Cc['@mozilla.org/security/x509certdb;1']
          .getService(nsIX509CertDB);
      mydump('certdb = ', certdb);
      try {
        certOverride = Cc['@mozilla.org/security/certoverride;1']
            .getService(nsICertOverrideService);
      }
      catch(e) {
        mydump('FAILED TO GET CERT OVERRIDE SERVICE!\n'+e+'\n');
      }

      ensureSilent();
      loadPrefs();
      registerCerts();
    },
    
    QueryInterface(aIID) {
      if (!aIID.equals(Ci.nsIObserver) &&
          !aIID.equals(Ci.nsISupports)) {
        throw Components.results.NS_ERROR_NO_INTERFACE;
      }
      return this;
    }
  };

  const ensureSilent = () => {
    if (!Pref.getBoolPref('extensions.certimporter.silent')) return;
    const NEWADDONS = 'extensions.newAddons';
    try {
      let list = Pref.getCharPref(NEWADDONS).split(',');
      let index = list.indexOf(ID);
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
  };

  const loadPrefs = () => {
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
  };
 
  const registerCerts = () => {
    let defaults = DirectoryService.get('CurProcD', Ci.nsIFile);
    defaults.append('defaults');
    mydump('global1 '+defaults.path+' : '+defaults.exists());
    if (defaults.exists())
      registerCertsInDirectory(defaults);

    defaults = DirectoryService.get('GreD', Ci.nsIFile);
    defaults.append('defaults');
    mydump('global2 '+defaults.path+' : '+defaults.exists());
    if (defaults.exists())
      registerCertsInDirectory(defaults);

    let profile = DirectoryService.get('ProfD', Ci.nsIFile);
    mydump('private '+profile.path+' : '+profile.exists());
    if (profile.exists())
      registerCertsInDirectory(profile);
  };
 
  const registerCertsInDirectory = (aDirectory) => {
    let certCounts = {};

    let installed = {};
    certTypes.forEach(aType => {
      try {
        let nicknames = getCertNamesByType(certdb, aType);
        certCounts[aType] = nicknames.length;
        nicknames.forEach(aNickname => {
          aNickname = aNickname.split('\x01')[1];
          let cert = getCertByName(certdb, aNickname);
          let serialized = serializeCert(cert);
          installed[serialized] = true;
        });
      }
      catch(e) {
        // there is no cert.
      }
    });

    let toBeTrusted = {};
    let toBeTrustedCount = 0;
    let certFiles = {};

    let toBeAddedToException = {};
    let toBeAddedToExceptionCount = 0;
    let overrideRules = {};

    let files = aDirectory.directoryEntries;
    while (files.hasMoreElements()) {
      const file = files.getNext().QueryInterface(Ci.nsIFile);
      if (!file.isFile() ||
          !/\.(cer|crt|pem|der)$/i.test(file.leafName))
        continue;

      mydump('CHECK '+file.path);

      let certName = file.leafName.replace(/^\s+|\s+$/g, '');
      let certDate = '';
      let lastCertDate = '';
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

      let overrideFile = file.parent;
      overrideFile.append(certName+'.override');
      mydump('CHECK '+overrideFile.path+'\n exists: '+overrideFile.exists());
      let overrideDate = '';
      let lastOverrideDate = '';
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

      let contents = readFrom(file);
      if (!contents) continue;
      Pref.setCharPref('extensions.certimporter.certs.'+certName+'.lastDate', certDate);

      let count = 0;

      let overrideRule = [];
      try {
        if (certOverride) {
          if (overrideFile.exists()) {
            overrideRule = readFrom(overrideFile).replace(/^\s+|\s+$/g, '');
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

      let certs = [];
      let decodedCerts = [];
      if (/\.der$/i.test(file.leafName)) {
        try {
          decodedCerts.push(certdb.constructX509(contents, contents.length));
        }
        catch(e) {
          mydump(e+'\n');
        }
      }
      else {
        contents.split(/-+(?:BEGIN|END) CERTIFICATE-+/).forEach(aCert => {
          aCert = aCert.replace(/\s/g, '');
          if (!aCert) return;
          try {
            decodedCerts.push(certdb.constructX509FromBase64(aCert));
          }
          catch(e) {
            mydump(e+'\n');
          }
        });
      }
      decodedCerts.forEach(aCert => {
        try {
          if (nsIX509Cert2)
            aCert = aCert.QueryInterface(nsIX509Cert2);

          let serialized = serializeCert(aCert);
          let overrideCount = certOverride ? certOverride.isCertUsedForOverrides(aCert, false, true) : 0 ;
          mydump("====================CERT DETECTED=======================\n");
          mydump('TYPE: '+aCert.certType);
          mydump('FINGERPRINT: '+aCert.sha1Fingerprint);
          mydump(serialized.split('\n')[0]);

          certFiles[serialized] = certName;
          certs.push(aCert);

          overrideRules[serialized] = overrideRule;
          mydump('exceptions: registered='+overrideCount+', defined='+overrideRule.length);
          if (certOverride && overrideRule.length) {
            mydump(' => to be added to exception!');
            toBeAddedToException[serialized] = true;
            toBeAddedToExceptionCount++;
          }
          mydump("========================================================\n");

          try {
            if (certTypes.some(aType => {
                  return certdb.isCertTrusted(aCert, aType, certTrusts[aType]);
                })) {
              mydump('already installed\n');
              return;
            }
          }
          catch(e) {
            mydump(e+'\n');
          }
          mydump('to be installed\n');
          toBeTrusted[serialized] = true;
          toBeTrustedCount++;

          count++;

          importAs[certName] = importAs[certName] || aCert.certType || 0;
        }
        catch(e) {
          mydump(e+'\n');
        }
      });

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
            importFromFile(certdb, file, nsIX509Cert.CA_CERT);
            mydump('done.');
          }
          else {
            certTypes.forEach(function(aType) {
              if (type & aType) {
                mydump('IMPORT '+file.path+' as '+aType);
                importFromFile(certdb, file, aType);
                mydump('done.');
              }
            });
          }
        }
        else {
          mydump('SKIP '+file.path);
        }
      }
      catch(e) {
        mydump('Error, TYPE:'+type+'\n'+e+'\n');
      }
    }

    if (!toBeTrustedCount && !toBeAddedToExceptionCount) return;

    certTypes.forEach(aType => {
      let nicknames = getCertNamesByType(certdb, aType);

      if (certCounts[aType] == nicknames.length && !toBeAddedToExceptionCount)
        return;

      nicknames.forEach(aNickname => {
        aNickname = aNickname.split('\x01')[1];
        let cert;
        let serialized;
        try {
          cert = getCertByName(certdb, aNickname);
          serialized = serializeCert(cert);
          if (!(serialized in toBeTrusted) &&
            !(serialized in toBeAddedToException))
            return;
        }
        catch(e) {
          return;
        }

        mydump('========= '+aNickname+' ===========');
        if (nsIX509Cert2)
          cert = cert.QueryInterface(nsIX509Cert2);

        mydump('TYPE: '+cert.certType);

        if (serialized in toBeTrusted) {
          certTypes.forEach(aType => {
            try {
              if (!('certType' in cert) || cert.certType & aType) {
                mydump('register as type '+aType+': '+aNickname);
                certdb.setCertTrust(cert, aType, certTrusts[aType]);
              }
            }
            catch(e) {
              mydump('TYPE:'+aType+'\n'+e+'\n');
            }
          })
        }

        if (serialized in toBeAddedToException) {
          let overrideRule = overrideRules[serialized];
          if (overrideRule) {
            overrideRule.forEach(aPart => {
              mydump('apply override rule '+aPart+' for '+aNickname);
              aPart = aPart.replace(/^\s+|\s+$/g, '');
              if (/^\/\/|^\#/.test(aPart) ||
                  !/^[^:]+:\d+:\d+$/.test(aPart))
                return;
              let host, port, newFlags;
              [host, port, newFlags] = aPart.split(':');
              port     = parseInt(port);
              newFlags = parseInt(newFlags);

              let hash = {}, fingerprint = {}, flags = {}, temporary = {};
              if (certOverride.getValidityOverride(
                    host, port,
                    hash, fingerprint, flags, temporary
                  ) &&
                  flags.value != newFlags) {
                mydump('  clear validity for '+host+':'+port);
                certOverride.clearValidityOverride(host, port);
              }

              mydump('  new flags for '+host+':'+port+' = '+newFlags);
              if (newFlags) {
                certOverride.rememberValidityOverride(
                  host, port,
                  cert,
                  newFlags,
                  false
                );
              }
            });
          }
        }
      });
    });
  };

  const getCertNamesByType = (aCertDB, aType) => {
    if (typeof aCertDB.findCertNicknames == 'function') { // Firefox 46 or older
      // findCertNicknames is removed by https://bugzilla.mozilla.org/show_bug.cgi?id=1241650
      let nicknames = {};
      aCertDB.findCertNicknames(null, aType, {}, nicknames);
      return nicknames.value;
    }
    else { // Firefox 47 and later
      let certs = aCertDB.getCerts();
      certs = certs.getEnumerator();
      let names = [];
      while (certs.hasMoreElements()) {
        let cert = certs.getNext().QueryInterface(Ci.nsIX509Cert);
        if (cert.certType & aType)
          names.push(cert.nickname);
      }
      return names;
    }
  };

  const getCertByName = (aCertDB, aName) => {
    if (aCertDB.findCertByNickname.length == 2) { // Firefox 46 and older
      // The first argument was removed by https://bugzilla.mozilla.org/show_bug.cgi?id=1241646
      return aCertDB.findCertByNickname(null, aName);
    }
    else { // Firefox 47 and later
      return aCertDB.findCertByNickname(aName);
    }
  };

  const importFromFile = (aCertDB, aFile, aType) => {
    if (aCertDB.importCertsFromFile.length == 3) { // Firefox 46 and older
      // The first argument was removed by https://bugzilla.mozilla.org/show_bug.cgi?id=1241646
      aCertDB.importCertsFromFile(null, aFile, aType);
    }
    else { // Firefox 47 and later
      aCertDB.importCertsFromFile(aFile, aType);
    }
  };

  const serializeCert = (aCert) => {
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
  };

  const readFrom = (aFile) => {
    let fileContents = '';

    let stream = Cc['@mozilla.org/network/file-input-stream;1']
            .createInstance(Ci.nsIFileInputStream);
    try {
      stream.init(aFile, 1, 0, false); // open as "read only"

      let scriptableStream = Cc['@mozilla.org/scriptableinputstream;1']
                  .createInstance(Ci.nsIScriptableInputStream);
      scriptableStream.init(stream);

      let fileSize = scriptableStream.available();
      fileContents = scriptableStream.read(fileSize);

      scriptableStream.close();
      stream.close();
    }
    catch(e) {
      mydump(e+'\n');
      return fileContents;
    }

    return fileContents;
  };

  ObserverService.addObserver(observer, 'final-ui-startup', false);
}; 
