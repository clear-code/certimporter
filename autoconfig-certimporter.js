{// Cert Importer, for Firefox 52/Thunderbird 52 and later
  const { classes: Cc, interfaces: Ci, utils: Cu } = Components;
  const { Services } = Cu.import('resource://gre/modules/Services.jsm', {});

  const ID = 'certimporter@clear-code.com';
  const BASE = 'extensions.certimporter.';

  const ObserverService = Cc['@mozilla.org/observer-service;1']
    .getService(Ci.nsIObserverService);

  const DirectoryService = Cc['@mozilla.org/file/directory_service;1']
      .getService(Ci.nsIProperties);

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

  const DEBUG_KEY = BASE + 'debug';
  let DEBUG = false;

  const log = (...args) => {
    if (!DEBUG)
      return;
    const str = Array.slice(args).join('\n');
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
        case 'domwindowopened':
          if (!aSubject.QueryInterface(Ci.nsIInterfaceRequestor)
                       .getInterface(Ci.nsIWebNavigation)
                       .QueryInterface(Ci.nsIDocShell)
                       .QueryInterface(Ci.nsIDocShellTreeNode || Ci.nsIDocShellTreeItem) // nsIDocShellTreeNode is merged to nsIDocShellTreeItem by https://bugzilla.mozilla.org/show_bug.cgi?id=331376
                       .QueryInterface(Ci.nsIDocShellTreeItem)
                       .parent)
            aSubject.QueryInterface(Ci.nsIDOMWindow)
                    .addEventListener('DOMContentLoaded', () => {
                      handleAutoConfirmWindow(aSubject.QueryInterface(Ci.nsIDOMWindow));
                    }, { once: true });
          return;
      }
    },
 
    init() {
      try {
        DEBUG = Services.prefs.getBoolPref(DEBUG_KEY);
      }
      catch(e) {
      }
      log('initialize');

      certdb = Cc['@mozilla.org/security/x509certdb;1']
          .getService(nsIX509CertDB);
      log('certdb = ', certdb);
      try {
        certOverride = Cc['@mozilla.org/security/certoverride;1']
            .getService(nsICertOverrideService);
      }
      catch(e) {
        log('FAILED TO GET CERT OVERRIDE SERVICE!\n'+e+'\n');
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
    try {
      if (!Services.prefs.getBoolPref(BASE + 'silent'))
        return;
    }
    catch(e) {
      return; // default=false
    }
    const NEWADDONS = 'extensions.newAddons';
    try {
      let list = Services.prefs.getCharPref(NEWADDONS).split(',');
      let index = list.indexOf(ID);
      if (index > -1) {
        list.splice(index, 1);
        if (list.length)
          Services.prefs.setCharPref(NEWADDONS, list.join(','));
        else
          Services.prefs.clearUserPref(NEWADDONS);
      }
    }
    catch(e) {
    }
  };

  const loadPrefs = () => {
    const prefix = BASE + 'importAs.';
    Services.prefs.getChildList(prefix, {}).forEach(aPref => {
      try {
        importAs[aPref.replace(prefix, '')] = Services.prefs.getIntPref(aPref);
      }
      catch(e) {
      }
    });

    try {
      allowRegisterAgain = Services.prefs.getBoolPref(BASE + 'allowRegisterAgain');
    }
    catch(e) {
    }
  };
 
  const registerCerts = () => {
    let defaults = DirectoryService.get('CurProcD', Ci.nsIFile);
    defaults.append('defaults');
    log('global1 '+defaults.path+' : '+defaults.exists());
    if (defaults.exists())
      registerCertsInDirectory(defaults);

    defaults = DirectoryService.get('GreD', Ci.nsIFile);
    defaults.append('defaults');
    log('global2 '+defaults.path+' : '+defaults.exists());
    if (defaults.exists())
      registerCertsInDirectory(defaults);

    let profile = DirectoryService.get('ProfD', Ci.nsIFile);
    log('private '+profile.path+' : '+profile.exists());
    if (profile.exists())
      registerCertsInDirectory(profile);
  };

  const autoConfirmUrls = [];
  const autoConfirmConfigs = [];
  const setAutoConfirmConfigs = (aCertName, aTrust) => {
    if (!aTrust)
      aTrust = certTrusts[nsIX509Cert.CA_CERT];
    let base = BASE + 'auto-import.' + aCertName.replace(/\./g, '_');
    let actions = ['accept'];
    if (aTrust & nsIX509CertDB.TRUSTED_OBJSIGN)
      actions.unshift('check;id:trustObjSign');
    if (aTrust & nsIX509CertDB.TRUSTED_EMAIL)
      actions.unshift('check;id:trustEmail');
    if (aTrust & nsIX509CertDB.TRUSTED_SSL)
      actions.unshift('check;id:trustSSL');

    // 日本語環境用の設定
    autoConfirmUrls.push('chrome://pippki/content/downloadcert.xul');
    autoConfirmConfigs.push({
      text:    '“' + aCertName + '” が行う認証のうち、信頼するものを選択してください。',
      actions: JSON.stringify(actions)
    });
    // 英語環境用の設定
    autoConfirmUrls.push('chrome://pippki/content/downloadcert.xul');
    autoConfirmConfigs.push({
      text:    'Do you want to trust “' + aCertName + '” for the following purposes?',
      actions: JSON.stringify(actions)
    });
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

      log('CHECK '+file.path);

      let certName = file.leafName.replace(/^\s+|\s+$/g, '');
      let certDate = '';
      let lastCertDate = '';
      try {
        certDate = String(file.lastModifiedTime);
        try {
          lastCertDate = Services.prefs.getCharPref(BASE + 'certs.'+certName+'.lastDate');
        }
        catch(e) {
        }
      }
      catch(e) {
        log(e);
      }

      let overrideFile = file.parent;
      overrideFile.append(certName+'.override');
      log('CHECK '+overrideFile.path+'\n exists: '+overrideFile.exists());
      let overrideDate = '';
      let lastOverrideDate = '';
      try {
        if (certOverride && overrideFile.exists())
          overrideDate = String(overrideFile.lastModifiedTime);
        try {
          lastOverrideDate = Services.prefs.getCharPref(BASE + 'certs.'+certName+'.lastOverrideDate');
        }
        catch(e) {
        }
      }
      catch(e) {
        log(e);
      }

      if ((!allowRegisterAgain && lastCertDate == certDate) &&
        lastOverrideDate == overrideDate)
        continue;

      let contents = readFrom(file);
      if (!contents) continue;
      Services.prefs.setCharPref(BASE + 'certs.'+certName+'.lastDate', certDate);

      let count = 0;

      let overrideRule = [];
      try {
        if (certOverride) {
          if (overrideFile.exists()) {
            overrideRule = readFrom(overrideFile).replace(/^\s+|\s+$/g, '');
            Services.prefs.setCharPref(BASE + 'certs.'+certName+'.lastOverrideDate', overrideDate);
          }
          else {
            try {
              overrideRule = Services.prefs.getCharPref(BASE + 'override.'+certName);
            } catch(e) {
              overrideRule = null;
            }
          }
          overrideRule = overrideRule ? overrideRule.split(/\s+/) : [] ;
        }
      }
      catch(e) {
        log(e);
      }

      let certs = [];
      let decodedCerts = [];
      if (/\.der$/i.test(file.leafName)) {
        try {
          decodedCerts.push(certdb.constructX509(contents, contents.length));
        }
        catch(e) {
          log(e+'\n');
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
            log(e+'\n');
          }
        });
      }
      decodedCerts.forEach(aCert => {
        try {
          if (nsIX509Cert2)
            aCert = aCert.QueryInterface(nsIX509Cert2);

          let serialized = serializeCert(aCert);
          let overrideCount = certOverride ? certOverride.isCertUsedForOverrides(aCert, false, true) : 0 ;
          log('====================CERT DETECTED=======================\n');
          log('TYPE: '+aCert.certType);
          log('FINGERPRINT: '+aCert.sha1Fingerprint);
          log(serialized.split('\n')[0]);

          certFiles[serialized] = certName;
          certs.push(aCert);

          overrideRules[serialized] = overrideRule;
          log('exceptions: registered='+overrideCount+', defined='+overrideRule.length);
          if (certOverride && overrideRule.length) {
            log(' => to be added to exception!');
            toBeAddedToException[serialized] = true;
            toBeAddedToExceptionCount++;
          }
          log('========================================================\n');

          try {
            if (certTypes.some(aType => {
                  return certdb.isCertTrusted(aCert, aType, certTrusts[aType]);
                })) {
              log('already installed\n');
              return;
            }
          }
          catch(e) {
            log(e+'\n');
          }
          log('to be installed\n');
          toBeTrusted[serialized] = true;
          toBeTrustedCount++;

          count++;

          importAs[certName] = importAs[certName] || aCert.certType || 0;
        }
        catch(e) {
          log(e+'\n');
        }
      });

      if (!count) {
        log('SKIP '+file.path+' (no count)');
        continue;
      }

      log('certName '+certName);
      let type = certName in importAs ?
          importAs[certName] :
          importAs['*'] ;
      log('type '+type);
      try {
        if (type) {
          if (type & nsIX509Cert.CA_CERT) {
            log('IMPORT '+file.path+' as a CA cert');
            setAutoConfirmConfigs(certName, certTrusts[nsIX509Cert.CA_CERT]);
            importFromFile(certdb, file, nsIX509Cert.CA_CERT);
            log('done.');
          }
          else {
            certTypes.forEach(aType => {
              if (type & aType) {
                setAutoConfirmConfigs(certName, certTrusts[aType]);
                importFromFile(certdb, file, aType);
                log('done.');
              }
            });
          }
        }
        else {
          log('SKIP '+file.path);
        }
      }
      catch(e) {
        log('Error, TYPE:'+type+'\n'+e+'\n');
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

        log('========= '+aNickname+' ===========');
        if (nsIX509Cert2)
          cert = cert.QueryInterface(nsIX509Cert2);

        log('TYPE: '+cert.certType);

        if (serialized in toBeTrusted) {
          certTypes.forEach(aType => {
            try {
              if (!('certType' in cert) || cert.certType & aType) {
                log('register as type '+aType+': '+aNickname);
                certdb.setCertTrust(cert, aType, certTrusts[aType]);
              }
            }
            catch(e) {
              log('TYPE:'+aType+'\n'+e+'\n');
            }
          })
        }

        if (serialized in toBeAddedToException) {
          let overrideRule = overrideRules[serialized];
          if (overrideRule) {
            overrideRule.forEach(aPart => {
              log('apply override rule '+aPart+' for '+aNickname);
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
                log('  clear validity for '+host+':'+port);
                certOverride.clearValidityOverride(host, port);
              }

              log('  new flags for '+host+':'+port+' = '+newFlags);
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
    let certs = aCertDB.getCerts();
    certs = certs.getEnumerator();
    let names = [];
    while (certs.hasMoreElements()) {
      let cert = certs.getNext().QueryInterface(Ci.nsIX509Cert);
      if (cert.certType & aType)
        names.push(cert.nickname || cert.commonName);
    }
    return names;
  };

  const getCertByName = (aCertDB, aName) => {
    return aCertDB.findCertByNickname(aName);
  };

  const importFromFile = (aCertDB, aFile, aType) => {
    aCertDB.importCertsFromFile(aFile, aType);
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
      log(e+'\n');
      return fileContents;
    }

    return fileContents;
  };

  ObserverService.addObserver(observer, 'final-ui-startup', false);


  // codes for "Auto Confirm"
  const handleAutoConfirmWindow = (aWindow) => {
    const doc = aWindow.document;
    const url = aWindow.location.href;
    log('url: ' + url);
    let fromIndex = 0;
    while (true) {
      log('fromIndex: ' + fromIndex);
      let index = autoConfirmUrls.indexOf(url, fromIndex);
      log('index: ' + index);
      if (index === -1)
        return;
      let config = autoConfirmConfigs[index];
      log('config: ' + config);
      if (matchedWindow(aWindow, config)) {
        aWindow.setTimeout(() => {
          let action = config.action;
          if (action)
            processAction(aWindow, action);
          let actions = config.actions;
          if (actions)
            processActions(aWindow, actions);
        }, 500);
        return;
      }
      fromIndex = index + 1;
    }
  };

  const processActions = (aWindow, aActions, aRootElement) => {
    const doc = aWindow.document;
    log('actions: ' + aActions);
    for (let action of JSON.parse(aActions)) {
      log('action: ' + action);
      processAction(aWindow, action, aRootElement);
    }
  };

  const describeElement = (aElement) => {
    const description = [aElement.localName];
    if (aElement.id)
      description.push('#' + aElement.id);
    if (aElement.className)
      description.push('.' + aElement.className.replace(/\s+/g, '.'));
    return description.join('');
  };

  const processAction = (aWindow, aAction, aRootElement) => {
    const doc = aWindow.document;
    const root = doc.documentElement;
    log('action: ' + aAction);
    const actions = aAction.match(/^([^;]+);?(.*)/);
    if (actions === null)
      return;
    const action = actions[1];
    const value = actions[2];
    switch (action) {
      case 'accept':
        log('accept');
        if (typeof root.acceptDialog == 'function')
          root.acceptDialog();
        else
          Cu.reportError(new Error('We don\'t know how to accept '+describeElement(root)));
        return;
      case 'cancel':
        log('cancel');
        if (typeof root.cancelDialog == 'function')
          root.cancelDialog();
        else
          Cu.reportError(new Error('We don\'t know how to cancel '+describeElement(root)));
        return;
      case 'click':
        log('click');
        {
          let element = findVisibleElementByLabel(root, value);
          log(element);
          if (typeof element.click === 'function') {
            log('element.click(): ready');
            element.click();
            log('element.click(): done');
          }
          else {
            log('element is not clickable');
            Cu.reportError(new Error('found element '+describeElement(element)+' is not clickable.'));
          }
        }
        return;
      case 'push':
        let buttons;
        if (root._buttons) {
          buttons = root._buttons;
        }
        else {
          Cu.reportError(new Error('We cannot detect pushable buttons in '+describeElement(root)));
          return;
        }
        for (let type in buttons) {
          const button = buttons[type];
          log('label: ' + button.label);
          if (button.label.match(value)) {
            button.click();
            log('push');
            return;
          }
        }
        log('push: no match');
        return;
      case 'input':
        Cu.reportError(new Error('We don\'t know how to input text at '+describeElement(root)));
        log('input');
        return;
      case 'check':
        log('check');
        if (value) {
          const element = findVisibleElementByLabel(root, value);
          log('  element: ' + element);
          log('  element.checked: ready');
          element.checked = true;
          log('  element.checked: done');
        }
        else {
          Cu.reportError(new Error('We don\'t know how to check checkbox in '+describeElement(root)));
        }
        return;
      case 'uncheck':
        log('uncheck');
        if (value) {
          const element = findVisibleElementByLabel(root, value);
          log(element);
          log('  element.checked: ready');
          element.checked = false;
          log('  element.checked: done');
        }
        else {
          Cu.reportError(new Error('We don\'t know how to uncheck checkbox in '+describeElement(root)));
        }
        return;
      default:
        log('no action');
        return;
    }
  };

  const matchedWindow = (aWindow, aConfig) => {
    log('matchedWindow');
    let textMatcher = aConfig.text;
    log('  textMatcher: ' + textMatcher);
    if (textMatcher && !findVisibleElementByLabel(aWindow.document.documentElement, textMatcher))
      return false;
    log('  match');
    return  true;
  };

  const findVisibleElementByLabel = (aRootElement, text) => {
    log('findVisibleElementByLabel');
    if (text.indexOf('"') !== -1) {
      text = 'concat("' + text.replace(/"/g, '", \'"\', "') + '")';
    } else {
      text = '"' + text + '"';
    }
    let expression = '/descendant::*[contains(@label, ' + text + ')] | ' +
                     '/descendant::*[local-name()="label" or local-name()="description"][contains(@value, ' + text + ')] | ' +
                     '/descendant::*[contains(text(), ' + text + ')]';
    log('  expression: ' + expression);
    try {
      const doc = aRootElement.ownerDocument;
      const global = doc.defaultView;
      const elements = doc.evaluate(
        expression,
        aRootElement,
        null,
        global.XPathResult.ORDERED_NODE_SNAPSHOT_TYPE,
        null
      );
    }
    catch(e) {
      log('  error: ' + e);
    }
    log('  elements.length: ' + elements.snapshotLength);
    for (let i = 0, maxi = elements.snapshotLength; i < maxi; i++) {
      const element = elements.snapshotItem(i);
      if (element.clientHeight > 0 &&
          element.clientWidth > 0) {
        return element;
      }
    }
    log('  no visible element');
    return null;
  };

  Cc['@mozilla.org/embedcomp/window-watcher;1']
    .getService(Ci.nsIWindowWatcher)
    .registerNotification(observer);
}; 
