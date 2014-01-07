// You can override the type of certs. Possible values:
//
//  0 = unknown
//  1 = CA
//  2 = user
//  4 = e-mail
//  8 = site

// Set default type of any cert to "unknown".
pref("extensions.certimporter.importAs.*", 0);

// Define the type of the cert as a "CA cert".
// It will be applied prior to the type specified by the cert itself.
pref("extensions.certimporter.importAs.cacert.pem", 1);

// Define the type of the cert as a "site cert" (for SSL).
// It will be applied prior to the type specified by the cert itself.
pref("extensions.certimporter.importAs.newcert.pem", 8);
