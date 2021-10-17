# Changelog

## 0.2.0 - TBD

* Added [krb5_cc_switch](https://web.mit.edu/kerberos/krb5-1.11/doc/appdev/refs/api/krb5_cc_switch.html)
  * Used to switch the primary credential cache in a collection credential cache
* Added [krb5_cc_support_switch](https://github.com/heimdal/heimdal/blob/9dcab76724b417140b4e475701118a01d2892e7c/lib/krb5/cache.c)
  * Used to detect if a credential cache type, like `FILE`, `DIR`, supports switching with `krb5_cc_switch`
* Added [krb5_cc_cache_match](https://web.mit.edu/kerberos/krb5-1.11/doc/appdev/refs/api/krb5_cc_cache_match.html)
  * Retrieve the credential cache inside a collection for the principal specified


## 0.1.2 - 2021-10-06

* Added Python 3.10 wheels


## 0.1.1 - 2021-09-14

* 0.1.0 was taken during registration, use this as the initial release instead


## 0.1.0 - 2021-09-14

Initial release
