# Changelog

## 0.3.0 - 2022-02-16

* Added CCache APIs:
  * [krb5_cc_set_default_name](https://web.mit.edu/kerberos/krb5-devel/doc/appdev/refs/api/krb5_cc_set_default_name.html)
  * [krb5_cc_start_seq_get](https://web.mit.edu/kerberos/krb5-devel/doc/appdev/refs/api/krb5_cc_start_seq_get.html#c.krb5_cc_start_seq_get)
  * [krb5_cc_next_cred](https://web.mit.edu/kerberos/krb5-devel/doc/appdev/refs/api/krb5_cc_next_cred.html#c.krb5_cc_next_cred)
  * [krb5_cc_end_seq_get](https://web.mit.edu/kerberos/krb5-devel/doc/appdev/refs/api/krb5_cc_end_seq_get.html#c.krb5_cc_end_seq_get)
* CCaches can be iterated to get each credential entry in the cache.
* Added Keytab management APIs:
  * [krb5_kt_add_entry](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_kt_add_entry.html)
  * [krb5_kt_get_entry](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_kt_get_entry.html)
  * [krb5_kt_have_content](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_kt_have_content.html)
  * [krb5_kt_read_service_key](https://web.mit.edu/kerberos/krb5-devel/doc/appdev/refs/api/krb5_kt_read_service_key.html)
  * [krb5_kt_remove_entry](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_kt_remove_entry.html)
  * [krb5_kt_start_seq_get](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_kt_start_seq_get.html)
  * [krb5_kt_next_entry](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_kt_next_entry.html)
  * [krb5_kt_end_seq_get](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_kt_end_seq_get.html)
* Keytabs can be iterated to get each entry in the keytab.
* Added KeyBlock management APIs:
  * [krb5_init_keyblock](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_init_keyblock.html)
  * Due to differences between MIT and Heimdal this function reflects `krb5_keyblock_init` in Heimdal where the data is copied to the keyblock on creation
* Added credential options APIs:
  * [krb5_get_init_creds_opt_set_anonymous](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_get_init_creds_opt_set_anonymous.html)
  * [krb5_get_init_creds_opt_set_etype_list](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_get_init_creds_opt_set_etype_list.html)
  * [krb5_get_init_creds_opt_set_in_ccache](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_get_init_creds_opt_set_in_ccache.html) - MIT 1.11 or newer
  * [krb5_get_init_creds_opt_set_pac_request](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_get_init_creds_opt_set_pac_request.html) - Heimdal or MIT 1.15
  * [krb5_get_init_creds_opt_set_proxiable](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_get_init_creds_opt_set_proxiable.html)
  * [krb5_get_init_creds_opt_set_renew_life](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_get_init_creds_opt_set_renew_life.html)
  * [krb5_get_init_creds_opt_set_tkt_life](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_get_init_creds_opt_set_tkt_life.html)
  * [krb5_get_init_creds_opt_set_fast_ccache](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_get_init_creds_opt_set_fast_ccache.html) - MIT only
  * [krb5_get_init_creds_opt_set_fast_ccache_name](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_get_init_creds_opt_set_fast_ccache_name.html) - MIT only
  * [krb5_get_init_creds_opt_set_fast_flags](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_get_init_creds_opt_set_fast_flags.html) - MIT only
  * [krb5_get_init_creds_opt_set_pa](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_get_init_creds_opt_set_pa.html) - MIT only
  * [krb5_get_init_creds_opt_set_salt](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_get_init_creds_opt_set_salt.html)
* Added miscellaneous APIs:
  * [krb5_copy_principal](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_copy_principal.html)
  * [krb5_string_to_enctype](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_string_to_enctype.html)
  * [krb5_enctype_to_string](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_enctype_to_string.html)
  * [krb5_enctype_to_name](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_enctype_to_name.html) - MIT only


## 0.2.0 - 2021-10-18

* Added [krb5_cc_switch](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_cc_switch.html)
  * Used to switch the primary credential cache in a collection credential cache
* Added [krb5_cc_support_switch](https://github.com/heimdal/heimdal/blob/9dcab76724b417140b4e475701118a01d2892e7c/lib/krb5/cache.c)
  * Used to detect if a credential cache type, like `FILE`, `DIR`, supports switching with `krb5_cc_switch`
* Added [krb5_cc_cache_match](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_cc_cache_match.html)
  * Retrieve the credential cache inside a collection for the principal specified


## 0.1.2 - 2021-10-06

* Added Python 3.10 wheels


## 0.1.1 - 2021-09-14

* 0.1.0 was taken during registration, use this as the initial release instead


## 0.1.0 - 2021-09-14

Initial release
