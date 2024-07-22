# Changelog

## 0.6.0 - 2024-07-22

* Fix up wheel package build to not include uneeded `python_krb5.h` file in the final `site-packages` install dir
* Added CCache APIs:
  * [krb5_cc_get_config](https://web.mit.edu/kerberos/krb5-devel/doc/appdev/refs/api/krb5_cc_get_config.html)
  * [krb5_cc_set_config](https://web.mit.edu/kerberos/krb5-devel/doc/appdev/refs/api/krb5_cc_set_config.html)
* Added Context APIs:
  * [krb5_set_real_time](https://web.mit.edu/kerberos/krb5-devel/doc/appdev/refs/api/krb5_set_real_time.html)
  * [krb5_timeofday](https://web.mit.edu/Kerberos/krb5-devel/doc/appdev/refs/api/krb5_timeofday.html)
  * [krb5_us_timeofday](https://web.mit.edu/kerberos/krb5-devel/doc/appdev/refs/api/krb5_us_timeofday.html)
  * MIT only
  * [krb5_get_time_offsets](https://web.mit.edu/kerberos/krb5-devel/doc/appdev/refs/api/krb5_get_time_offsets.html)
* Added Credential APIs:
  * [krb5_get_renewed_creds](https://web.mit.edu/kerberos/krb5-devel/doc/appdev/refs/api/krb5_get_renewed_creds.html)
  * MIT only
  * [krb5_get_etype_info](https://web.mit.edu/kerberos/krb5-devel/doc/appdev/refs/api/krb5_get_etype_info.html)
  * [krb5_get_validated_creds](https://web.mit.edu/kerberos/krb5-devel/doc/appdev/refs/api/krb5_get_validated_creds.html)
  * MIT 1.20+ only
  * [krb5_marshal_credentials](https://web.mit.edu/kerberos/krb5-devel/doc/appdev/refs/api/krb5_marshal_credentials.html)
  * [krb5_unmarshal_credentials](https://web.mit.edu/kerberos/krb5-devel/doc/appdev/refs/api/krb5_unmarshal_credentials.html)
* Added KeyBlock APIs:
  * MIT only
  * [krb5_c_string_to_key](https://web.mit.edu/kerberos/krb5-devel/doc/appdev/refs/api/krb5_c_string_to_key.html)
* Added Principal APIs:
  * [krb5_build_principal]https://web.mit.edu/kerberos/krb5-devel/doc/appdev/refs/api/krb5_build_principal.html)
* Added the following properties to the `Creds` object:
  * `ticket_flags_raw` - Flags in the ticket as returned by the C API
  * `ticket_flags` - Flags in the ticket converted to a known enum value
* Added the following properties to the `Principal` object:
  * `realm` - The realm of the principal
  * `components` - The list of name components.
  * `type` - The name type of the principal.

## 0.5.1 - 2023-08-29

* Added support for Cython 3.x.y when building the extension modules
* Added Python 3.12 wheel for macOS

## 0.5.0 - 2023-02-20

* Added exception that is raised when `krb5.init_context()` failed
* Moved back to `setup.cfg` based setuptools project for compatibility with `pip` present on system distributions
* Added the following properties to the `Creds` object:
  * `client` - A copy of the credential's client principal
  * `server` - A copy of the credential's server principal
  * `keyblock` - A copy of the credential's session encryption key info
  * `times` - A copy of the credential's lifetime info including the auth time, star time, end time, and renewal time
  * `ticket` -  A copy of the credential's ticket data
  * `second_ticket` - A copy of the credential's second ticket data (`DUPLICATE-SKEY` or `ENC-TKT-IN-SKEY`)
* Added CCache APIs:
  * [krb5_cc_remove_cred](https://web.mit.edu/kerberos/krb5-devel/doc/appdev/refs/api/krb5_cc_remove_cred.html)
  * [krb5_cc_retrieve_cred](https://web.mit.edu/kerberos/krb5-devel/doc/appdev/refs/api/krb5_cc_retrieve_cred.html)
* Added Keyblock APIs:
  * [krb5_copy_keyblock](https://web.mit.edu/kerberos/krb5-devel/doc/appdev/refs/api/krb5_copy_keyblock.html)

## 0.4.1 - 2022-10-25

* Added Python 3.11 wheel

## 0.4.0 - 2022-08-09

* Require Python 3.7 or newer (dropped 3.6)
* Created PEP 517 compliant package
* Moved all setuptools configuration, except extension information, to `pyproject.toml`
* Will no longer include the cythonised `.c` files in the sdist making Cython a build requirement
  * With PEP 517 this requirement will be automatically satisfied making this a non-breaking change for people using PEP 517 features

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
