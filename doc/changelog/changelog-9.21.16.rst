.. Copyright (C) Internet Systems Consortium, Inc. ("ISC")
..
.. SPDX-License-Identifier: MPL-2.0
..
.. This Source Code Form is subject to the terms of the Mozilla Public
.. License, v. 2.0.  If a copy of the MPL was not distributed with this
.. file, you can obtain one at https://mozilla.org/MPL/2.0/.
..
.. See the COPYRIGHT file distributed with this work for additional
.. information regarding copyright ownership.

BIND 9.21.16
------------

New Features
~~~~~~~~~~~~

- Add +[no]showtruncated and +[no]showallmessages to dig. ``e78e6150e5``

  The dig option +showtruncated adds the ability to display the
  truncated message before retrying the query over TCP.

  The dig option +showallmessages add a short cut which is the
  equivalent of "dig +qr +showbadcookie +showbadversion +showtruncated".
  :gl:`#5657` :gl:`!11275`

- Add spatch to detect implicit bool/int/result cast. ``2affdbce19``

  Detection of implicit cast from a boolean into an int, or an
  isc_result_t into a boolean (either in an assignement or return
  position).

  If such pattern is found, a warning comment is added into the code
  (and the CI will fails) so the error can be spotted and manually
  fixed. :gl:`!11095`

Removed Features
~~~~~~~~~~~~~~~~

- Remove internal memory filling in favor of jemalloc opt.junk.
  ``def4be7cb6``

  Instead of having our own implementation of memory junk filling, rely
  on the jemalloc opt.junk feature (set with MALLOC_CONF="junk:true").
  :gl:`!11270`

Feature Changes
~~~~~~~~~~~~~~~

- Improve output of 'rndc dnssec -status' ``814f7a72cd``

  Add a new parameter ``-v`` to the ``rndc dnssec -status`` command for
  more verbose output. Previously, key states were printed, and keys
  that can be purged were listed. This made the output hard to read.
  This information is now only shown in the verbose output.

  Add more meaningful messages to the status output, making it clearer
  what the state of a rollover is.

  This makes the output more condense, improving its readability.
  :gl:`#3938` :gl:`!11099`

- Use atomics for CMM_{LOAD,STORE}_SHARED with ThreadSanitizer.
  ``6fd209b6f0``

  Upstream has removed the atomics implementation of CMM_LOAD_SHARED and
  CMM_STORE_SHARED as these can be used also with non-stdatomics types.
  As we only use the CMM api with stdatomics types, we can restore the
  previous behaviour to prevent ThreadSanitizer warnings. :gl:`#5660`
  :gl:`!11288`

- Change the QNAME minimization algorithm to follow the standard.
  ``15494053b1``

  In !9155, the QNAME minimization was changed to not leak the query
  type to the parent name server.  This violates RFC 9156 Section 3,
  step (3) and it is not necessary.  It also breaks some (weird)
  authoritative DNS setups, especially when CNAMEs are involved.  Also
  there is really no privacy leak with query type. :gl:`#5661`
  :gl:`!11293`

- Add RRSIG if required as soon as they are found. ``2955bb90c8``

  When EDNS DO flag (`dig +dnssec`) flag is set, an rdataset is
  allocated to hold the RRSIG of an RR, if present in DB. However, this
  allocation is not done if the zone DB is not considered as secure
  (`dns_db_issecure() == false`). Changes this behaviour by allocating
  the rdataset anyway, so the RRSIG can be associated in the answer
  section of the response as soon it is found from the DB.

  The fact we attach the rrsig potentially more often (though it
  probably occurs in edge cases) doesn't seems to affect performance in
  any ways: :gl:`!11317`

- Add dns_message functions to set EDNS options. ``b4d638473e``

  The new `dns_message_ednsinit()` and `dns_message_ednsaddopt()`
  functions allow EDNS options to be added to a message one at a time;
  it is no longer necessary to construct a full array of EDNS options
  and set them all at once.

  This allows us to simplify EDNS option handling code, and in the
  future it wlil allow plugins to add EDNS options to existing messages.
  :gl:`!11261`

- Enforce bounds of prefetch configuration option. ``103799ac23``

  The prefetch configuration option now enforces boundaries. The
  configuration (including when using `named-checkconf`) now fails if
  the trigger (first value) is above 10, and if the eligibility (second
  optional value) isn't at least six seconds greater than the trigger
  value. :gl:`!11243`

- Enforces the fact that catalog-zone can not be used in non IN views.
  ``346007d52d``

  Catalog-zones can't be used in a view which is not from the IN class.
  This is now enforced as the server won't load (instead of loading
  without the catalog-zone) if such configuration is detected. This
  configuration error is now also caught by `named-checkconf`.
  :gl:`!11245`

- No effective config as text if allow-new-zones is yes. ``416826d4ea``

  Do not save the text version of the effective configuration when
  `allow-new-zones` is enabled, as in that case the object tree can be
  printed on demand, reducing unnecessary memory consumption.
  :gl:`!11242`

- Provide more information when the memory allocation fails.
  ``94ffc96897``

  Provide more information about the failure when the memory allocation
  fails. :gl:`!11272`

- Reduce the number of outgoing queries. ``37d851df37``

  Reduces the number of outgoing queries when resolving the nameservers
  for delegation points.  This helps the DNS resolver with cold cache
  resolve client queries with complex delegation chains and
  redirections. :gl:`!11148`

- Refactor zone fetch code. ``32322ffdd8``

  There is code duplication between `keyfetch` and `nsfetch`, refactor
  to allow common code paths to differentiate between them. This is in
  preparation for support of generalized DNS notifications, that will
  require fetching DSYNC records. :gl:`!11176`

- Remove exclusive mode when scheduling zone load. ``2958b3733c``

  Remove exclusive mode when scheduling the zone load, as it is no
  longer necessary; data that can be read or written by multiple threads
  are locked or atomic.

  The detection of the post zone DB loading logic has been refactored to
  take into account the fact that zone databases may be loaded before
  the function scheduling the loads. :gl:`!11231`

- Use malloc_usable_size()/malloc_size() for memory accounting.
  ``d8410f93d2``

  Restore usage of malloc_usable_size()/malloc_size(), but this time
  only for memory accounting and statistics purposes.  This should
  reduce the memory footprint in case of compilation without jemalloc as
  we don't have to keep track of the allocated memory size ourselves.
  :gl:`!11271`

Bug Fixes
~~~~~~~~~

- Fix the spurious timeouts while resolving names. ``908b7c1f34``

  Sometimes the loops in the resolving (e.g. to resolve or validate
  ns1.example.com we need to resolve ns1.example.com) were not properly
  detected leading to spurious 10 seconds delay.  This has been fixed
  and such loops are properly detected. :gl:`#3033`, #5578 :gl:`!11138`

- Fix bug where zone switches from NSEC3 to NSEC after retransfer.
  ``ddd1040761``

  When a zone is re-transferred, but the zone journal on an
  inline-signing secondary is out of sync, the zone could fall back to
  using NSEC records instead of NSEC3. This has been fixed. :gl:`#5527`
  :gl:`!11226`

- Add support for more linkers with LTO. ``1ede6683cd``

  Link-time optimization requires close coordination between the
  compiler and the linker, so not all combinations of compiler and
  linker support it.

  Previously, when compiling with Clang, we checked only for lld. With
  this commit, we expand the list of supported linkers we check for.
  :gl:`#5536` :gl:`!11022`

- Attach socket before async streamdns_resume_processing. ``fec55d786a``

  Call to `streamdns_resume_processing` is asynchronous but the socket
  passed as argument is not attached when scheduling the call.

  While there is no reproducible way (so far) to make the socket
  reference number down to 0 before `streamdns_resume_processing` is
  called, attach the socket before scheduling the call. This guard
  against an hypothetic case where, for some reasons, the socket
  refcount would reach 0, and be freed from memory when
  `streamdns_resume_processing` is called. :gl:`#5620` :gl:`!11247`

- Fix caching RRSIG covering cache NODATA record. ``a81aad0cdc``

  When a RRSIG for type that we already have cached NODATA record was
  cached due to mismatch of the records on the upstream nameservers, an
  assertion failure could trigger.  This has been fixed. :gl:`#5633`
  :gl:`!11228`

- Fix building on OpenBSD 7.8 with Clang 19.1.7. ``d30fdf063c``

  Add the OpenBSD and Clang combination to the existing kludge to
  recognize size_t and uintXX_t types as same when using a generic.
  :gl:`#5635` :gl:`!11235`

- AMTRELAY type 0 presentation format handling was wrong. ``d091771b42``

  RFC 8777 specifies a placeholder value of "." for the gateway field
  when the gateway type is 0 (no gateway).  This was not being checked
  for nor emitted when displaying the record. This has been corrected.

  Instances of this record will need the placeholder period added to
  them when upgrading. :gl:`#5639` :gl:`!11240`

- Fix parsing bug in remote-servers with key or tls. ``51af07cdee``

  The :any:`remote-servers` clause enable the following pattern using a
  named ``server-list``:

  remote-servers a { 1.2.3.4; ... };         remote-servers b { a key
  foo; };

  However, such configuration was wrongly rejected, with an "unexpected
  token 'foo'" error. Such configuration is now accepted. :gl:`#5646`
  :gl:`!11252`

- Fix allow-recursion/allow-query-cache inheritance. ``4a4368a5ec``

  The merging of the user options and defaults into the effective
  configuration broke the mutual inheritance of the `allow-recursion`,
  `allow-query`, and `allow-query-cache` ACLs, and of the
  `allow-recursion-on` and `allow-query-cache-on` ACLs. This has been
  fixed. :gl:`#5647` :gl:`!11254`

- Fix TLS contexts cache object usage bug in the resolver.
  ``d441e14cbf``

  :iscman:`named` could terminate unexpectedly when reconfiguring or
  reloading, and if client-side TLS transport was in use (for example,
  when forwarding queries to a DoT server). This has been fixed.
  :gl:`#5653` :gl:`!11295`

- Fix uninitialized pointer check on getipandkeylist. ``dd2d690d98``

  Function `named_config_getipandkeylist` could, in case of error in the
  early code attempting to get the `port` or `tls-port`, make a pointer
  check on a non-initialized value. This is now fixed. :gl:`!11303`

- Pass isc_buffer_t pointers when applicable. ``53ea41b459``

  In commit aea251f3bce7, `isc_buffer_reserve()` was changed to take a
  simple `isc_buffer_t *` instead of `isc_buffer_t **`. A number of
  functions calling it have now been similarly modified. :gl:`!11282`

- Remove holes in `dns_zoneflg_t` enum. ``1a9f7539bd``

  The `dns_zoneflg_t` enum defined multiple possible flags for a zone,
  but contains numerous holes (likely from flag removed in the past).
  This fixes the holes, and use a bit-shift and decimal notation to make
  holes easier to spot. :gl:`!11189`

- Save configuration as text. ``09bcacbd36``

  A `cfg_obj_t` object tree structure takes up considerably more space
  than the equivalent canonical text. If `allow-new-zones` is disabled
  and catalog zones are not in use, then we don't need the object tree.
  By storing the configuration in text format, we can use less memory,
  and `rndc showconf` and `rndc showzone` still work. :gl:`!11236`

- Standardize CHECK and RETERR macros. ``a45d253882``

  Previously, there were over 40 separate definitions of `CHECK` macros,
  of which most used `goto cleanup`, and the rest `goto failure` or
  `goto out`. There were another 10 definitions of `RETERR`, of which
  most were identical to `CHECK`, but some simply returned a result code
  instead of jumping to a cleanup label.

  This has now been standardized throughout the code base: `RETERR` is
  for returning an error code in the case of an error, and `CHECK` is
  for jumping to a cleanup tag, which is now always called `cleanup`.
  Both macros are defined in `isc/util.h`. :gl:`!10472`

- Adding NSEC3 opt-out records could leave invalid records in
  chain. ``6d03b4f9c6``

  When creating an NSEC3 opt-out chain, a node in the chain could be
  removed too soon, causing the previous NSEC3 being unable to be found,
  resulting in invalid NSEC3 records to be left in the zone. This has
  been fixed. :gl:`#5671`

