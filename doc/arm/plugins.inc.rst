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

.. _module-info:

Plugins
~~~~~~~

Plugins are a mechanism to extend the functionality of :iscman:`named` using
dynamically loadable libraries. By using plugins, core server
functionality can be kept simple for the majority of users; more complex
code implementing optional features need only be installed by users that
need those features.

The plugin interface is a work in progress, and is expected to evolve as
more plugins are added. Currently, only "query plugins" are supported;
these modify the name server query logic. Other plugin types may be
added in the future.

The plugins currently included in BIND are :iscman:`filter-aaaa.so
<filter-aaaa>`, :iscman:`filter-a.so <filter-a>` and :iscman:`synthrecord.so <synthrecord>`.

The plugin :iscman:`filter-aaaa.so <filter-aaaa>` replaces the ``filter-aaaa``
feature that previously existed natively as part of :iscman:`named`. The code
for this feature has been removed from :iscman:`named` and can no longer be
configured using standard :iscman:`named.conf` syntax, but linking in the
:iscman:`filter-aaaa.so <filter-aaaa>` plugin provides identical functionality.

Configuring Plugins
~~~~~~~~~~~~~~~~~~~
.. namedconf:statement:: plugin
   :tags: server
   :short: Configures plugins in :iscman:`named.conf`.

A plugin is configured with the :any:`plugin` statement in :iscman:`named.conf`:

::

   plugin query "library.so" {
       parameters
   };


In this example, ``query`` indicates that this is a query plugin,
and ``library.so`` is the name of the plugin library.  Note that the
library file extension (in this case, ``.so``) is optional, and can
be omitted.

Multiple :any:`plugin` statements can be specified, to load different
plugins or multiple instances of the same plugin.

``parameters`` are passed as an opaque string to the plugin's initialization
routine. Configuration syntax differs depending on the module.

Plugins can be configured globally, or at the :any:`view` or :any:`zone` level.

If a plugin is configured inside a zone (either directly or via inclusion
from a :any:`template`), then an instance of the plugin will be loaded for
that specific zone, and its hooks will be called only when that zone is
being used to answer a query.

::

    view external {
        template primary {
            type primary;
            file "$name.db";
            plugin query "plugin1.so" { parameters };
        };

        zone "example.com." {
            template primary;
            plugin query "plugin2.so" { parameters };
        };

        plugin query "plugin3.so" { paramters };
    };

In the above example, three plugin instances will be loaded: ``plugin1.so``
(which was configured in the template) and ``plugin2.so`` (configured in
the zone statement) will both be applied whenever a query looks up a name
in ``example.com``, and ``plugin3.so`` will apply to all queries answered
from the view ``external`` (including those from `example.com`).

.. warning ::

   It is possible to configure multiple instances of the same plugin into
   the same view or in the same zone, either directly or by inclusion from
   a :any:`template`.  While this configuration is legal, it should be
   avoided unless the plugin has been specifically designed for such use.
   The behavior of the first instance of a plugin used in a query may
   prevent subsequent instances from being called, causing unexpected
   behavior.


Developing Plugins
~~~~~~~~~~~~~~~~~~

Each plugin implements four functions:

-  ``plugin_register``
   to allocate memory, configure a plugin instance, and attach to hook
   points within
   :iscman:`named`
   ,
-  ``plugin_destroy``
   to tear down the plugin instance and free memory,
-  ``plugin_version``
   to check that the plugin is compatible with the current version of
   the plugin API,
-  ``plugin_check``
   to test syntactic correctness of the plugin parameters.

At various locations within the :iscman:`named` source code, there are "hook
points" at which a plugin may register itself. When a hook point is
reached while :iscman:`named` is running, it is checked to see whether any
plugins have registered themselves there; if so, the associated "hook
action" - a function within the plugin library - is called. Hook
actions may examine the runtime state and make changes: for example,
modifying the answers to be sent back to a client or forcing a query to
be aborted. More details can be found in the file
``lib/ns/include/ns/hooks.h``.
