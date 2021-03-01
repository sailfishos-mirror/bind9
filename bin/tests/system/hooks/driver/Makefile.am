include $(top_srcdir)/Makefile.top

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBDNS_CFLAGS)	\
	$(LIBNS_CFLAGS)		\
	$(LIBISCCFG_CFLAGS)

noinst_LTLIBRARIES = test-async.la

test_async_la_SOURCES = test-async.c

# use -rpath to force .libs/test-async.lai to made so that the install works
test_async_la_LDFLAGS = -avoid-version -module -shared -export-dynamic -rpath $(abs_builddir)

check:	$(noinst_LTLIBRARIES)
	$(LIBTOOL) --mode=install $(INSTALL) $(noinst_LTLIBRARIES) $(abs_builddir)
