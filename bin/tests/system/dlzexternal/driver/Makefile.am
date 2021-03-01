include $(top_srcdir)/Makefile.top

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBDNS_CFLAGS)

noinst_LTLIBRARIES = dlzexternal.la

dlzexternal_la_SOURCES =	\
	driver.c		\
	driver.h

# use -rpath to force .libs/dlzexternal.lai to made so that the install works
dlzexternal_la_LDFLAGS = -avoid-version -module -shared -export-dynamic -rpath $(abs_builddir)

check:	$(noinst_LTLIBRARIES)
	$(LIBTOOL) --mode=install $(INSTALL) $(noinst_LTLIBRARIES) $(abs_builddir)
