##
##  Makefile -- Build procedure for sample dosdetector Apache module
##  Autogenerated via ``apxs -n dosdetector -g''.
##

#   the used tools
APXS=/usr/local/sbin/apxs
APACHECTL=apachectl

#   additional user defines, includes and libraries
#DEF=-Dmy_define=my_value
#INC=-Imy/include/dir
#LIB=-Lmy/lib/dir -lmylib

#   the default target
all: mod_dosdetector_syslog.so

#   compile the DSO file
mod_dosdetector_syslog.so: mod_dosdetector_syslog.c
	$(APXS) -c $(DEF) $(INC) $(LIB) mod_dosdetector_syslog.c

#   install the DSO file into the Apache installation
#   and activate it in the Apache configuration
install: all
	$(APXS) -c -i -a -n 'dosdetector_syslog' mod_dosdetector_syslog.c

#   cleanup
clean:
	-rm -f mod_dosdetector_syslog.o mod_dosdetector_syslog.so mod_dosdetector_syslog.lo mod_dosdetector_syslog.slo mod_dosdetector_syslog.la .libs/mod_dosdetector_syslog.a .libs/mod_dosdetector_syslog.o .libs/mod_dosdetector_syslog.la .libs/mod_dosdetector_syslog.so .libs/mod_dosdetector_syslog.lai
	-rmdir .libs

#   simple test
test: reload
	lynx -mime_header http://localhost/dosdetector

#   reload the module by installing and restarting Apache
reload: install restart

#   the general Apache start/restart/stop procedures
start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop

