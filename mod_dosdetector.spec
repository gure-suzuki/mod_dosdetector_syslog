%define name	%{mod_name}
%define version %{mod_version}
%define release 1

# Module-Specific definitions
%define mod_version	0.2
%define mod_name	mod_dosdetector_syslog
#%define mod_conf	13_%{mod_name}.conf
%define mod_so		%{mod_name}.so
%define sourcename	mod_dosdetector_syslog-master
%define apxs		/usr/sbin/apxs

Summary:	DoS attack detector for the Apache web server
Name:		%{name}
Version:	%{version}
Release:	%{release}
License:	Apache License
Group:		System/Servers
URL:		https://github.com/gure-suzuki/mod_dosdetector_syslog
Source0:	https://github.com/gure-suzuki/mod_dosdetector_syslog/archive/%{sourcename}.tar.gz

BuildRoot:	%{_tmppath}/%{name}-buildroot
BuildPrereq:	httpd-devel apr-devel

%description
mod_auth_pgsql can be used to limit access to documents served by
a web server by checking fields in a table in a PostgresQL
database.

%prep
%setup -q -n %{sourcename}

%build

%{apxs} -c mod_dosdetector_syslog.c -n mod_dosdetector_syslog.so

%install
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}
mkdir -p %{buildroot}%{_libdir}/httpd/modules/
cp .libs/mod_dosdetector_syslog.so %{buildroot}%{_libdir}/httpd/modules/
# %{apxs} -c -i -a -n 'dosdetector_syslog' mod_dosdetector_syslog.c

%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

%post

%postun

%files
%defattr(-,root,root)
%{_libdir}/httpd/modules/
#%config(noreplace) %{ap_confd}/%{mod_conf}
#%doc README INSTALL *.html

%changelog
* Fri Jan 19 2007  <stanaka@inco.hatena.com> - 0.1-1
- Initial release.

