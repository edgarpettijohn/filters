# filters
filters for opensmtpd

filter-authban.awk
Requires: /usr/bin/awk and /usr/bin/logger

Should be used with a listen directive that provides authentication or it won't do much. 
It's currently hardcoded to reject connections after they have failed to authenticate 3 or more times.
