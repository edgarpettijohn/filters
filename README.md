# filters
filters for opensmtpd

filter-authban.awk
Requires: /usr/bin/awk and /usr/bin/logger

Should be used with a listen directive that provides authentication or it won't do much. 
It's currently hardcoded to reject connections after they have failed to authenticate 3 or more times.

filter-dnsbl.awk
Requires: /usr/bin/awk, /usr/bin/logger, and /usr/bin/host

Should be used on a listen directive for incoming mail. It is possible that a user's ip is in a dnsbl and 
we wouldn't want to deny them the ability to relay, granted they can authenticate.
It seems fast enough for me plus the memory footprint is considerably smaller than other dnsbl filters I've seen.
