#!/usr/bin/awk -f
#
# Copyright 2020 Edgar Pettijohn <edgar@pettijohn-web.com>
#
# Permission to use, copy, modify, and/or distribute this software for any purpose
# with or without fee is hereby granted, provided that the above copyright notice
# and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, 
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
# OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
# TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

function usage() {
	return "usage: filter-dnsbl dnsbl.sorbs.net"
}

function logit(msg) {
	system("logger -p mail.info " msg)
}

function die(msg) {
	system("logger -p mail.err -s " msg)

	exit 1
}

function reverse(addr) {
	print addr
	n = split(addr, i, ".")
	if (n != 4)
		return ""

	return i[4]"."i[3]"."i[2]"."i[1]
}

function lookup(addr) {
	reversed = reverse(addr)

	# must have been ipv6
	if (!length(reversed))
		return 0

	cmd = "host " reversed "." blacklist
	ret = 0

	while (cmd | getline answer > 0) 
		ans[answer] = 1

	for (a in ans) {
		if (match(a, "has"))
			ret = 1
	}
	if (close(cmd) != 0)
		die("can't close" cmd)

	return ret
}
	
BEGIN {
	blacklist = ARGV[1]
	ARGV[1] = ""
	ARGC = 0
	FS = "|"
	OFS = FS
	version = 0.4
	print blacklist
	if (!length(blacklist))
		die(usage())
	logit("filter-dnsbl: starting...")
}

"config|ready" == $0 {
	print "register|filter|smtp-in|connect"
	print "register|ready"
	next
}

"connect" == $5 {
	if ($2 != version)
		die("version mismatch")
	sid = $6
	token = $7
	src = $9

	if (lookup(src)) {
		logit("rejecting connection from: "src)
		print "filter-result|" token "|" sid "|reject|550 go away"
	} else {
		print "filter-result|" token "|" sid "|proceed"
	}
}

END {
	logit("filter-dnsbl: stopping...")
}
