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
# TORTIOUS ACITON, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#
# usage: filter auth-ban proc-exec "/etc/mail/filter-authban"
#        listen on egress filter auth-ban
#
# TODO: accept command line setting of `allowed'
#

function logit(msg) {
	system("logger -p mail.info " msg)
}

function die(msg) {
	system("logger -p mail.err -s " msg)

	exit 1
}

BEGIN {
	while (getline addr < "/tmp/authban" > 0)
		print addr
	ARGC = 0
	FS = "|"
	OFS = FS
	version = 0.5
	allowed = 3
	logit("starting...")
	system("rm /tmp/authban")
}

"config|ready" == $0 {
	print "register|report|smtp-in|link-connect"
	print "register|report|smtp-in|link-disconnect"
	print "register|report|smtp-in|link-auth"
	print "register|filter|smtp-in|connect"
	print "register|ready"
	next
}

"link-connect" == $5 {
	if (NF < 10)
		die("invalid input for link-connect")
	if ($2 != version)
		die("version mismatch")
	sid = $6
	src = $9

	state[sid] = src 
}

"link-auth" == $5 {
	if (NF < 8)
		die("invalid input for link-auth")
	if ($2 != version)
		die("version mismatch")
	sid = $6
	user = $7
	result = $8

	if (state[sid]) {
		split(state[sid], ip, ":")
		addr = ip[1]
		if (result == "fail") {
			logit("auth failure for " user " from " addr)
			state[addr] += 1
		}
		if (state[addr] >= allowed)
			banned[addr] = 1
	}
}

"link-disconnect" == $5 {
	if (NF < 6)
		die("invalid input for link-disconnect")
	if ($2 != version)
		die("version mismatch")
	sid = $6

	delete state[sid]
}

"connect" == $5 {
	if ($2 != version) 
		die("version mismatch")
	sid = $6
	token = $7
	src = $9

	if (banned[src]) {
		logit("rejecting connection from:" src)
		print "filter-result|" token "|" sid "|reject|550 go away"
	} else
		print "filter-result|" token "|" sid "|proceed"
}

END {
	for (addr in banned)
		print addr >> "/tmp/authban"

	logit("stopping...")
}
