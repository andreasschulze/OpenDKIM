-- Copyright (c) 2024, The Trusted Domain Project.
--   All rights reserved.

-- reject header larger then maximumheaders test
--
-- Confirms that an more headerdata as allowed produce a meaningful response

mt.echo("*** reject header larger then maximumheaders test")

-- setup
if TESTSOCKET ~= nil then
        sock = TESTSOCKET
else
        sock = "unix:" .. mt.getcwd() .. "/t-maximumheaders.sock"
end
binpath = mt.getcwd() .. "/.."
if os.getenv("srcdir") ~= nil then
        mt.chdir(os.getenv("srcdir"))
end

-- try to start the filter
mt.startfilter(binpath .. "/opendkim", "-x", "t-maximumheaders.conf",
               "-p", sock)

-- try to connect to it
conn = mt.connect(sock, 40, 0.25)
if conn == nil then
        error("mt.connect() failed")
end

-- send connection information
-- mt.negotiate() is called implicitly
if mt.conninfo(conn, "localhost", "unspec") ~= nil then
        error("mt.conninfo() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
        error("mt.conninfo() unexpected reply")
end

-- send envelope macros and sender data
-- mt.helo() is called implicitly
mt.macro(conn, SMFIC_MAIL, "i", "t-maximumheaders")
if mt.mailfrom(conn, "user@example.com") ~= nil then
        error("mt.mailfrom() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
        error("mt.mailfrom() unexpected reply")
end

-- send headers
-- mt.rcptto() is called implicitly
if mt.header(conn, "From", "user@example.com") ~= nil then
        error("mt.header(From) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
        error("mt.header(From) unexpected reply")
end
if mt.header(conn, "Date", "Tue, 27 Aug 2024 17:12:34 +0200") ~= nil then
        error("mt.header(Date) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
        error("mt.header(Date) unexpected reply")
end
if mt.header(conn, "Subject", "maximumheaders test") ~= nil then
        error("mt.header(Subject) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
        error("mt.header(Subject) unexpected reply")
end

-- until now, there are not more then 100 byte header sent
-- but now, the milter is expected to reject this "huge amount" of headerdata
if mt.header(conn, "x-this-exceeds-the-limit", "yes") ~= nil then
        error("mt.header()x-this-exceeds-the-limit failed")
end
if mt.getreply(conn) ~= SMFIR_REPLYCODE then
        error("mt.header(x-this-exceeds-the-limit) unexpected reply - expected REPLYCODE (reject)")
-- else
--      mt.echo("*** huge header data rejected as expected")
end

mt.abort(conn)
mt.disconnect(conn)
