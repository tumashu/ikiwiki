#!/usr/bin/perl
use warnings;
use strict;

use Test::More;
plan(skip_all => "IPC::Run not available")
	unless eval q{
		use IPC::Run qw(run);
		1;
	};

use IkiWiki;

use Cwd qw(getcwd);
use Errno qw(ENOENT);

# Black-box (ish) test for relative linking between CGI and static content

my $installed = $ENV{INSTALLED_TESTS};

my @command;
if ($installed) {
	@command = qw(ikiwiki);
}
else {
	ok(! system("make -s ikiwiki.out"));
	@command = ("perl", "-I".getcwd, qw(./ikiwiki.out
		--underlaydir=underlays/basewiki
		--set underlaydirbase=underlays
		--templatedir=templates));
}

sub parse_cgi_content {
	my $content = shift;
	my %bits;
	if ($content =~ qr{<base href="([^"]+)" */>}) {
		$bits{basehref} = $1;
	}
	if ($content =~ qr{href="([^"]+/style.css)"}) {
		$bits{stylehref} = $1;
	}
	if ($content =~ qr{class="parentlinks">\s+<a href="([^"]+)">this is the name of my wiki</a>/}s) {
		$bits{tophref} = $1;
	}
	if ($content =~ qr{<a[^>]+href="([^"]+)\?do=prefs"}) {
		$bits{cgihref} = $1;
	}
	return %bits;
}

sub write_old_file {
	my $name = shift;
	my $content = shift;

	writefile($name, "t/tmp/in", $content);
	ok(utime(333333333, 333333333, "t/tmp/in/$name"));
}

sub write_setup_file {
	my (%args) = @_;
	my $urlline = defined $args{url} ? "url: $args{url}" : "";
	my $w3mmodeline = defined $args{w3mmode} ? "w3mmode: $args{w3mmode}" : "";
	my $reverseproxyline = defined $args{reverse_proxy} ? "reverse_proxy: $args{reverse_proxy}" : "";

	writefile("test.setup", "t/tmp", <<EOF
# IkiWiki::Setup::Yaml - YAML formatted setup file
wikiname: this is the name of my wiki
srcdir: t/tmp/in
destdir: t/tmp/out
$urlline
cgiurl: $args{cgiurl}
$w3mmodeline
cgi_wrapper: t/tmp/ikiwiki.cgi
cgi_wrappermode: 0754
# make it easier to test previewing
add_plugins:
- anonok
anonok_pagespec: "*"
$reverseproxyline
ENV: { 'PERL5LIB': 'blib/lib:blib/arch' }
EOF
	);
}

sub thoroughly_rebuild {
	ok(unlink("t/tmp/ikiwiki.cgi") || $!{ENOENT});
	ok(! system(@command, qw(--setup t/tmp/test.setup --rebuild --wrappers)));
}

sub check_cgi_mode_bits {
	my (undef, undef, $mode, undef, undef,
		undef, undef, undef, undef, undef,
		undef, undef, undef) = stat("t/tmp/ikiwiki.cgi");
	is($mode & 07777, 0754);
}

sub check_generated_content {
	my $cgiurl_regex = shift;
	ok(-e "t/tmp/out/a/b/c/index.html");
	my $content = readfile("t/tmp/out/a/b/c/index.html");
	# no <base> on static HTML
	unlike($content, qr{<base\W});
	like($content, $cgiurl_regex);
	# cross-links between static pages are relative
	like($content, qr{<li>A: <a href="../../">a</a></li>});
	like($content, qr{<li>B: <a href="../">b</a></li>});
	like($content, qr{<li>E: <a href="../../d/e/">e</a></li>});
}

sub run_cgi {
	my (%args) = @_;
	my ($in, $out);
	my $is_preview = delete $args{is_preview};
	my $is_https = delete $args{is_https};
	my $goto = delete $args{goto};
	my %defaults = (
		SCRIPT_NAME	=> '/cgi-bin/ikiwiki.cgi',
		HTTP_HOST	=> 'example.com',
	);
	if (defined $goto) {
		$defaults{REQUEST_METHOD} = 'GET';
		$defaults{QUERY_STRING} = 'do=goto&page=a/b/c';
	}
	elsif (defined $is_preview) {
		$defaults{REQUEST_METHOD} = 'POST';
		$in = 'do=edit&page=a/b/c&Preview';
		$defaults{CONTENT_LENGTH} = length $in;
	} else {
		$defaults{REQUEST_METHOD} = 'GET';
		$defaults{QUERY_STRING} = 'do=prefs';
	}
	if (defined $is_https) {
		$defaults{SERVER_PORT} = '443';
		$defaults{HTTPS} = 'on';
	} else {
		$defaults{SERVER_PORT} = '80';
	}
	my %envvars = (
		%defaults,
		%args,
	);
	run(["./t/tmp/ikiwiki.cgi"], \$in, \$out, init => sub {
		map {
			$ENV{$_} = $envvars{$_}
		} keys(%envvars);
	});

	return $out;
}

sub check_goto {
	my $expected = shift;
	my $redirect = run_cgi(goto => 1, @_);
	ok($redirect =~ m/^Status:\s*302\s+/m);
	ok($redirect =~ m/^Location:\s*(\S*)\r?\n/m);
	my $location = $1;
	like($location, $expected);
}

sub test_startup {
	ok(! system("rm -rf t/tmp"));
	ok(! system("mkdir t/tmp"));

	write_old_file("a.mdwn", "A");
	write_old_file("a/b.mdwn", "B");
	write_old_file("a/b/c.mdwn",
	"* A: [[a]]\n".
	"* B: [[b]]\n".
	"* E: [[a/d/e]]\n");
	write_old_file("a/d.mdwn", "D");
	write_old_file("a/d/e.mdwn", "E");
}

sub test_site1_perfectly_ordinary_ikiwiki {
	diag("test_site1_perfectly_ordinary_ikiwiki");
	write_setup_file(
		url	=> "http://example.com/wiki/",
		cgiurl	=> "http://example.com/cgi-bin/ikiwiki.cgi",
	);
	thoroughly_rebuild();
	check_cgi_mode_bits();
	# url and cgiurl are on the same host so the cgiurl is host-relative
	check_generated_content(qr{<a[^>]+href="/cgi-bin/ikiwiki.cgi\?do=prefs"});
	check_goto(qr{^http://example\.com/wiki/a/b/c/$});
	my %bits = parse_cgi_content(run_cgi());
	like($bits{basehref}, qr{^(?:(?:http:)?//example\.com)?/wiki/$});
	like($bits{stylehref}, qr{^(?:(?:http:)?//example.com)?/wiki/style.css$});
	like($bits{tophref}, qr{^(?:/wiki|\.)/$});
	like($bits{cgihref}, qr{^(?:(?:http:)?//example.com)?/cgi-bin/ikiwiki.cgi$});

	# when accessed via HTTPS, links are secure
	%bits = parse_cgi_content(run_cgi(is_https => 1));
	like($bits{basehref}, qr{^(?:(?:https:)?//example\.com)?/wiki/$});
	like($bits{stylehref}, qr{^(?:(?:https:)?//example.com)?/wiki/style.css$});
	like($bits{tophref}, qr{^(?:/wiki|\.)/$});
	like($bits{cgihref}, qr{^(?:(?:https:)?//example.com)?/cgi-bin/ikiwiki.cgi$});
	check_goto(qr{^https://example\.com/wiki/a/b/c/$}, is_https => 1);

	# when accessed via a different hostname, links stay on that host
	%bits = parse_cgi_content(run_cgi(HTTP_HOST => 'staging.example.net'));
	like($bits{basehref}, qr{^(?:(?:http:)?//staging\.example\.net)?/wiki/$});
	like($bits{stylehref}, qr{^(?:(?:http:)?//staging.example.net)?/wiki/style.css$});
	like($bits{tophref}, qr{^(?:/wiki|\.)/$});
	like($bits{cgihref}, qr{^(?:(?:http:)?//staging.example.net)?/cgi-bin/ikiwiki.cgi$});
	TODO: {
	local $TODO = "hostname should be copied to redirects' Location";
	check_goto(qr{^https://staging\.example\.net/wiki/a/b/c/$}, is_https => 1);
	}

	# previewing a page
	%bits = parse_cgi_content(run_cgi(is_preview => 1));
	like($bits{basehref}, qr{^(?:(?:http:)?//example\.com)?/wiki/a/b/c/$});
	like($bits{stylehref}, qr{^(?:(?:http:)?//example.com)?/wiki/style.css$});
	like($bits{tophref}, qr{^(?:/wiki|\.\./\.\./\.\.)/$});
	like($bits{cgihref}, qr{^(?:(?:http:)?//example.com)?/cgi-bin/ikiwiki.cgi$});
}

sub test_site2_static_content_and_cgi_on_different_servers {
	diag("test_site2_static_content_and_cgi_on_different_servers");
	write_setup_file(
		url	=> "http://static.example.com/",
		cgiurl	=> "http://cgi.example.com/ikiwiki.cgi",
	);
	thoroughly_rebuild();
	check_cgi_mode_bits();
	# url and cgiurl are not on the same host so the cgiurl has to be
	# protocol-relative or absolute
	check_generated_content(qr{<a[^>]+href="(?:http:)?//cgi.example.com/ikiwiki.cgi\?do=prefs"});
	check_goto(qr{^http://static\.example\.com/a/b/c/$});

	my %bits = parse_cgi_content(run_cgi(SCRIPT_NAME => '/ikiwiki.cgi', HTTP_HOST => 'cgi.example.com'));
	like($bits{basehref}, qr{^(?:(?:http:)?//static.example.com)?/$});
	like($bits{stylehref}, qr{^(?:(?:http:)?//static.example.com)?/style.css$});
	like($bits{tophref}, qr{^(?:http:)?//static.example.com/$});
	like($bits{cgihref}, qr{^(?:(?:http:)?//cgi.example.com)?/ikiwiki.cgi$});

	# when accessed via HTTPS, links are secure
	%bits = parse_cgi_content(run_cgi(is_https => 1, SCRIPT_NAME => '/ikiwiki.cgi', HTTP_HOST => 'cgi.example.com'));
	like($bits{basehref}, qr{^(?:https:)?//static\.example\.com/$});
	like($bits{stylehref}, qr{^(?:(?:https:)?//static.example.com)?/style.css$});
	like($bits{tophref}, qr{^(?:https:)?//static.example.com/$});
	like($bits{cgihref}, qr{^(?:(?:https:)?//cgi.example.com)?/ikiwiki.cgi$});
	check_goto(qr{^https://static\.example\.com/a/b/c/$}, is_https => 1,
		HTTP_HOST => 'cgi.example.com', SCRIPT_NAME => '/ikiwiki.cgi');

	# when accessed via a different hostname, links to the CGI (only) should
	# stay on that host?
	%bits = parse_cgi_content(run_cgi(is_preview => 1, SCRIPT_NAME => '/ikiwiki.cgi', HTTP_HOST => 'staging.example.net'));
	like($bits{basehref}, qr{^(?:http:)?//static\.example\.com/a/b/c/$});
	like($bits{stylehref}, qr{^(?:(?:http:)?//static.example.com|\.\./\.\./\.\.)/style.css$});
	like($bits{tophref}, qr{^(?:(?:http:)?//static.example.com|\.\./\.\./\.\.)/$});
	like($bits{cgihref}, qr{^(?:(?:http:)?//(?:staging\.example\.net|cgi\.example\.com))?/ikiwiki.cgi$});
	TODO: {
	local $TODO = "use self-referential CGI URL?";
	like($bits{cgihref}, qr{^(?:(?:http:)?//staging.example.net)?/ikiwiki.cgi$});
	}
	check_goto(qr{^https://static\.example\.com/a/b/c/$}, is_https => 1,
		HTTP_HOST => 'staging.example.net', SCRIPT_NAME => '/ikiwiki.cgi');
}

sub test_site3_we_specifically_want_everything_to_be_secure {
	diag("test_site3_we_specifically_want_everything_to_be_secure");
	write_setup_file(
		url	=> "https://example.com/wiki/",
		cgiurl	=> "https://example.com/cgi-bin/ikiwiki.cgi",
	);
	thoroughly_rebuild();
	check_cgi_mode_bits();
	# url and cgiurl are on the same host so the cgiurl is host-relative
	check_generated_content(qr{<a[^>]+href="/cgi-bin/ikiwiki.cgi\?do=prefs"});

	# when accessed via HTTPS, links are secure
	my %bits = parse_cgi_content(run_cgi(is_https => 1));
	like($bits{basehref}, qr{^(?:(?:https:)?//example\.com)?/wiki/$});
	like($bits{stylehref}, qr{^(?:(?:https:)?//example.com)?/wiki/style.css$});
	like($bits{tophref}, qr{^(?:/wiki|\.)/$});
	like($bits{cgihref}, qr{^(?:(?:https:)?//example.com)?/cgi-bin/ikiwiki.cgi$});
	check_goto(qr{^https://example\.com/wiki/a/b/c/$}, is_https => 1);

	# when not accessed via HTTPS, links should still be secure
	# (but if this happens, that's a sign of web server misconfiguration)
	%bits = parse_cgi_content(run_cgi());
	like($bits{tophref}, qr{^(?:/wiki|\.)/$});
	TODO: {
	local $TODO = "treat https in configured url, cgiurl as required?";
	is($bits{basehref}, "https://example.com/wiki/");
	like($bits{stylehref}, qr{^(?:(?:https:)?//example.com)?/wiki/style.css$});
	}
	like($bits{cgihref}, qr{^(?:(?:https:)?//example.com)?/cgi-bin/ikiwiki.cgi$});
	check_goto(qr{^https://example\.com/wiki/a/b/c/$}, is_https => 0);

	# when accessed via a different hostname, links stay on that host
	%bits = parse_cgi_content(run_cgi(is_https => 1, HTTP_HOST => 'staging.example.net'));
	like($bits{basehref}, qr{^(?:(?:https:)?//staging\.example\.net)?/wiki/$});
	like($bits{stylehref}, qr{^(?:(?:https:)?//staging.example.net)?/wiki/style.css$});
	like($bits{tophref}, qr{^(?:/wiki|\.)/$});
	like($bits{cgihref}, qr{^(?:(?:https:)?//staging.example.net)?/cgi-bin/ikiwiki.cgi$});
	check_goto(qr{^https://staging\.example\.net/wiki/a/b/c/$}, is_https => 1,
		HTTP_HOST => 'staging.example.net');

	# previewing a page
	%bits = parse_cgi_content(run_cgi(is_preview => 1, is_https => 1));
	like($bits{basehref}, qr{^(?:(?:https:)?//example\.com)?/wiki/a/b/c/$});
	like($bits{stylehref}, qr{^(?:(?:https:)?//example.com)?/wiki/style.css$});
	like($bits{tophref}, qr{^(?:/wiki|\.\./\.\./\.\.)/$});
	like($bits{cgihref}, qr{^(?:(?:https:)?//example.com)?/cgi-bin/ikiwiki.cgi$});
}

sub test_site4_cgi_is_secure_static_content_doesnt_have_to_be {
	diag("test_site4_cgi_is_secure_static_content_doesnt_have_to_be");
	# (NetBSD wiki)
	write_setup_file(
		url	=> "http://example.com/wiki/",
		cgiurl	=> "https://example.com/cgi-bin/ikiwiki.cgi",
	);
	thoroughly_rebuild();
	check_cgi_mode_bits();
	# url and cgiurl are on the same host but different schemes
	check_generated_content(qr{<a[^>]+href="https://example.com/cgi-bin/ikiwiki.cgi\?do=prefs"});

	# when accessed via HTTPS, links are secure (to avoid mixed-content)
	my %bits = parse_cgi_content(run_cgi(is_https => 1));
	like($bits{basehref}, qr{^(?:(?:https:)?//example\.com)?/wiki/$});
	like($bits{stylehref}, qr{^(?:(?:https:)?//example.com)?/wiki/style.css$});
	like($bits{tophref}, qr{^(?:/wiki|\.)/$});
	like($bits{cgihref}, qr{^(?:(?:https:)?//example.com)?/cgi-bin/ikiwiki.cgi$});
	check_goto(qr{^https://example\.com/wiki/a/b/c/$}, is_https => 1);

	# FIXME: when not accessed via HTTPS, should the static content be
	# forced to https anyway? For now we accept either
	%bits = parse_cgi_content(run_cgi());
	like($bits{basehref}, qr{^(?:(?:https?)?://example\.com)?/wiki/$});
	like($bits{stylehref}, qr{^(?:(?:https?:)?//example.com)?/wiki/style.css$});
	like($bits{tophref}, qr{^(?:(?:https?://example.com)?/wiki|\.)/$});
	like($bits{cgihref}, qr{^(?:(?:https:)?//example.com)?/cgi-bin/ikiwiki.cgi$});
	check_goto(qr{^https://example\.com/wiki/a/b/c/$}, is_https => 0);

	# when accessed via a different hostname, links stay on that host
	%bits = parse_cgi_content(run_cgi(is_https => 1, HTTP_HOST => 'staging.example.net'));
	# because the static and dynamic stuff is on the same server, we assume that
	# both are also on the staging server
	like($bits{basehref}, qr{^(?:(?:https:)?//staging\.example\.net)?/wiki/$});
	like($bits{stylehref}, qr{^(?:(?:https:)?//staging.example.net)?/wiki/style.css$});
	like($bits{tophref}, qr{^(?:(?:(?:https:)?//staging.example.net)?/wiki|\.)/$});
	like($bits{cgihref}, qr{^(?:(?:https:)?//(?:staging\.example\.net|example\.com))?/cgi-bin/ikiwiki.cgi$});
	TODO: {
	local $TODO = "this should really point back to itself but currently points to example.com";
	like($bits{cgihref}, qr{^(?:(?:https:)?//staging.example.net)?/cgi-bin/ikiwiki.cgi$});
	}
	check_goto(qr{^https://staging\.example\.net/wiki/a/b/c/$}, is_https => 1,
		HTTP_HOST => 'staging.example.net');

	# previewing a page
	%bits = parse_cgi_content(run_cgi(is_preview => 1, is_https => 1));
	like($bits{basehref}, qr{^(?:(?:https:)?//example\.com)?/wiki/a/b/c/$});
	like($bits{stylehref}, qr{^(?:(?:https:)?//example.com)?/wiki/style.css$});
	like($bits{tophref}, qr{^(?:/wiki|\.\./\.\./\.\.)/$});
	like($bits{cgihref}, qr{^(?:(?:https:)?//example.com)?/cgi-bin/ikiwiki.cgi$});
}

sub test_site5_w3mmode {
	diag("test_site5_w3mmode");
	# as documented in [[w3mmode]]
	write_setup_file(
		url	=> undef,
		cgiurl	=> "ikiwiki.cgi",
		w3mmode	=> 1,
	);
	thoroughly_rebuild();
	check_cgi_mode_bits();
	# FIXME: does /$LIB/ikiwiki-w3m.cgi work under w3m?
	check_generated_content(qr{<a[^>]+href="(?:file://)?/\$LIB/ikiwiki-w3m.cgi/ikiwiki.cgi\?do=prefs"});

	my %bits = parse_cgi_content(run_cgi(PATH_INFO => '/ikiwiki.cgi', SCRIPT_NAME => '/cgi-bin/ikiwiki-w3m.cgi'));
	my $pwd = getcwd();
	like($bits{tophref}, qr{^(?:\Q$pwd\E/t/tmp/out|\.)/$});
	like($bits{cgihref}, qr{^(?:file://)?/\$LIB/ikiwiki-w3m.cgi/ikiwiki.cgi$});
	like($bits{basehref}, qr{^(?:(?:file:)?//)?\Q$pwd\E/t/tmp/out/$});
	like($bits{stylehref}, qr{^(?:(?:(?:file:)?//)?\Q$pwd\E/t/tmp/out|\.)/style.css$});

	my $redirect = run_cgi(goto => 1, PATH_INFO => '/ikiwiki.cgi',
		SCRIPT_NAME => '/cgi-bin/ikiwiki-w3m.cgi');
	like($redirect, qr{^Content-type: text/plain\r?\n}m);
	like($redirect, qr{^W3m-control: GOTO (?:file://)?\Q$pwd\E/t/tmp/out/a/b/c/\r?\n}m);
}

sub test_site6_behind_reverse_proxy {
	diag("test_site6_behind_reverse_proxy");
	write_setup_file(
		url	=> "https://example.com/wiki/",
		cgiurl	=> "https://example.com/cgi-bin/ikiwiki.cgi",
		reverse_proxy => 1,
	);
	thoroughly_rebuild();
	check_cgi_mode_bits();
	# url and cgiurl are on the same host so the cgiurl is host-relative
	check_generated_content(qr{<a[^>]+href="/cgi-bin/ikiwiki.cgi\?do=prefs"});

	# because we are behind a reverse-proxy we must assume that
	# we're being accessed by the configured cgiurl
	my %bits = parse_cgi_content(run_cgi(HTTP_HOST => 'localhost'));
	like($bits{tophref}, qr{^(?:/wiki|\.)/$});
	like($bits{cgihref}, qr{^(?:(?:https:)?//example.com)?/cgi-bin/ikiwiki.cgi$});
	like($bits{basehref}, qr{^(?:(?:https:)?//example\.com)?/wiki/$});
	like($bits{stylehref}, qr{^(?:(?:https:)?//example.com)?/wiki/style.css$});
	check_goto(qr{^https://example\.com/wiki/a/b/c/$}, HTTP_HOST => 'localhost');

	# previewing a page
	%bits = parse_cgi_content(run_cgi(is_preview => 1, HTTP_HOST => 'localhost'));
	like($bits{tophref}, qr{^(?:/wiki|\.\./\.\./\.\.)/$});
	like($bits{cgihref}, qr{^(?:(?:https:)?//example.com)?/cgi-bin/ikiwiki.cgi$});
	like($bits{basehref}, qr{^(?:(?:https)?://example\.com)?/wiki/a/b/c/$});
	like($bits{stylehref}, qr{^(?:(?:https:)?//example.com)?/wiki/style.css$});
}

test_startup();

test_site1_perfectly_ordinary_ikiwiki();
test_site2_static_content_and_cgi_on_different_servers();
test_site3_we_specifically_want_everything_to_be_secure();
test_site4_cgi_is_secure_static_content_doesnt_have_to_be();
test_site5_w3mmode();
test_site6_behind_reverse_proxy();

done_testing();
