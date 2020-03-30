#!/usr/bin/env perl
use strict;
use lib '.';
use warnings;
use SOCKS5;

my $server = SOCKS5->new(socks_port => 9066);
$server->start_proxy();
