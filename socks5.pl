#!/usr/bin/env perl

#by LvMalware <https://github.com/LvMalware>

use utf8;
use strict;
use threads;
use warnings;
use IO::Socket::INET;
use Encode qw(encode);

use constant SOCKS_VERSION => 5;

sub add_log
{
    my $now = localtime();
    print STDOUT "[$now] $_[0]\n";
}

sub server_loop
{
    my ($host, $port, $username, $password, $log_file) = @_;
    open(STDOUT, ">", $log_file) if defined($log_file);
    my $server = IO::Socket::INET->new(
        Listen    => 5,
        ReuseAddr => 1,
        LocalAddr => $host,
        LocalPort => $port,
    ) || die "Can't create the server: $!";
    add_log("Started SOCKS5 server using port $port");
    while (1)
    {
        my $client   = $server->accept();
        my $cli_host = $client->peerhost();
        my $cli_port = $client->peerport();
        add_log("Accepted connection from $cli_host:$cli_port");
        my $identifier;
        $client->recv($identifier, 2);
        my ($version, $nmethods) = unpack("CC", $identifier);
        unless ($version == SOCKS_VERSION)
        {
            add_log("$cli_host - invalid version requested.");
            $client->close();
            next;
        }
        unless ($nmethods > 0)
        {
            add_log("$cli_host - no methods requested.");
            $client->close();
            next;
        }
        add_log("$cli_host - requested $nmethods methods.");
        my @methods = map {
            my $m;
            $client->recv($m, 1);
            ord($m);
        } 1 .. $nmethods;

        #verify if authentication is necessary
        #for now, only username/password authentication is supported.
        if (defined($username) && defined($password))
        {
            unless (grep /^2$/, @methods)
            {
                add_log("$cli_host - must authenticate first.");
                $client->close();
                next;
            }
            unless (authenticate_user($client, $username, $password))
            {
                add_log("$cli_host - failed to authenticate.");
                $client->close();
                next;
            }

            add_log("$cli_host - authenticated successful.");

        }
        else
        {
            add_log("$cli_host - no authentication needed.");
            $client->send(pack("CC", SOCKS_VERSION, 0));
        }
        my $request_header;
        $client->recv($request_header, 4);
        my ($ver, $cmd, $rsv, $atyp) = unpack("CCCC", $request_header);
        my ($dst_addr, $dst_port);
        if ($atyp == 1) #IPv4
        {
            $client->recv($dst_addr, 4);
            $dst_addr = inet_ntoa($dst_addr);
        }
        elsif ($atyp == 3) #DOMAIN NAME
        {
            my $addr_len;
            $client->recv($addr_len, 1);
            $client->recv($dst_addr, ord($addr_len));
        }
        elsif ($atyp == 4) #IPv6
        {
            $client->recv($dst_addr, 16);
            $dst_addr = inet_ntop(AF_INET6, $dst_addr);
        }
        else #UNKOWN (possively a mistake)
        {
            status_reply($client, 8, $rsv, $atyp, addr_to_int($host), $port);
            next;
        }
        
        $client->recv($dst_port, 2);
        $dst_port = unpack("n", $dst_port);

        if ($cmd == 1) #CONNECT
        {
            my $target = IO::Socket::INET->new(
                PeerAddr => $dst_addr,
                PeerPort => $dst_port,
                Proto    => 'tcp'
            );
            unless (defined ($target))
            {
                add_log("$cli_host - failed to connect to $dst_addr:$dst_port");
                status_reply($client, 5, $rsv, $atyp, 0, 0);
                $client->close();
                next;
            }
            add_log("$cli_host - connected to $dst_addr:$dst_port");
            status_reply($client, 0, $rsv, $atyp, addr_to_int($host), $port);
            threads->new(\&client_to_target, $client, $target);
            threads->new(\&target_to_client, $client, $target);
        }
        elsif ($cmd == 2) #BIND
        {
            #not implemented yet
            status_reply($client, 7, $rsv, $atyp, addr_to_int($host), $port);
            $client->close();
            next;
        }
        elsif ($cmd == 3) #UDP ASSOCIATE
        {
            #not implemented yet
            status_reply($client, 7, $rsv, $atyp, addr_to_int($host), $port);
            $client->close();
            next;
        }
        else #UNKNOWN (possively a mistake)
        {
            status_reply($client, 7, $rsv, $atyp, 0, 0);
            $client->close();
            next;
        }
    }
}

sub addr_to_int { unpack "I", inet_aton($_[0]) }

sub client_to_target
{
    my ($client, $target) = @_;
    while (1)
    {
        my $data = "";
        $client->recv($data, 2048);
        last unless ((length($data) > 0) && ($target->send($data) == length($data)));
    }
}

sub target_to_client
{
    my ($client, $target) = @_;
    while (1)
    {
        my $data = "";
        $target->recv($data, 2048);
        last unless ((length($data) > 0) && ($client->send($data) == length($data)));
    }
}

sub status_reply
{
    my ($client, $rep, $rsv, $atyp, $bnd_addr, $bnd_port) = @_;
    $client->send(pack("CCCCIn", SOCKS_VERSION, $rep, $rsv, $atyp, $bnd_addr, $bnd_port));
}

sub authenticate_user
{
    my ($client, $username, $password) = @_;
    $client->send(pack("CC", SOCKS_VERSION, 2));
    my ($version, $usr_len, $pass_len, $pass, $user);
    $client->recv($version, 1);
    $client->recv($usr_len, 1);
    $client->recv($user, ord($usr_len));
    $client->recv($pass_len, 1);
    $client->recv($pass, ord($pass_len));
    $user = encode('utf-8', $user);
    $pass = encode('utf-8', $pass);
    if (($user eq $username) && ($pass eq $password))
    {
        $client->send(pack("CC", ord($version), 0));
        return 1;
    }
    $client->send(pack("CC", ord($version), 0xFF));
    return 0;
}

server_loop("0.0.0.0", 9666, "user", "pass");