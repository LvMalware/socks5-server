use utf8;
use strict;
use threads;
use warnings;
use IO::Select;
use threads::shared;
use IO::Socket::INET;
use Encode qw(encode decode);
use open IO  => ':encoding(UTF-8)';
use constant SOCKS_VERSION => 5;
my ($username, $password);
share($username);
share($password);

sub add_log
{
    my $now = localtime();
    print STDOUT "[$now] $_[0]\n";
}

sub start_proxy
{
    my %args = @_;
    open(STDOUT, ">", $args{log_file}) if defined($args{log_file});
    my $host  = $args{host} || "0.0.0.0";
    my $port  = $args{port} || 9666;
    $username = $args{user} || "user";
    $password = $args{pass} || "pass";
    add_log("Starting SOCKS5 server. Using port $port");
    my $server = IO::Socket::INET->new(
        Listen    => 5,
        LocalAddr => $host,
        LocalPort => $port,
        Proto     => 'tcp',
        ReuseAddr => 1
    ) || die "Can't create the server: $!";
    threads->create('thread_server', $server)->join();
}

sub stop_proxy
{
    my @threads = threads->list();
    for my $th (@threads)
    {
        $th->kill('KILL')->join();
    }
}

sub thread_server
{
    my ($server) = @_;
    $SIG{'KILL'} = sub { $server->shutdown(2); $server->close(); undef($server) };
    while (defined($server))
    {
        my $client   = $server->accept();
        my $cli_host = $client->peerhost();
        my $cli_port = $client->peerport();
        add_log("Accepted connection from $cli_host:$cli_port");
        my $header;
        #receive the greeting header
        $client->recv($header, 2);
        #unpack the version and methods
        my ($version, $nmethods) = unpack("CC", $header);
        #verify if the requested version is supported
        unless ($version == SOCKS_VERSION)
        {
            $client->close();
            add_log("$cli_host requested an unsupported version ($version)");
            next;
        }
        #verify the number of requested methods
        unless ($nmethods > 0)
        {
            $client->close();
            add_log("$cli_host requested invalid methods ($nmethods)");
            next;
        }
        #receive avaiable methods
        my @methods = map {my $m; $client->recv($m, 1); ord($m) } 1 .. $nmethods;
        #verify authentication request
        unless (grep /^2$/, @methods)
        {
            $client->close();
            add_log("$cli_host must authenticate first.");
            next;
        }
        $client->send(pack("CC", SOCKS_VERSION, 2));
        if (authenticate_client($client))
        {
            my $data;
            $client->recv($data, 4);
            my ($version, $cmd, $foo, $addr_type) = unpack("CCCC", $data);
            unless ($version == SOCKS_VERSION)
            {
                $client->close();
                add_log("$cli_host requested an unsupported version ($version)");
                next;
            }
            my $address;
            if ($addr_type == 1) #IPv4
            { 
                add_log("$cli_host requested IPv4 connection");
                $client->recv($address, 4);
                $address = inet_ntoa($address);
            }
            elsif ($addr_type == 3) #Domain Name
            {
                add_log("$cli_host requested Domain Name connection");
                my $len;
                $client->recv($len, 1);
                $len = ord($len);
                $client->recv($address, $len);
            }
            elsif ($addr_type == 4) #IPv6
            {
                add_log("$cli_host requested IPv6 connection");
                $client->recv($address, 16);
                $address = inet_ntop(AF_INET6, $address);
            }
            my $port;
            $client->recv($port, 2);
            $port = hex join('', map {sprintf("%02x", ord($_))} split //, $port);
            add_log("$cli_host requested IPv4 connection to $address:$port");
            my $target;
            if ($cmd == 1) #CONNECT
            {
                $target = IO::Socket::INET->new(
                    PeerAddr => $address,
                    PeerPort => $port,
                    Proto    => "tcp"
                )
                ||
                (add_log("$cli_host Failed to connect to $address:$port") && err_replay($client, $addr_type, 5) && next);
                add_log("$cli_host connected to $address:$port");
            }
            else
            {
                $client->shutdown(2);
                $client->close();
                add_log($client->peerhost() . " invalid command");
                next;
            }
            my @bind_addr = sockaddr_in(getsockname($target));
            my ($myport, $myaddr) = ($bind_addr[0], unpack("I", $bind_addr[1]));
            my $ok = $client->send(pack("CCCC", SOCKS_VERSION, 0, 0, $addr_type) . inet_aton("0.0.0.0") . pack("H", $myport));
            ($client->close() && next) unless ($ok > 0);
            if ($cmd == 1)
            {
                threads->create('handle_client', $client, $target)->join();
            }
            else
            {
                $client->shutdown(2);
                $client->close();
            }
        }
    }
}

sub authenticate_client
{
    my ($client) = @_;
    my $version;
    $client->recv($version, 1);
    my ($usr_len, $pwd_len, $user, $pass);
    $client->recv($usr_len, 1);
    $client->recv($user, ord($usr_len));
    $client->recv($pwd_len, 1);
    $client->recv($pass, ord($pwd_len));
    $user = encode('utf-8', $user);
    $pass = encode('utf-8', $pass);
    if (($user eq $username) and ($pass eq $password))
    {
        $client->send(pack("CC", ord($version), 0));
        add_log($client->peerhost() . " authenticated.");
    }
    else
    {
        eval { $client->send(pack("CC", ord($version), 0xFF)); client->close(); };
        
        add_log($client->peerhost() . " invalid username and/or password");
        return 0;
    }
    1;
}

sub err_replay
{
    my ($client, $addr_type, $err_number) = @_;
    $client->send(pack("CCCCIH", SOCKS_VERSION, $err_number, 0, $addr_type, 0, 0));
    $|++;
    $client->shutdown(2);
    $client->close()
}

sub handle_client
{
    my ($client, $target) = @_;
    my $host = $client->peerhost();
    my $targ = $target->peerhost();
    add_log("handling connection from $host with $targ");
    while (defined($client))
    {
        my @ready = IO::Select->new($client, $target)->can_read();
        foreach my $sock (@ready)
        {
            my $data = "";
            if ($sock == $client)
            {
                $client->recv($data, 4096);
                if ((length($data) == 0) || ($target->send($data) < length($data)))
                {
                    $client->close();
                    $target->close();
                    $client = undef;
                    $target = undef;
                    next;
                }
                #$|++;
            }
            elsif ($sock ==  $target)
            {
                $target->recv($data, 4096);
                if ((length($data) == 0) || ($client->send($data) < length($data)))
                {
                    $client->close();
                    $target->close();
                    $client = undef;
                    $target = undef;
                    next;
                }
                #$|++;
            }
        }
    }
    add_log("$host disconnected.");
    threads->exit();
}

start_proxy();