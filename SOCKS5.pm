package SOCKS5;
use strict;
use threads;
use warnings;
use IO::Select;
use base 'Exporter';
use threads::shared;
use Logging::Simple; #install: cpan install Logging::Simple
use IO::Socket::INET;
use Encode qw(encode decode);

our $VERSION = "0.1";

use constant SOCKS_VERSION => 5;

sub new
{
    my ($self, %args) = @_;
    my $data :shared = shared_clone({
        logger     => Logging::Simple->new,
        log_file   => $args{log_file},  #file name (default STDOUT)
        socks_port => $args{socks_port} || 9666,
        socks_user => $args{socks_user} || 'user',
        socks_pass => $args{socks_pass} || 'pass',
        socks_host => $args{socks_host} || '0.0.0.0', #listen for this address
    });
    bless $data, $self;
}

sub start_proxy
{
    my ($self) = @_;
    $self->{logger}->file($self->{log_file}) if defined($self->{log_file});
    $self->{logger}->_4("Starting SOCKS5 server. Using port $self->{socks_port}");
    $self->{server} = IO::Socket::INET->new(
        LocalAddr => $self->{socks_host},
        LocalPort => $self->{socks_port},
        Proto     => 'tcp'
    ) || die "Can't create the server: $!";
    $self->{th_listen} = threads->create('thread_server', $self);
}

sub stop_proxy
{
    my ($self) = @_;
    my @threads = threads->list();
    for my $th (@threads)
    {
        $th->kill('KILL')->join();
    }
}

sub thread_server
{
    my ($self) = @_;
    $SIG{'KILL'} = sub {
        $self->{server}->shutdown(2);
        $self->{server}->close();
        $self->{server} = undef;
    };
    while (defined($self->{server}))
    {
        my $client   = $self->{server}->accept();
        my $cli_host = $client->peerhost();
        my $cli_port = $client->peerport();
        $self->{log}->_4("Accepted connection from $cli_host:$cli_port");
        my $header;
        #receive the greeting header
        $client->recv($header, 2);
        #unpack the version and methods
        my ($version, $nmethods) = unpack("BB!", $header);
        #verify if the requested version is supported
        unless ($version == SOCKS_VERSION)
        {
            $client->close();
            $self->{log}->_4("$cli_host requested an unsupported version ($version)");
            next;
        }
        #verify the number of requested methods
        unless ($nmethods > 0)
        {
            $client->close();
            $self->{log}->_4("$cli_host requested invalid methods ($nmethods)");
            next;
        }
        #receive avaiable methods
        my @methods = map {my $m; $client->recv($m, 1); ord($m) } 1 .. $nmethods;
        #verify authentication request
        unless (grep /^2$/, @methods)
        {
            $client->close();
            $self->{log}->_4("$cli_host must authenticate first.");
            next;
        }
        $client->send(pack("BB!", SOCKS_VERSION, 2));
        $|=1;
        if ($self->authenticate_client($client))
        {
            my $data;
            $client->recv($data, 4);
            my ($version, $cmd, $foo, $addr_type) = unpack("BBBB!", $data);
            unless ($version == SOCKS_VERSION)
            {
                $client->close();
                $self->{log}->_4("$cli_host requested an unsupported version ($version)");
                next;
            }
            my $address;
            if ($addr_type == 1) #IPv4
            { 
                $client->recv($address, 4);
                $address = inet_ntoa($address);
            }
            elsif ($addr_type == 3) #Domain Name
            {
                my $len;
                $client->recv($len, 1);
                $len = ord($len);
                $client->recv($address, $len);
            }
            my $port;
            $client->recv($port, 2);
            ($port) = unpack("H!", $port);
            my $bind_addr;
            my $target;
            if ($cmd == 1) #CONNECT
            {
                $target = IO::Socket::INET->new(
                    PeerAddr => $address,
                    PeerPort => $port,
                    Proto    => "tcp"
                )
                || eval {
                    $self->{log}->_4("$cli_host Failed to connect to $address:$port");
                    err_replay($client, $addr_type, 5);
                    $client->shutdown(2);
                    $client->close()
                };
                $self->{log}->_4("$cli_host Connected to $address:$port");
                $bind_addr = $target->getsockname();
            }
            else
            {
                $client->shutdown(2);
                $client->close();
                $self->{log}->_4($client->peerhost() . " invalid command");
            }
            ($address, $port) = sockaddr_in($bind_addr);
            $client->send(pack("BBBBIH!", SOCKS_VERSION, 0, 0, $addr_type, $address, $port));
            if ($cmd == 1)
            {
                push @{$self->{client_threads}}, threads->create('handle_client', $self, $client, $target);
                next;
            }
            $client->shutdown(2);
            $client->close();
        }
    }
}

sub authenticate_client
{
    my ($self, $client) = @_;
    my $version;
    $client->recv($version, 1);
    unless ($version == 1)
    {
        $client->shutdown(2);
        $client->close();
        $self->{log}->_4($client->peerhost() . " invalid authentication version");
        return 0;
    }
    my ($usr_len, $pwd_len, $username, $password);
    $client->recv($usr_len, 1);
    $client->recv($username, ord($usr_len));
    $client->recv($pwd_len, 1);
    $client->recv($password, ord($pwd_len));
    $username = decode('utf-8', $username);
    $password = decode('utf-8', $password);
    if (($username eq $self->{socks_user}) and ($password eq $self->{socks_pass}))
    {
        $client->send(pack("BB!", $version, 0));
        $self->{log}->_4($client->peerhost() . " authenticated.");
    }
    else
    {
        $client->send(pack("BB!", $version, 0xFF));
        $client->shutdown(2);
        client->close();
        $self->{log}->_4($client->peerhost() . " invalid username and/or password");
        return 0;
    }
    1;
}
sub err_replay
{
    my ($client, $addr_type, $err_number) = @_;
    $client->send(pack("BBBBIH!", SOCKS_VERSION, $err_number, 0, $addr_type, 0, 0));
}

sub handle_client
{
    my ($self, $client, $target) = @_;
    $SIG{'KILL'} = sub {
        $target->shutdown(2);
        $client->shutdown(2);
        $target->close();
        $client->close();
        undef($target);
        undef($client);
    };
    my $select = IO::Select->new();
    $select->add($client, $target);
    while (defined($client))
    {
        my $data;
        my @ready = $select->can_read();
        for my $sock (@ready)
        {
            if ($sock == $client)
            {
                $client->recv($data, 4096);
                last unless ($target->send($data) > 0);
            }
            else
            {
                $target->recv($data, 4096);
                last unless ($client->send($data) > 0);
            }
        }
    }
}