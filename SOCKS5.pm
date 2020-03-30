package SOCKS5;
use strict;
use threads;
use warnings;
use base 'Exporter';
use Logging::Simple; #install: cpan install Logging::Simple
use IO::Socket::INET;

our $VERSION = "0.1";

use constant SOCKS_VERSION => 5;

sub new
{
    my ($self, %args) = @_;
    my $data = {
        logger     => Logging::Simple->new(),
        log_file   => $args{log_file} || 0,  #file name (0 means STDOUT)
        socks_port => $args{socks_port} || 9666,
        socks_user => $args{socks_user} || 'user',
        socks_pass => $args{socks_pass} || 'pass',
        socks_host => $args{socks_host} || '0.0.0.0', #listen for this address
    };
    bless $data, $self;
}

sub start_proxy
{
    my ($self) = @_;
    $self->{logger}->file($self->{log_file});
    $self->{logger}->_0("Starting SOCKS5 server. Using port $self->{socks_port}");
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

}

sub thread_server
{
    my ($self) = @_;
    $SIG{'KILL'} = sub {$self->{server}->close(); $self->{server} = undef};
    while (defined($self->{server}))
    {
        my $client   = $self->{server}->accept();
        my $cli_host = $client->peerhost();
        my $cli_port = $client->peerport();
        $self->{log}->_0("Accepted connection from $cli_host:$cli_port");
        my $header;
        #receive the greeting header
        $client->recv($header, 2);
        #unpack the version and methods
        my ($version, $nmethods) = unpack("BB!", $header);
        #verify if the requested version is supported
        unless ($version == SOCKS_VERSION)
        {
            $client->close();
            $self->{log}->_0("$cli_host requested an unsupported version ($version)");
            next;
        }
        #verify the number of requested methods
        unless ($nmethods > 0)
        {
            $client->close();
            $self->{log}->_0("$cli_host requested invalid methods ($nmethods)");
            next;
        }
        #receive avaiable methods
        my @methods = map {my $m; $client->recv($m, 1); ord($m) } 1 .. $nmethods;
        #verify authentication request
        unless (grep /^2$/, @methods)
        {
            $client->close();
            $self->{log}->_0("$cli_host must authenticate first.");
            next;
        }
        $client->send(pack("BB!", SOCKS_VERSION, 2));
        $|=1;

        push @{$self->{client_threads}}, threads->create('handle_client', $self, $client);
    }
}

sub handle_client
{

}