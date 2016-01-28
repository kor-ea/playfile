#!/usr/bin/perl -w
use IO::Socket::INET;
use Net::RTP;
use Time::HiRes qw/ usleep /; 
use Digest::MD5 'md5_hex';
use Data::Dumper;
use Config::Simple;
use strict;


# Get the command line parameters
my ($phone, $configfile) = @ARGV;
die "Usage: perl -w playfile.pl phonenumber configfile" unless (defined $phone && defined $configfile);

my %config;
Config::Simple->import_from($configfile, \%config) or die Config::Simple->error();
if (defined $config{'general.logfile'}){
	my $logfile = $config{'general.logfile'};
	open OUTPUT, '>', $logfile or die $!;
	STDOUT->fdopen( \*OUTPUT, 'w' ) or die $!;
}
my $debug = $config{'general.debug'};
#-------------------SIP varables-------------------------------------
my $remoteip = $config{'sip.proxyip'};
my $remoteport = $config{'sip.proxyport'};
my $user=$config{'sip.user'};
my $pass=$config{'sip.pass'};
my $domain=$config{'sip.domain'};
#--------------------RTP
my $DEFAULT_PORT = $config{'rtp.default_port'};	# Default RTP port
my $DEFAULT_TTL = $config{'rtp.default_ttl'};		# Default Time-to-live
my $PAYLOAD_TYPE = $config{'rtp.payload_type'};		# a-law
my $PAYLOAD_SIZE = $config{'rtp.payload_size'};		# 160 samples per packet
my $soundfile=$config{'general.soundfile'};
my $soxpath=$config{'general.soxpath'};
my $auth_sent=0; #сделать отсылку invite с авторизацией только один раз
#-------------------------------------------------------
#connecting to the peer
my $sock = new IO::Socket::INET (
                PeerAddr => $remoteip,
 		PeerPort => $remoteport,
                Proto => 'udp',
               );
die "Could not create socket: $!\n" unless $sock;

#getting local ip and port
my $localip = $sock->sockhost();
my $localport = $sock->sockport();

#setting Sip attributes
my $to="sip:$phone\@$domain";
#my $from="sip:$user\@$localip:$localport";
my $userdomain="$user\@$domain";
my $from=qq("$user"<sip:$userdomain>);
my $uri="sip:$userdomain:$remoteport";
my $branch="z9hG4bk" . time() . "-playfile";
my $callid = time().$domain;
my $cseq_num = 1;
my $method="REGISTER";


#Constructing SIP-packet
my %request;
$request{'Via'}="SIP/2.0/UDP $localip:$localport;branch=$branch;rport";
$request{'Max-Forwards'}="70";
$request{'Contact'}="<sip:$userdomain>";
$request{'To'}="$from";
$request{'From'}=qq($from;tag=as234dfasf);
$request{'Call-ID'}=$callid;
$request{'Expires'}="120";
$request{'Allow'}="INVITE, ACK, CANCEL, OPTIONS, BYE, REGISTER, SUBSCRIBE, NOTIFY,REFER, INFO, MESSAGE";
$request{'Supported'}="replaces";
$request{'User-Agent'}="playfile";
$request{'Content-Type'}="application/sdp";
$request{'CSeq'}=$cseq_num." ".$method;
my $time=time();
my $sdp = qq(v=0\r
o=PlayFile $time $time IN IP4 $localip\r
s=PlayFile Audio Call\r
c=IN IP4 $localip\r
t=0 0\r
m=audio 40004 RTP/AVP 8 0 3 101\r
a=rtpmap:8 PCMA/8000\r
a=rtpmap:0 PCMU/8000\r
a=rtpmap:3 GSM/8000\r
a=rtpmap:101 telephone-event/8000\r
a=fmtp:101 0-15\r
a=ptime:20\r
a=sendrecv\r\n);
$request{'Content-length'}=0;#length($sdp);

my $response_str;
my %response;

SendPacket($method);
                          
#Loop
while (1) {
	#getting response
	sleep 1;
	$sock->recv($response_str, 5000);
	print ".......".(split /\n/,$response_str)[0]."\n";
	if ($debug){ print "\n$response_str\n"}

	if ($response_str =~ /SIP\/2\.0 407/){ 		#Proxy-Authorization required
		if ($method eq "INVITE"){
			#ACK
			$request{'CSeq'}=++$cseq_num." ACK";
			$request{'Content-length'}="0";
			delete $request{'Proxy-Authorization'};

			SendPacket("ACK");

			if ($auth_sent){next;} #if already sent AUTH dont send again
		}
		#incrementing CSeq
		$request{'CSeq'}=++$cseq_num." ".$method;
       		$request{'Content-length'}=length($sdp);

		ParseResponse();

		Auth('Proxy-Authenticate');

		SendPacket($method, $sdp);
		if ($method eq "INVITE"){$auth_sent=1}
	}
	elsif ($response_str =~ /SIP\/2\.0 200/ && $method eq "REGISTER"){ #Registered
		$method = "INVITE";
		$uri = "$to:$remoteport";
		delete $request{'Proxy-Authorization'};

		#incrementing CSeq
		$request{'CSeq'}=++$cseq_num." ".$method;
		$request{'To'}="<$to>";
		$request{'Content-length'}=length($sdp);

		SendPacket($method,$sdp);
	}
	elsif ($response_str =~ /SIP\/2\.0 401/ ){ #Unauthorized
		if($auth_sent && $method eq 'INVITE'){next;}
		ParseResponse();

		#incrementing CSeq
		$request{'CSeq'}=++$cseq_num." ".$method;

		Auth('WWW-Authenticate'); #create auth field

		SendPacket($method,$sdp);		
       		if ($method eq "INVITE"){$auth_sent=1}
	}
	elsif (($response_str =~ /SIP\/2\.0 200/ ) && $method eq "INVITE"){
		print "\nCALL ASNWERED!\n";
		#----------------RTP----------------------
		# parsing response into hash
		SendRTP();
		sleep 2;
		SendPacket("BYE");
		close $sock;
		exit 1;
	}
	elsif ($response_str =~ /OPTIONS.+SIP/ ){ 
		ParseResponse();
		my ($optline) = ($response_str =~ /(OPTIONS.+SIP\/2\.0)/);
		print $optline."\n";
		delete $response{$optline};
		#incrementing CSeq
		#my ($cseq_opt) = ($response{'CSeq'} =~ /(\d+)/);		
		#$response{'CSeq'}=++$cseq_opt." OPTIONS";

		SendOK();		

	}

	
	elsif ($response_str =~ /SIP\/2\.0 48/){
		print "\nBusy or not available, exit 0\n";
		close $sock;
		exit 0;
	}

	elsif ($response_str =~ /SIP\/2\.0 60/){
		print "\nDeclined, exit 0\n";
		close $sock;
		exit 0;
	}

	elsif ($response_str =~ /SIP\/2\.0 403/){
		print "\nForbidden, exit 0\n";
		close $sock;
		exit 0;
	}
}

sub SendPacket{
	my $localmethod = $_[0];
	my $localsdp = "";
	if ($_[1]){$localsdp = "\r\n\r\n".$_[1]}

	#Making string from hash
	my $packet_str = join("\r\n", map { "$_: $request{$_}" } keys %request);
	
	#adding method 
	$packet_str = "$localmethod $uri SIP/2.0\r\n".$packet_str.$localsdp."\r\n\r\n";

	print "$localmethod $uri SIP/2.0\n";
	if ($debug) {print $packet_str."\n"}

	#sending packet
	print $sock $packet_str;
}
sub SendOK{
	#Making string from hash
	my $packet_str = join("\r\n", map { "$_: $response{$_}" } keys %response);
	
	#adding method 
	$packet_str = "SIP/2.0 200 OK\r\n".$packet_str."\r\n\r\n";

	print "SIP/2.0 200 OK\n";
	if ($debug) {print $packet_str."\n"}

	#sending packet
	print $sock $packet_str;
}


sub Auth{
	#getting realm and nonce
	my $authreq = $_[0];
	my $authresp = "Proxy-Authorization";
	if ($authreq eq 'WWW-Authenticate'){
		$authresp = "Authorization";
	}
	my %auth;
	my $key;
	my $val="";
	for (split /[\,\s*]/, $response{$authreq}) {
	 	($key, $val) = split /=/;
		next unless $key;
		next unless $val;
		$val =~ s/\"//g;
		$auth{$key} = $val;
	}
	my $realm = $auth{'realm'};
	my $nonce = $auth{'nonce'};
	my $opaque = $auth{'opaque'};
	my $qop = $auth{'qop'};

	#constructing auth_response
	my $a1_hex = md5_hex(join(':',$user,$realm,$pass));
	my $a2_hex = md5_hex(join(':',$method,$uri));

	#adding Authorization field
	if ($qop){
		my $cnonce = time()."asf3";
		my $auth_response = md5_hex( join( ':',	$a1_hex,$nonce,"00000001",$cnonce,$qop,$a2_hex));
		$request{$authresp}=qq(Digest username="$user",realm="$realm",nonce="$nonce",uri="$uri",qop="$qop",nc="00000001",cnonce="$cnonce",response="$auth_response",opaque="$opaque",algorithm=MD5);
	}else{
        	my $auth_response = md5_hex( join( ':',	$a1_hex,$nonce,$a2_hex));
		$request{$authresp}=qq(Digest username="$user",realm="$realm",nonce="$nonce",uri="$uri",response="$auth_response",algorithm=MD5);
	}


}

sub ParseResponse{
	%response = ();
	for (split /\r\n/, $response_str) {
	    my ($key, $val) = split /:\s/;
	    next unless $key;
	    $response{$key} = $val;
	}
#	if($debug){print "Response hash:\n".Dumper(\%response)}
}

sub SendRTP{
		my %sdphash;
		for (split /\r\n/, $response_str) {
		    my ($key, $val) = split /=/;
		    next unless $key;
		    $sdphash{$key} = $val;
		}
		#getting rtp port and host from sdp
		my ($remotertphost) = ($sdphash{'c'} =~ /(\d+\.\d+\.\d+\.\d+)/);
		my ($remotertpport) = ($sdphash{'m'} =~ /(\d+)/);
		print "RTP: $remotertphost $remotertpport\n";
		#openning RTP connection
		my $rtp = new Net::RTP(
			PeerPort=>$remotertpport,
			PeerAddr=>$remotertphost,
		) || die "Failed to create RTP socket: $!";

		# set the TTL
		if ($rtp->superclass() =~ /Multicast/) {
			$rtp->mcast_ttl( $DEFAULT_TTL );
		}

		# creating RTP packet
		my $packet = new Net::RTP::Packet();
		$packet->payload_type( $PAYLOAD_TYPE );
		# openning the input file (via sox)
		open(PCMU, "$soxpath $soundfile -t raw -e a-law -c 1 -r 8000 - |") 
		or die "Failed to open input file: $!";
		my $data;
		print "\r\nSending $soundfile\.";
		while( my $read = read( PCMU, $data, $PAYLOAD_SIZE ) ) {
	                #setting payload, and incrementing sequence number and timestamp
			$packet->payload($data);
			$packet->seq_num_increment();
			$packet->timestamp_increment( $PAYLOAD_SIZE );
			#sending packet
			my $sent = $rtp->send( $packet );
			print "\.";
			usleep( 1000000 * $PAYLOAD_SIZE / 8000 );
		}
		print "Done!\n";
		close( PCMU );	
}