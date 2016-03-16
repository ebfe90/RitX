#!/usr/bin/env perl

# RitX - Reverse IP Tool v1.7

print "\n\t+-----------------------------+\n";
print "\t|           RitX 1.7          |\n";
print "\t+-----------------------------+\n\n\n";

use LWP::Simple;
use Socket;
use Getopt::Long;


# check missing modules...
my @Modules = ("threads","LWP::ConnCache","HTTP::Cookies");

foreach my $module (@Modules)
{
	my $can = eval "use $module;1;";
    if ($can && $module =~ /threads/)
	{
		# Do processing using threads
		$thread_support = 1;
    }
	elsif(!$can && $module =~ /threads/)
	{
		# Do it without using threads
		$thread_support = 0;
    }
	# The module isn't there
	if ($@ =~ /Can't locate/) {
		die "\n[!!] it seems that some modules are missing...:\n".$@."\n";
	}
}

my $b = $0;
$b =~ s/.*\///;
sub usage {
    print <<HELP;
Usage: perl $b [OPTIONS]
Options:
   -t, --target            Server hostname or IP
   -c, --check             Check extracted domains that are in the same IP address to eleminate cached/old records
   -b, --bing              Save Bing search results to a file
       --bing-api          Bing API key (http://www.bing.com/developers/)
       --vd-api            ViewDNS API key (http://ViewDNS.info/api/)
       --list              List current supported Reverse Ip Lookup websites
       --max               maximum number of pages to fetch (default:10)              
       --print             Print results
       --timeout=SECONDS   Seconds to wait before timeout connection (default 30)
       --user-agent        Specify User-Agent value to send in HTTP requests
       --proxy             To use a Proxy
       --proxy-auth        Proxy authentication information (user:password).
   -o, --output=FILE       Save results to a file (default IP.txt)
   -h, --help              This shity message
   -v, --verbose           Print more informations

   Threads:
   --threads=THREADS       Maximum number of concurrent IP checks (default 1) require --check

HELP
    exit;
}

my %SERV = (
	Myipneighbors =>{
		SITE	=>	"My-ip-neighbors.com",
		URL		=>	"http://www.my-ip-neighbors.com/?domain=%s",
		REGEX	=>	'<td class="action"\starget="\_blank"><a\shref="http\:\/\/whois\.domaintools\.com\/(.*?)"\starget="\_blank"\sclass="external">Whois<\/a><\/td>',
	},
	Hackertarget =>{
		SITE	=>	"Api.hackertarget.com",
		URL		=>	"http://api.hackertarget.com/reverseiplookup/?q=%s",
		REGEX	=>	'([^\n]+)',
	},
	
	Yougetsignal =>{
		SITE	=>	"Yougetsignal.com",
		DATA	=>	'remoteAddress',
		URL		=>	"http://www.yougetsignal.com/tools/web-sites-on-web-server/php/get-web-sites-on-web-server-json-data.php",
		SP		=>	'Yougetsignal()',
	},
	Pagesinventory =>{
		SITE	=>	"Pagesinventory.com",
		URL		=>	"http://www.pagesinventory.com/ip/%s-%d.html",
		SP		=>	'Pagesinventory()',
	},
	Myiptest =>{
		SITE	=>	"Myiptest.com",
		URL		=>	"http://www.myiptest.com/staticpages/index.php/Reverse-IP/%s",
		REGEX	=>	"<td style='width:200px;'><a href='http:\/\/www\.myiptest\.com\/staticpages\/index\.php\/Reverse-IP\/.*?'>(.*?)<\/a><\/td>",
	},
	WebHosting =>{
		SITE	=>	"Whois.WebHosting.info",
		URL		=>	"http://whois.webhosting.info/%s?pi=%d&ob=SLD&oo=DESC",
		SP		=>	'Whoiswebhosting()',
	},
	Domainsbyip =>{
		SITE	=>	'Domainsbyip.com',
		URL		=>	'http://domainsbyip.com/%s/', 
		REGEX	=>	'<li class="site.*?"><a href="http\:\/\/domainsbyip.com\/domaintoip\/(.*?)/">.*?<\/a>',
	},
	Ipadress =>{
		SITE	=>	"Ip-adress.com",
		URL		=>	"http://www.ip-adress.com/reverse_ip/%s",
		REGEX	=>	'<td style\=\"font\-size\:8pt\">.\n\[<a href="\/whois\/(.*?)">Whois<\/a>\]',
	},
	Bing =>{
		SITE	=>	"Bing.com",
		URL		=>	'https://api.datamarket.azure.com/Data.ashx/Bing/Search/v1/Web?Query=\'ip:%s\'&$top=50&$format=json&$skip=%d',
		SP		=>	'BingAPI()',
	},
	ewhois =>{
		SITE	=>	"Ewhois.com",
		URL		=>	"http://www.ewhois.com/",
		SP		=>	'eWhois()',
	},
	Sameip =>{
		SITE	=>	"Sameip.org",
		URL		=>	"http://sameip.org/ip/%s/",
		REGEX	=>	'<a href="http:\/\/.*?" rel=\'nofollow\' title="visit .*?" target="_blank">(.*?)<\/a>',
	},
	Robtex =>{
		SITE	=>	"Robtex.com",
		URL		=>	"http://www.robtex.com/ajax/dns/%s.html",
		REGEX	=>	"<span id=\"dns.*?\"><a href=\"\/\/dns\.robtex\.com\/(.*?)\.html\"  >",
	},
	Webmax =>{
		SITE	=>	"Tools.web-max.ca",
		URL		=>	"http://ip2web.web-max.ca/?byip=1&ip=%s",
		REGEX	=>	'<a href="http:\/\/.*?" target="_blank">(.*?)<\/a>',
	},
	DNStrails =>{
		SITE	=>	"DNStrails.com",
		URL		=>	"http://www.DNStrails.com/tools/lookup.htm?ip=%s&date=recent",
		REGEX	=>	'date=recent">(.*?)<\/a>\s\(as\sa\swebserver\)',
	},
	Viewdns =>{
		SITE	=>	"Viewdns.info",
		URL		=>	"http://pro.viewdns.info/reverseip/?host=%s&apikey=%s&output=json",
		SP		=>	"ViewDNS()"
	}
);

my @useragents = ('Mozilla/6.0 (Windows NT 6.2; WOW64; rv:16.0.1) Gecko/20121011 Firefox/16.0.1',
'Mozilla/5.0 (Windows NT 6.2; WOW64; rv:16.0.1) Gecko/20121011 Firefox/16.0.1',
'Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:16.0.1) Gecko/20121011 Firefox/16.0.1',
'Mozilla/5.0 (Windows NT 6.1; rv:15.0) Gecko/20120716 Firefox/15.0a2',
'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.1.16) Gecko/20120427 Firefox/15.0a1',
'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:15.0) Gecko/20120427 Firefox/15.0a1',
'Mozilla/5.0 (Windows NT 6.2; WOW64; rv:15.0) Gecko/20120910144328 Firefox/15.0.2',
'Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:15.0) Gecko/20100101 Firefox/15.0.1',
'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:14.0) Gecko/20120405 Firefox/14.0a1',
'Mozilla/5.0 (Windows NT 6.1; rv:14.0) Gecko/20120405 Firefox/14.0a1',
'Mozilla/5.0 (Windows NT 5.1; rv:14.0) Gecko/20120405 Firefox/14.0a1',
'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
'Mozilla/5.0 (X11; Linux i686) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
'Mozilla/5.0 (Windows NT 6.0; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
'Mozilla/5.0 (Windows NT 6.0) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_2) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535.11',
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_5_8) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.66 Safari/535',
'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Ubuntu/11.10 Chromium/17.0.963.65 Chrome/17.0.963.65 Safari/535.11',
'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Ubuntu/11.04 Chromium/17.0.963.65 Chrome/17.0.963.65 Safari/535.11',
'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Ubuntu/10.10 Chromium/17.0.963.65 Chrome/17.0.963.65 Safari/535.11',
'Mozilla/5.0 (X11; Linux i686) AppleWebKit/535.11 (KHTML, like Gecko) Ubuntu/11.10 Chromium/17.0.963.65 Chrome/17.0.963.65 Safari/535.11',
'Mozilla/5.0 (X11; Linux i686) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.65 Safari/535.11',
'Mozilla/5.0 (X11; FreeBSD amd64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.65 Safari/535.11',
'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.65 Safari/535.11',
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_2) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.65 Safari/535.11',
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_0) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.65 Safari/535.11',
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_4) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.65 Safari/535.11');

# Process options.
my ($target,$timeout,$threadz,$check,$print,$bing,$proxy,$proxy_auth,$useragent,$filename,$verbose,$max);

if ( @ARGV > 0 )
{
	GetOptions( 't|target=s'	=> \$target,
				'timeout=i'		=> \$timeout,
				'threads=i' 	=> \$threadz,
				'max=i'			=> \$max,
				'c|check'		=> \$check,
				'print'			=> \$print,
				'list'	 		=> \&list_serv,
				'bing-api=s'	=> \$bing_api,
				'vd-api=s'		=> \$vd_api,
				'b|bing'		=> \$bing,
				'proxy=s'		=> \$proxy,
				'proxy-auth=s'	=> \$proxy_auth,
				'user-agent'	=> \$useragent,
				'o|output=s'	=> \$filename,
				'v|verbose' 	=> \$verbose,
				'h|help'		=> \&usage) or exit;
}
else
{
	print "[*] Usage    : perl $b [OPTIONS]\n";
	print "    EXEMPLE  : perl $b -t www.target.com -o result.txt\n\n";
	print "[*] Try 'perl $b -h' for more options.\n";
	exit;
}


if($^O =~ /MSWin32|cygwin/ and ($threadz>10))
{
	print "\n[-] Sorry, maximum number of used threads is 10 for Windows to avoid some possible connection and performance issues\n\n";
	exit;
}

if ($target =~ /\d+.\d+.\d+.\d+/)
{
	# nice do nothing
}
elsif ($target =~ /([a-z][a-z0-9\-]+(\.|\-*\.))+[a-z]{2,6}$/)
{
	my $IP = getIP($target);
	if ($IP)
	{
		$target = $IP;
	}
	else
	{
		die "\n[!!] Unable to Resolve Host $target ! \n";
	}
}
else
{
	die "[-] Invalid Hostname or Ip address .\n";
}


my $DNSx = gethostbyaddr(inet_aton($target),AF_INET);
# Check if the target uses CloudFlare service
my $IPx = unpack("N",inet_aton($target));

#https://www.cloudflare.com/ips-v4
if(($IPx >= 3324641278 and $IPx <= 3324608512)
or ($IPx >= 3161612288 and $IPx <= 3161616382)
or ($IPx >= 3193827328 and $IPx <= 3193831422)
or ($IPx >= 1822605312 and $IPx <= 1822621694)
or ($IPx >= 2372222976 and $IPx <= 2372239358)
or ($IPx >= 1729546240 and $IPx <= 1729547262)
or ($IPx >= 2918526976 and $IPx <= 2918531070)
or ($IPx >= 3340468224 and $IPx <= 3340470270)
or ($IPx >= 3428692224 and $IPx <= 3428692478)
or ($IPx >= 3428708352 and $IPx <= 3428708606)
)
{
	print "[WARNING] The target uses CloudFlare's service!!\n\n";
	print "[!] do you wanna continue? [y/n]:";
	my $choice=<STDIN>;
	chop($choice);
	if($choice eq "n")
	{
		print "\n[*] You made the right choice!!\n\n";
		exit;
	}
	else
	{
		print  "[+] OK! as you like\n";
	}
}



# Global variables
$bingApiKey  = $bing_api || 'y+WsWbJTyl/93GXbvGXo7kXbB3nxrEz2kExRstXOI84=';#get your own code :p
$VERSION     = '1.6';
$TMPdir      = "tmp";
$useragent ||= $useragents[int(rand(scalar(@useragents)))]; #take a random user agent
$filename  ||= "$target.txt";
$timeout   ||= 30;
$max       ||= 10;
$SIG{INT}    = \&trapsig;

mkdir $TMPdir or die "[-] Cant create tmp directory!\n" if ! -d $TMPdir;

if(!$vd_api)
{
	delete $SERV{Viewdns};
}


my $ua = LWP::UserAgent->new(agent => $useragent);
$ua->timeout($timeout);
$ua->max_redirect(0);
$ua->conn_cache(LWP::ConnCache->new());
$ua->default_header('Referer' => "http://www.google.com/#q=a".int(rand(5)*rand(5)));#fake Referer


$|++;
if ($proxy)
{
	$proxy .= ":8080" if not $proxy =~ /:/;
	# connect to the proxy
	my $req = HTTP::Request->new(CONNECT => 'http://'.$proxy.'/' );
	if (defined $proxy_auth)
	{
		my ($user,$password)=split(":",$proxy_auth);
		$req->proxy_authorization_basic($user, $password);
	}
	my $res = $ua->request($req);
	# connection failed
	if ( not $res->is_success ){
		print "\n[-] failed to connect to the proxy... ignore it\n\n";
	}
	else
	{
		$ua->proxy(http => "http://$proxy/");
	}
}

print "\n[*] This process will take a little time so be patient...\n\n";
print "[*] Processing:\n";

### Functions

sub list_serv
{
	print "[*] List of available Reverse Ip Lookup services:\n\n";
	foreach $X (keys %SERV)
	{
		print "    -> $SERV{$X}->{SITE}\n";
	}
	print "\n";
	exit(0);
}

sub trapsig 
{
	print "\n\n[!!] Caught Interrupt (CTRL+C), Aborting\n";
	print "[!!] Saving results\n";
	save_report($filename);
	exit();
}
sub add
{
	my $x = lc($_[0]);
	($x =~ /[\<\"]|freecellphonetracer|reversephonedetective|americanhvacparts|freephonetracer|phone\.addresses|reversephone\.theyellowpages|\.in-addr\.arpa|^\d+(\.|-)\d+(\.|-)/) ? return:0;
	push(@{$SERV{$X}->{DUMP}},$x) if($verbose);
	$x =~ s/https?\:\/\/|\*\.|^www\.|\///;#
	++$SERV{$X}->{NB};
	push(@result,$x);
}
sub getIP
{
	my @ip = unpack('C4',(gethostbyname($_[0]))[4]) or return;
	return join('.',@ip);
}

sub getDNS
{
	return gethostbyaddr(inet_aton($_[0]),AF_INET);
}

sub Req
{
	my ($URL,$data)=@_;
	my $res;
	if(!$data)
	{
		$res = $ua->get($URL);
	}
	else
	{
		$res = $ua->post($URL, 
		{
			$data => $target,
		});
	}
	if(!$res->is_success)
	{
		print "[!] Error: ".$res->status_line."\n" if ($verbose);
	}
	return $res->content;
}

sub Yougetsignal
{
	my $resu = Req(sprintf($SERV{$X}->{URL},$target),$SERV{$X}->{DATA});
	while ($resu =~ m/\["(.*?)\"\, \"(1|)\"\]/g)
	{
		add($1);
	}
	if ($resu =~ m/Daily reverse IP check limit reached for/i)
	{
		$ERROR = "E1";
		$SERV{$X}->{NB} = $ERROR;
	}
}

sub ViewDNS
{
	my %hash = ();
	$repjson = Req(sprintf($SERV{$X}->{URL},$target,$vd_api));
	return if($repjson =~ /"domain_count" : "0"/);
	$repjson =~ s/\" \:/\" =>/g;
	$hashs = eval($repjson);
	foreach $s (@{$hashs->{response}{domains}})#yeah it could be done in another way but whatever
	{
		add($s->{name});
	}
	#$hashs->{response}{domains}[0]{name};
}


sub eWhois
{
	sub callback 
	{
		while($_[0] =~ m/"(.*?)","","","(UA\-[0-9]+\-[0-9]+|)",""/g)
		{
			add($1);
		}
	}
	my $url = "http://www.ewhois.com/export/ip-address/$target/";
	my $cookie_jar = HTTP::Cookies->new(autosave => 1);
	my $browser = LWP::UserAgent->new(agent => $useragent);
	$browser->cookie_jar($cookie_jar);
	my $resu = $browser->post("http://www.ewhois.com/login/",
	{
		'data[User][email]'=>'r12xr00tu@gmail.com',
		'data[User][password]'=>'RitX:::R1tX',#I've made it for you, so don't be an ass
		'data[User][remember_me]'=>'0'
	});
	if(!$resu->header('Location'))
	{
		print "[-] Sorry, we cant login to eWhois!\n";
		return;
	}
	$browser->get($url, ':content_cb' => \&callback );
}

sub Pagesinventory
{
	for (my $i=0;$i<=$max;$i++)
	{
		my $resu = Req(sprintf($SERV{$X}->{URL},$target,$i));

		if ($resu =~ m/<td>\.\.\.<\/td><\/table><div class="ntb-div">/g)
		{
			while ($resu =~ m/<td><a href="\/domain\/(.*?)\.html">/g)
			{			
				add($1);
			}
		}
		else
		{
			while ($resu =~ m/<td><a href="\/domain\/(.*?)\.html">/g)
			{
				add($1);
			}
			return;
		}
	}

}


sub Whoiswebhosting
{
	for (my $i=1;$i<=$max;$i++)
	{
		my $resu = Req(sprintf($SERV{$X}->{URL},$target,$i));
		if ($resu =~ m/<a href=\"\/.*?\?pi\=\d+\&ob\=SLD\&oo\=DESC\">Next\&nbsp\;\&gt\;\&gt\;<\/a>/g)
		{
			while ($resu =~ m/<td><a href="http:\/\/whois\.webhosting\.info\/.*?\.">(.*?)\.<\/a><\/td>/g)
			{
				add($1);
			}
		}
		else
		{
			while ($resu =~ m/<td><a href="http:\/\/whois\.webhosting\.info\/.*?\.">(.*?)\.<\/a><\/td>/g)
			{
				add($1);
			}
			if ($resu =~ m/The security key helps us prevent automated searches/i)
			{
				$ERROR = "E2";
				$SERV{$X}->{NB} = $ERROR;
				return;
			}
		}
	}
}


sub BingAPI
{
	my $b;
	use MIME::Base64 qw(encode_base64);

	for(my $offset=50;$offset<=($max*50);$offset+=50)
	{
		$resu = $ua->get(sprintf($SERV{$X}->{URL},$target,$offset),"Authorization" => 'Basic '.encode_base64($bingApiKey.":".$bingApiKey))->content;
		if ($resu =~ /\_\_next\"\:/)
		{
			while ($resu =~ /\,\"Url\"\:\"(.*?)\"\}/g)
			{
				$b = $1;
				push(@bingtrash,$b) if $bing;
				$b =~ s/\/.*// if index($b,"/");
				add($b);
			}
		}
		else
		{
			return;
		}
	}
}

sub add2tmp
{
	syswrite(TMP,gethostbyaddr(inet_aton($_[0]),AF_INET).":$_[0];");
}


sub checkDomain
{
	if(getDNS('www.'.$_[0]) eq $DNSx)
	{
		$NEWNB++;
		print "    Found : $_[0]\n";
		push(@resx,'www.'.$_[0]);
	}
	elsif(getDNS($_[0]) eq $DNSx)
	{
		print "    Found : $_[0]\n";
		$NEWNB++;
		push(@resx,$_[0]);
	}
	else
	{
		print "    Try : $_[0]\n";
	}
}

sub save_report
{
	my $filen = $_[0];
	if($donecheck && $threadz && $thread_support)
	{
		open (IN,"./$TMPdir/RitX-tmp.txt") or print ("\n[!] Can't create the file ($filen)\n");
		open (OUT,">$target-checked.txt") or print ("\n[!] Can't create the file ($filen)\n");
		syswrite(OUT,"# Genereted By RitX $VERSION\n# Those are the domains hosted on the same web server as ($target).\n# Results were tested and checked, so all old records were removed.\n\n");
		while(<IN>)
		{
			chomp;
			if (index($_,$DNSx))
			{
				$NEWNB++;
				s/$DNSx://; 
				syswrite(OUT,"$_\n");
			}
		}
		close(IN);
		close(OUT);
	}
	elsif($donecheck && !$threadz)
	{
		open (OUT,">$target-checked.txt") or print ("\n[!] Can't create the file ($filen)\n");
		syswrite(OUT,"# Genereted By RitX $VERSION\n# Those are the domains hosted on the same web server as ($target).\n# Results were tested and checked, so all old records were removed.\n# Total domains: $NEWNB\n\n");
		foreach (@resx)
		{
			syswrite(OUT,"$_\n") if ($_);
		}
		close(OUT);
	}
	open (F,">$filen") or print ("\n[!] Can't create the file ($filen)\n");
	syswrite(F,"# Genereted By RitX $VERSION\n# Those are the domains hosted on the same web server as ($target).\n# Total domains: $TOTALNB\n\n");
	foreach(@result)
	{
		syswrite(F,"$_\n") if ($_);
	}
	close(F);
}


#----------#
foreach $X (keys %SERV)
{
	my $match = $SERV{$X}->{REGEX};
	syswrite(STDOUT,"   -> $SERV{$X}->{SITE}\n");
	if(!$SERV{$X}->{SP})
	{
		$res=Req(sprintf($SERV{$X}->{URL},$target),$SERV{$X}->{DATA});
	}
	else
	{
		eval($SERV{$X}->{SP});
		next;
	}
	while($res =~ m/$match/g)
	{
		add($1);
	}
}

die "\n\n[-] Sorry, there is no data were retrieved!\n" if(scalar(@result)<1);

@result = sort(grep { ++$R12{$_} < 2 } @result);
undef(%R12);#useless

$TOTALNB = scalar(@result);

if($verbose)
{
	print "\n[+] DEBUG:\n\n";
	foreach $X (keys %SERV)
	{
		syswrite(STDOUT,"  + $SERV{$X}->{SITE}\n");
		foreach $DMP (@{$SERV{$X}->{DUMP}})
		{
			syswrite(STDOUT,"    - $DMP\n");
		}
	}
}

if($bing)
{
	if (scalar(@bingtrash)>0)
	{
		syswrite(STDOUT,"[+] saving Bing results...  ");
		my $file = "bingresults-$target.txt";
		open (BING,">$file") or print ("\n[!] Can't create bing results\n");
		print BING "# Genereted By RitX $VERSION\n# Those are all search results from Bing.com ($target).\n\n";
		foreach (@bingtrash)
		{
			print BING "$_\n";
		}
		close(BING);
		syswrite(STDOUT,"DONE\n");
		print "[+] bing results were saved into $file\n";
	}
	else
	{
		print "\n[-] no bing data!!\n\n"
	}
}

if ($check)
{
	my ($domain,$t);
	print "\n[x] Checking and removing old records from results\n";
	if ($threadz && $thread_support)
	{
		open(TMP,">./$TMPdir/RitX-tmp.txt");
		TMP->autoflush(1);
		foreach (@result)
		{
			threads->create(\&add2tmp,"www.$_")->detach;
			$t++;
			if($t==$threadz)
			{
				$s+=$t;
				print "\r passed $s";
				undef $t;
				sleep 1;
			}
		}
		close(TMP);
	}
	else
	{
		print "[-] Sorry your PERL installation doesn't support threads!\n\n" if !$thread_support;
		&checkDomain($_) foreach (@result);
	}
	$donecheck = 1;
	print "[+] Done\n";
}
&save_report($filename);


print "\n[x] Result of $target : \n\n";

print "                        +--------+\n                        |   NB   |\n+-----------------------+--------+\n";
foreach $X (keys %SERV)
{
	printf "| %-22s| %-7s|\n",$SERV{$X}->{SITE},(($SERV{$X}->{NB}) ? $SERV{$X}->{NB} : 0);
	print "+--------------------------------+\n";
}
printf "  %-14s| Total | %-7s|\n"," ",$TOTALNB;
print "                +----------------+\n";
print "[+] After removing old records : $NEWNB\n\n" if $donecheck;

if ($ERROR)
{
	print "+--Keys------------------------------------+\n";
	print "|E1: Daily reverse IP check limit reached. |\n";
	print "|E2: Some Security Measures (Captcha).     |\n";
	print "+------------------------------------------+\n";
}
if ($TOTALNB != 0 and $print)
{
	print "[+] Results:\n";
	my $v = 0;
	foreach my $RD (@result)
	{
		$v++;
		print "  $RD\n";
		if($v==20){<STDIN>;undef $v};
	}
}
print "[+] All domain name results has been saved to ($filename)\n";
print "[+] All checked domains are saved to ($target-checked.txt)\n" if ($NEWNB>0);