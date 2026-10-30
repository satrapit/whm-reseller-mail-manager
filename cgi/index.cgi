#!/usr/local/cpanel/3rdparty/bin/perl
#WHMADDON:rsm:Reseller System Mail Manager:rsm.png
#ACLS:all
use strict;
use warnings;
use lib '/usr/local/cpanel/';
use Whostmgr::ACLS ();
use Cpanel::Template ();
use JSON::PP qw(encode_json decode_json);
use Digest::SHA qw(hmac_sha256_hex);
use IPC::Open3;
use Symbol qw(gensym);

# Run only behind authenticated WHM, as actual root. ACL "all" alone is not sufficient.
my $who = $ENV{REMOTE_USER} // '';
Whostmgr::ACLS::init_acls();
if ($who ne 'root' || !Whostmgr::ACLS::checkacl('all')) {
    print "Status: 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nAccess denied\n";
    exit;
}
my $state_dir='/var/lib/whm-reseller-mail-manager';
my $key_file="$state_dir/csrf.key";
# Never load a redirected, group-readable or non-root-owned CSRF signing key.
# Validate both the privileged state directory and the regular key file.
sub safe_root_path {
    my ($path, $type, $permissions) = @_;
    my @st=lstat($path);
    return 0 unless @st && $st[4] == 0 && ($st[2] & 07777) == $permissions;
    my $actual_type=$st[2] & 0170000;
    return $actual_type == ($type eq 'directory' ? 0040000 : 0100000);
}
if (!safe_root_path($state_dir,'directory',0700) ||
    !safe_root_path($key_file,'file',0600)) {
    print "Status: 503 Service Unavailable\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nPlugin security state unavailable\n";
    exit;
}
my $secret='';
if (open my $kf,'<',$key_file) { local $/; $secret=<$kf>; close $kf; }
if (length($secret)<48) {
    print "Status: 503 Service Unavailable\r\nContent-Type: text/plain\r\n\r\nPlugin not initialized\n";
    exit;
}
my $uri=$ENV{REQUEST_URI}//'';
my $session=($uri =~ m{/(cpsess\d{8,20})/} ? $1 : ($ENV{cp_security_token}//''));
$session =~ s{^/}{};
# Fail closed when the WHM security session is missing; do not bind CSRF to a blank token.
if ($session !~ /^cpsess\d{8,20}$/) {
    print "Status: 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nWHM security session required\n";
    exit;
}
my $client_ip=$ENV{REMOTE_ADDR}//'';
my $bucket=int(time()/3600);
sub csrf_at { return hmac_sha256_hex(join('|','root',$session,$client_ip,$_[0]), $secret); }
my $csrf=csrf_at($bucket);
sub constant_equal {
    my ($a,$b)=@_;
    return 0 unless defined($a) && defined($b) && length($a)==length($b);
    my $d=0; for (my $i=0;$i<length($a);$i++) { $d |= ord(substr($a,$i,1)) ^ ord(substr($b,$i,1)); }
    return $d==0;
}
sub decode_form {
    my ($raw)=@_; my %kv;
    for my $part (split /&/,$raw,64) {
        my ($k,$v)=split /=/,$part,2;
        for ($k,$v) { $_ //= ''; tr/+/ /; s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg; }
        return {} if $k =~ /[^a-z0-9_]/i || length($k)>35 || length($v)>350;
        return {} if exists $kv{$k}; # reject parameter pollution / duplicate action keys
        $kv{$k}=$v;
    }
    return \%kv;
}
my $method=$ENV{REQUEST_METHOD}//'GET';
my $params={};
if ($method eq 'POST') {
    my $len=$ENV{CONTENT_LENGTH}//0;
    if ($len !~ /^\d+$/ || $len > 8192 || ($ENV{CONTENT_TYPE}//'') !~ m{^application/x-www-form-urlencoded(?:;|$)}i) {
        print "Status: 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nInvalid form\n";exit;
    }
    my $raw='';
    while (length($raw) < $len) {
        my $n=read(STDIN,my $chunk,$len-length($raw));
        if (!defined($n) || $n == 0) {
            print "Status: 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nIncomplete request body\n";
            exit;
        }
        $raw.=$chunk;
    }
    $params=decode_form($raw);
    my $submitted=$params->{csrf}//'';
    if (!constant_equal($submitted,csrf_at($bucket)) && !constant_equal($submitted,csrf_at($bucket-1))) {
        print "Status: 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nCSRF check failed\n";exit;
    }
} elsif ($method eq 'GET') {
    $params=decode_form($ENV{QUERY_STRING}//'');
} else {
    print "Status: 405 Method Not Allowed\r\nAllow: GET, POST\r\nContent-Type: text/plain\r\n\r\nUnsupported method\n";
    exit;
}
sub core {
    my ($params)=@_;
    my $out=''; my $err=''; my $pid;
    eval {
        local $SIG{ALRM}=sub { die "Backend timeout\n" };
        alarm(35);
        my ($in,$stdout); my $stderr=gensym();
        $pid=open3($in,$stdout,$stderr,'/usr/bin/python3','/opt/whm-reseller-mail-manager/app/src/rsm.py');
        print $in encode_json($params);
        close $in;
        local $/;
        $out=<$stdout>//'';
        $err=<$stderr>//'';
        waitpid($pid,0);
        alarm(0);
    };
    if ($@ || length($out)>2_000_000 || !$out) {return {ok=>JSON::PP::false,error=>'Backend unavailable or timed out'};}
    my $result=eval { decode_json($out) };
    return $result if $result && ref $result eq 'HASH';
    return {ok=>JSON::PP::false,error=>'Invalid backend reply'};
}
my $tab=$params->{tab}//'dashboard';
$tab='dashboard' unless $tab =~ /^(dashboard|resellers|dns)$/;
my $flash='';my $dns;my $dns_type='';
if ($method eq 'POST') {
    my $action=$params->{action}//'';
    if ($action =~ /^(save_general|verify_general|rotate_challenge|save_reseller|verify|inspect|preview|audit_reseller|provision_reseller_dkim)$/) {
        my $resp=core({ %$params,action=>$action });
        if ($resp->{ok}) { $flash=$resp->{data}{message}//'Operation completed';
            if ($action eq 'inspect') {$dns=$resp->{data};$dns_type='inspect';$tab='dns';}
            if ($action eq 'preview') {$dns=$resp->{data};$dns_type='preview';$tab='dns';}
            if ($action eq 'audit_reseller') {$dns=$resp->{data};$dns_type='audit';$tab='resellers';}
            if ($action eq 'provision_reseller_dkim') {$dns=$resp->{data};$dns_type='provision';$tab='resellers';}
        } else { $flash='Error: '.($resp->{error}//'Unknown error'); }
    } else {$flash='Unsupported action';}
}
my $result=core({action=>'dashboard'});
my $data=$result->{ok} ? $result->{data} : {settings=>{},resellers=>[],events=>[],orphan_configs=>[]};
if (!$result->{ok}) {
    $flash='Error: '.($result->{error}//'Cannot load WHM data').($flash?' | '.$flash:'');
}
my $settings=$data->{settings}||{};
my $rows=$data->{resellers}||[];
# A single, mutually exclusive onboarding state for each reseller. Values from
# WHM inventory, not from guessed DNS deliverability or notification history.
my ($ready,$needs_dns,$paused,$unconfigured,$covered_accounts)=(0,0,0,0,0);
for my $entry (@$rows) {
    if (!$entry->{email}) { $unconfigured++; }
    elsif (!$entry->{verified}) { $needs_dns++; }
    elsif (!$entry->{enabled}) { $paused++; }
    else { $ready++; $covered_accounts+=($entry->{accounts}//0); }
}
my $model={
    tab           => $tab,
    csrf          => $csrf,
    flash         => $flash,
    settings      => $settings,
    default_challenge_name=> $data->{default_challenge_name}//'',
    default_challenge_value=> $data->{default_challenge_value}//'',
    enabled       => (($settings->{enabled}//'0') eq '1') ? 1 : 0,
    rows          => $rows,
    total         => scalar(@$rows),
    active        => scalar(grep { $_->{enabled} } @$rows),
    ready         => $ready,
    needs_dns     => $needs_dns,
    paused        => $paused,
    unconfigured  => $unconfigured,
    action_needed => $needs_dns+$paused+$unconfigured,
    covered_accounts => $covered_accounts,
    accounts_total=> $data->{accounts_total}//0,
    events        => $data->{events}||[],
    orphan_configs=> $data->{orphan_configs}||[],
    dns_output    => $dns_type eq 'inspect' ? JSON::PP->new->canonical->pretty->encode($dns) : '',
    dns_result    => $dns_type eq 'inspect' ? $dns : undef,
    preview_result=> $dns_type eq 'preview' ? $dns : undef,
    audit_result  => $dns_type eq 'audit' ? $dns : undef,
    provision_result=> $dns_type eq 'provision' ? $dns : undef,
    audit_target  => $dns && ($dns_type eq 'audit' || $dns_type eq 'provision') ? ($params->{reseller}//'') : '',
    audit_ip      => ($params->{action}//'') eq 'audit_reseller' ? ($params->{ip}//'') : '',
    form_email    => ($params->{action}//'') eq 'inspect' ? ($params->{email}//'') : '',
    form_ip       => ($params->{action}//'') eq 'inspect' ? ($params->{ip}//'') : '',
    form_selector => ($params->{action}//'') eq 'inspect' ? ($params->{selector}//'') : '',
    form_account  => ($params->{action}//'') eq 'preview' ? ($params->{account}//'') : '',
};

# The WHM master template renders the native header, navigation sidebar and footer.
# Do not add a standalone HTML document or a plugin CSP that blocks WHM assets.
print "Content-Type: text/html; charset=utf-8\r\n";
print "Cache-Control: no-store\r\n";
print "X-Content-Type-Options: nosniff\r\n";
print "Referrer-Policy: same-origin\r\n\r\n";
eval {
    Cpanel::Template::process_template('whostmgr', {
        template_file => 'rsm/index.tmpl',
        print         => 1,
        rsm           => $model,
    });
    1;
} or do {
    my $error=$@ || 'unknown Template Toolkit error';
    $error =~ s/[\r\n]+/ /g;
    warn "RSM WHM template render failure: $error\n";
};
