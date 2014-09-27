use FindBin;
use lib "$FindBin::Bin/extlib/lib/perl5";
use lib "$FindBin::Bin/lib";
use File::Basename;
use Plack::Builder;
use Isu4Qualifier::Web;
use Plack::Session::State::Cookie;
use Plack::Session::Store::File;
use Data::MessagePack;
use Cache::Memcached::Fast;
use Plack::Session::Store::Cache;

my $root_dir = File::Basename::dirname(__FILE__);
my $session_dir = "/tmp/isu4_session_plack";
mkdir $session_dir;

my $mp = Data::MessagePack->new;

my $app = Isu4Qualifier::Web->psgi($root_dir);
builder {
# enable sub {
#   my $app = shift;
#   sub {
#     my $env = shift;
#     DB::enable_profile();
#     my $res = $app->($env);
#     DB::disable_profile();
#     return $res;
#   };
# };
  enable 'ReverseProxy';
  enable 'Static',
    path => qr!^/(?:stylesheets|images)/!,
    root => $root_dir . '/public';
  enable 'Session',
    state => Plack::Session::State::Cookie->new(
      httponly    => 1,
      session_key => "isu4_session",
    ),
    store => Plack::Session::Store::Cache->new(
      cache => do {
        Cache::Memcached::Fast->new({
          servers => [ { address => 'localhost:11211' } ],
          serialize_methods => [
            sub { $mp->pack($_[0]) },
            sub { $mp->unpack($_[0]) },
          ],
        })
      },
    ),
    ;
  $app;
};
