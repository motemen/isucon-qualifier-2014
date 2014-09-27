package Isu4Qualifier::Web;

use strict;
use warnings;
use utf8;
use Kossy;
use DBIx::Sunny;
use Digest::SHA qw/ sha256_hex /;
use Data::Dumper;
use Cache::Memcached::Fast;
use Data::MessagePack;

my $mp = Data::MessagePack->new;

sub config {
  my ($self) = @_;
  $self->{_config} ||= {
    user_lock_threshold => $ENV{'ISU4_USER_LOCK_THRESHOLD'} || 3,
    ip_ban_threshold => $ENV{'ISU4_IP_BAN_THRESHOLD'} || 10
  };
};

sub memd {
  my $self = shift;
  $self->{_membed} ||= Cache::Memcached::Fast->new({
    servers => [ { address => 'localhost:11211' } ],
    serialize_methods => [
      sub { $mp->pack($_[0]) },
      sub { $mp->unpack($_[0]) },
    ],
  });
}

sub db {
  my ($self) = @_;
  my $host = $ENV{ISU4_DB_HOST} || '127.0.0.1';
  my $port = $ENV{ISU4_DB_PORT} || 3306;
  my $username = $ENV{ISU4_DB_USER} || 'root';
  my $password = $ENV{ISU4_DB_PASSWORD};
  my $database = $ENV{ISU4_DB_NAME} || 'isu4_qualifier';

  $self->{_db} ||= do {
    DBIx::Sunny->connect(
      "dbi:mysql:database=$database;mysql_socket=/var/lib/mysql/mysql.sock", $username, $password, {
        RaiseError => 1,
        PrintError => 0,
        AutoInactiveDestroy => 1,
        mysql_enable_utf8   => 1,
        mysql_auto_reconnect => 1,
      },
    );
  };
}

sub calculate_password_hash {
  my ($password, $salt) = @_;
  sha256_hex($password . ':' . $salt);
};

sub user_locked {
  my ($self, $user) = @_;

  $self->config->{user_lock_threshold} <= $user->{recent_login_failures_cnt};
};

sub ip_banned {
  my ($self, $ip) = @_;
  my $count = $self->memd->get(ipkey($ip)) || 0;
  $self->config->{ip_ban_threshold} <= $count;
};

sub attempt_login {
  my ($self, $login, $password, $ip) = @_;
  my $user = $self->db->select_row('SELECT * FROM users WHERE login = ?', $login);

  if ($self->ip_banned($ip)) {
    $self->login_log(0, $login, $ip, $user);
    return undef, 'banned';
  }

  if ($self->user_locked($user)) {
    $self->login_log(0, $login, $ip, $user);
    return undef, 'locked';
  }

  if ($user && calculate_password_hash($password, $user->{salt}) eq $user->{password_hash}) {
    $self->login_log(1, $login, $ip, $user);
    return $user, undef;
  }
  elsif ($user) {
    $self->login_log(0, $login, $ip, $user);
    return undef, 'wrong_password';
  }
  else {
    $self->login_log(0, $login, $ip);
    return undef, 'wrong_login';
  }
};

sub current_user {
  my ($self, $user_id) = @_;

  $self->db->select_row('SELECT * FROM users WHERE id = ?', $user_id);
};

sub last_login {
  my ($self, $user) = @_;

  +{
    login      => $user->{login},
    ip         => $user->{last_ip}           || $user->{current_ip},
    created_at => $user->{last_logged_in_at} || $user->{current_logged_in_at},
  };

};

sub banned_ips {
  my ($self) = @_;
  my $threshold = $self->config->{ip_ban_threshold};

  my $ip_failures = $self->db->select_all('SELECT ip FROM ip_login_failure');
  return [
      grep { $self->memd->get(ipkey($_)) >= $threshold } map { $_->{ip} } @$ip_failures
  ];
};

sub locked_users {
  my ($self) = @_;
  my @user_ids;
  my $threshold = $self->config->{user_lock_threshold};

  my $users = $self->db->select_all('SELECT login, recent_login_failures_cnt FROM users');
  return [
      map { $_->{login} } grep { $_->{recent_login_failures_cnt} >= $threshold } @$users
  ];
};

sub ipkey {
    my $ip = shift;
    return "failip:$ip";
}

sub login_log {
  my ($self, $succeeded, $login, $ip, $user) = @_;
  my $user_id = $user && $user->{id};

  my $txn = $self->db->txn_scope;

  $self->db->query(
    'INSERT IGNORE INTO ip_login_failure SET ip = ?', $ip
  );

  if ($succeeded) {
    $self->memd->set(ipkey($ip), 0);
    $self->db->query(
      'UPDATE users SET
        recent_login_failures_cnt = 0,
        last_logged_in_at    = current_logged_in_at,
        last_ip              = current_ip,
        current_logged_in_at = NOW(),
        current_ip           = ?
      WHERE id = ?',
      $ip, $user_id
    );
    $txn->commit;
  } else {
    $self->db->query(
      'UPDATE users SET recent_login_failures_cnt = recent_login_failures_cnt + 1 WHERE id = ?',
      $user_id
    ) if defined $user_id;
    $txn->commit;
    $self->memd->add(ipkey($ip), 0);
    $self->memd->incr(ipkey($ip), 1);
  }
};

sub set_flash {
  my ($self, $c, $msg) = @_;
  $c->req->env->{'psgix.session'}->{flash} = $msg;
};

sub pop_flash {
  my ($self, $c, $msg) = @_;
  my $flash = $c->req->env->{'psgix.session'}->{flash};
  delete $c->req->env->{'psgix.session'}->{flash};
  $flash;
};

filter 'session' => sub {
  my ($app) = @_;
  sub {
    my ($self, $c) = @_;
    my $sid = $c->req->env->{'psgix.session.options'}->{id};
    $c->stash->{session_id} = $sid;
    $c->stash->{session}    = $c->req->env->{'psgix.session'};
    $app->($self, $c);
  };
};

get '/' => [qw(session)] => sub {
  my ($self, $c) = @_;

  $c->render('index.tx', { flash => $self->pop_flash($c) });
};

post '/login' => sub {
  my ($self, $c) = @_;
  my $msg;

  my ($user, $err) = $self->attempt_login(
    $c->req->param('login'),
    $c->req->param('password'),
    $c->req->address
  );

  if ($user && $user->{id}) {
    $c->req->env->{'psgix.session'}->{user_id} = $user->{id};
    $c->redirect('/mypage');
  }
  else {
    if ($err eq 'locked') {
      $self->set_flash($c, 'This account is locked.');
    }
    elsif ($err eq 'banned') {
      $self->set_flash($c, "You're banned.");
    }
    else {
      $self->set_flash($c, 'Wrong username or password');
    }
    $c->redirect('/');
  }
};

get '/mypage' => [qw(session)] => sub {
  my ($self, $c) = @_;
  my $user_id = $c->req->env->{'psgix.session'}->{user_id};
  my $user = $self->current_user($user_id);
  my $msg;

  if ($user) {
    $c->render('mypage.tx', { last_login => $self->last_login($user) });
  }
  else {
    $self->set_flash($c, "You must be logged in");
    $c->redirect('/');
  }
};

get '/report' => sub {
  my ($self, $c) = @_;
  $c->render_json({
    banned_ips => $self->banned_ips,
    locked_users => $self->locked_users,
  });
};

1;
