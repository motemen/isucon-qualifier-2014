package Isu4Qualifier::Web;

use strict;
use warnings;
use utf8;
use Kossy;
use DBIx::Sunny;
use Digest::SHA qw/ sha256_hex /;
use Data::Dumper;

sub config {
  my ($self) = @_;
  $self->{_config} ||= {
    user_lock_threshold => $ENV{'ISU4_USER_LOCK_THRESHOLD'} || 3,
    ip_ban_threshold => $ENV{'ISU4_IP_BAN_THRESHOLD'} || 10
  };
};

sub db {
  my ($self) = @_;
  my $host = $ENV{ISU4_DB_HOST} || '127.0.0.1';
  my $port = $ENV{ISU4_DB_PORT} || 3306;
  my $username = $ENV{ISU4_DB_USER} || 'root';
  my $password = $ENV{ISU4_DB_PASSWORD};
  my $database = $ENV{ISU4_DB_NAME} || 'isu4_qualifier';

  $self->{_db} ||= do {
    DBIx::Sunny->connect(
      "dbi:mysql:database=$database;host=$host;port=$port", $username, $password, {
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
  my $row = $self->db->select_row(
    'SELECT ip, cnt FROM ip_login_failure WHERE ip = ?', $ip
  );
  $row ||= {};

  $self->config->{ip_ban_threshold} <= ($row->{cnt} || 0);
};

sub attempt_login {
  my ($self, $login, $password, $ip) = @_;
  my $user = $self->db->select_row('SELECT * FROM users WHERE login = ?', $login);

  if ($self->ip_banned($ip)) {
    $self->login_log(0, $login, $ip, $user ? $user->{id} : undef);
    return undef, 'banned';
  }

  if ($self->user_locked($user)) {
    $self->login_log(0, $login, $ip, $user->{id});
    return undef, 'locked';
  }

  if ($user && calculate_password_hash($password, $user->{salt}) eq $user->{password_hash}) {
    $self->login_log(1, $login, $ip, $user->{id});
    return $user, undef;
  }
  elsif ($user) {
    $self->login_log(0, $login, $ip, $user->{id});
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
  my ($self, $user_id) = @_;

  my $logs = $self->db->select_all(
   'SELECT * FROM login_log WHERE succeeded = 1 AND user_id = ? ORDER BY id DESC LIMIT 2',
   $user_id);

  @$logs[-1];
};

sub banned_ips {
  my ($self) = @_;
  my $threshold = $self->config->{ip_ban_threshold};

  my $ip_failures = $self->db->select_all('SELECT ip,cnt FROM ip_login_failure');
  return [
      map { $_->{ip} } grep { $_->{cnt} >= $threshold } @$ip_failures
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

sub login_log {
  my ($self, $succeeded, $login, $ip, $user_id) = @_;
  my $txn = $self->db->txn_scope;
  $self->db->query(
    'INSERT INTO login_log (`created_at`, `user_id`, `login`, `ip`, `succeeded`) VALUES (NOW(),?,?,?,?)',
    $user_id, $login, $ip, ($succeeded ? 1 : 0)
  );
  if ($succeeded) {
    $self->db->query(
      'UPDATE ip_login_failure SET cnt = 0 WHERE ip = ?',
      $ip
    );
    $self->db->query(
      'UPDATE users SET recent_login_failures_cnt = 0 WHERE id = ?',
      $user_id
    );
  } else {
    $self->db->query(
      'INSERT INTO ip_login_failure (`ip`, `cnt`) VALUES (?,1) ON DUPLICATE KEY UPDATE `cnt` = `cnt` + 1',
      $ip
    );
    $self->db->query(
      'UPDATE users SET recent_login_failures_cnt = recent_login_failures_cnt + 1 WHERE id = ?',
      $user_id
    );
  }
  $txn->commit;
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
    $c->render('mypage.tx', { last_login => $self->last_login($user_id) });
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
