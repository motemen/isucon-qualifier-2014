use strict;
use warnings;
use v5.14;
use DBIx::Sunny;

my $host = $ENV{ISU4_DB_HOST} || '127.0.0.1';
my $port = $ENV{ISU4_DB_PORT} || 3306;
my $username = $ENV{ISU4_DB_USER} || 'root';
my $password = $ENV{ISU4_DB_PASSWORD};
my $database = $ENV{ISU4_DB_NAME} || 'isu4_qualifier';

my $db = DBIx::Sunny->connect(
    "dbi:mysql:database=$database;host=$host;port=$port", $username, $password, {
        RaiseError => 1,
        PrintError => 0,
        AutoInactiveDestroy => 1,
        mysql_enable_utf8   => 1,
        mysql_auto_reconnect => 1,
    },
);

my $finished = {};
my $cnt = {};
my $logs = $db->select_all('SELECT * FROM login_log ORDER BY id DESC');

my $i = 0;
for my $log (@$logs) {
    if (++$i % 1000 == 0) {
        printf "%d/%d\n", $i, scalar @$logs;
    }

    my $user_id = $log->{user_id};
    if ($finished->{$user_id}) {
        next;
    }

    if ($log->{succeeded}) {
        $finished->{$user_id}++;

        $db->query(
            'UPDATE users SET recent_login_failures_cnt = ? WHERE id = ?',
            $cnt->{$user_id}, $user_id
        );
    } else {
        $cnt->{$user_id}++;
    }
}

foreach my $user_id (keys %$cnt) {
    next if $finished->{$user_id};

    $db->query(
        'UPDATE users SET recent_login_failures_cnt = ? WHERE id = ?',
        $cnt->{$user_id}, $user_id
    );
}
