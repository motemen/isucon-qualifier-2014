use strict;
use warnings;
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

my $users = $db->select_all('SELECT id FROM users');

for my $user (@$users) {
    my $log = $db->select_row(
        'SELECT COUNT(1) AS failures FROM login_log WHERE user_id = ? AND id > IFNULL((select id from login_log where user_id = ? AND succeeded = 1 ORDER BY id DESC LIMIT 1), 0)',
        $user->{'id'}, $user->{'id'});

    my $cnt = $log->{failures};

    $db->query(
        'UPDATE users SET recent_login_failures_cnt = ? WHERE id = ?',
        $cnt, $user->{id}
    );
}
