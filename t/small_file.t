# vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(1);

plan tests => repeat_each() * (blocks() * 3 + 2 * 1);

our $http_config = <<'_EOC_';
    slowfs_cache_path  /tmp/ngx_slowfs_cache keys_zone=test_cache:10m;
    slowfs_temp_path   /tmp/ngx_slowfs_temp 1 2;
_EOC_

our $config = <<'_EOC_';
    location /slowfs {
        alias               /etc;
        slowfs_cache        test_cache;
        slowfs_cache_key    $uri$is_args$args;
        slowfs_cache_valid  3m;
        add_header          X-Cache-Status $slowfs_cache_status;
    }

    location ~ /purge(/.*) {
        slowfs_cache_purge  test_cache $1$is_args$args;
    }
_EOC_

worker_connections(128);
no_shuffle();
run_tests();

no_diff();

__DATA__

=== TEST 1: get from cache
--- http_config eval: $::http_config
--- config eval: $::config
--- request
GET /slowfs/passwd
--- error_code: 200
--- response_headers
Content-Type: text/plain
X-Cache-Status: HIT
--- response_body_like: root
--- timeout: 10



=== TEST 2: purge from cache
--- http_config eval: $::http_config
--- config eval: $::config
--- request
DELETE /purge/slowfs/passwd
--- error_code: 200
--- response_headers
Content-Type: text/html
--- response_body_like: Successful purge
--- timeout: 10



=== TEST 3: purge from empty cache
--- http_config eval: $::http_config
--- config eval: $::config
--- request
DELETE /purge/slowfs/passwd
--- error_code: 404
--- response_headers
Content-Type: text/html
--- response_body_like: 404 Not Found
--- timeout: 10



=== TEST 4: get from cache (again)
--- http_config eval: $::http_config
--- config eval: $::config
--- request
GET /slowfs/passwd
--- error_code: 200
--- response_headers
Content-Type: text/plain
X-Cache-Status: HIT
--- response_body_like: root
--- timeout: 10
