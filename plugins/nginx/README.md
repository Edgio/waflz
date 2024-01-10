# waflz nginx module

### build

./configure --add-module=<path to nginx module>

### Sample nginx server block
```sh
server {
        listen        8080;
        server_name   localhost;

        
        
        waflz_ruleset_dir   /tmp/waf/ruleset/;
        waflz_conf_dir  /tmp/waf/conf/
        city_mmdb_path /tmp/maxmind_dbs/GeoIP2City.mmdb;
        asn_mmdb_path /tmp/maxmind_dbs/GeoIP2ISP.mmdb;

        access_log   logs/access_log  main;

        location / {
            scopes       testscopes.json;
            root /tmp/www/;
            index  index.html index.htm;
        }

    }
```