exec carton exec start_server --path /var/lib/nginx/app.sock \
    -- plackup -s Starlet                                    \
    --max-reqs-per-child=50000 --min-reqs-per-child=5000     \
    --max-workers=8 \
    -E prod app.psgi
