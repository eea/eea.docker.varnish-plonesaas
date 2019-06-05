acl purge {
    "localhost";
    "127.0.0.1";
    "172.17.0.0/16"; # Docker network
    "10.42.0.0/16";  # Rancher network
    "10.62.0.0/16";  # Rancher network
}

sub vcl_recv {

    # Before anything else we need to fix gzip compression
    if (req.http.Accept-Encoding) {
        if (req.url ~ "\.(jpg|png|gif|gz|tgz|bz2|tbz|mp3|ogg)$") {
            # No point in compressing these
            unset req.http.Accept-Encoding;
        } else if (req.http.Accept-Encoding ~ "br") {
            set req.http.Accept-Encoding = "br";
        } else if (req.http.Accept-Encoding ~ "gzip") {
            set req.http.Accept-Encoding = "gzip";
        } else if (req.http.Accept-Encoding ~ "deflate") {
            set req.http.Accept-Encoding = "deflate";
        } else {
            # unknown algorithm
            unset req.http.Accept-Encoding;
        }
    }

    if (req.http.X-Forwarded-Proto == "https" ) {
        set req.http.X-Forwarded-Port = "443";
    } else {
        set req.http.X-Forwarded-Port = "80";
        set req.http.X-Forwarded-Proto = "http";
    }

    # cache authenticated requests by adding header
    set req.http.X-Username = "Anonymous";
    if (req.http.Cookie && req.http.Cookie ~ "__ac(|_(name|password|persistent))=")
    {
        set req.http.X-Username = regsub( req.http.Cookie, "^.*?__ac=([^;]*);*.*$", "\1" );

        # pick up a round-robin instance for authenticated users
        set req.backend_hint = cluster_plone.backend();

        # pass (no caching)
        unset req.http.If-Modified-Since;
        return(pass);
    }
    else
    {
        # login form always goes to the reserved instances
        if (req.url ~ "login_form$" || req.url ~ "login$")
        {
            set req.backend_hint = cluster_plone.backend();

            # pass (no caching)
            unset req.http.If-Modified-Since;
            return(pass);
        }
        else
        {
            # downloads go only to these backends
            if (req.url ~ "/(file|download)$" || req.url ~ "/(file|download)\?(.*)")
            {
                set req.backend_hint = cluster_plone.backend();
            }
            else
            {
                # pick up a random instance for anonymous users
                set req.backend_hint = cluster_plone.backend();
            }
        }
    }


    # Handle special requests
    if (req.method != "GET" && req.method != "HEAD") {

        # POST - Logins and edits
        if (req.method == "POST") {
            return(pass);
        }

        # PURGE - The CacheFu product can invalidate updated URLs
        if (req.method == "PURGE") {
            if (!client.ip ~ purge) {
                return (synth(405, "Not allowed."));
            }

            # replace normal purge with ban-lurker way - may not work
            # Cleanup double slashes: '//' -> '/' - refs #95891
            ban ("obj.http.x-url == " + regsub(req.url, "\/\/", "/"));
            return (synth(200, "Ban added. URL will be purged by lurker"));
        }

        return(pass);
    }

    ### always cache these items:

    # javascript
    if (req.method == "GET" && req.url ~ "\.(js)") {
        return(hash);
    }

    ## images
    if (req.method == "GET" && req.url ~ "\.(gif|jpg|jpeg|bmp|png|tiff|tif|ico|img|tga|wmf)$") {
        return(hash);
    }

    ## multimedia
    if (req.method == "GET" && req.url ~ "\.(svg|swf|ico|mp3|mp4|m4a|ogg|mov|avi|wmv)$") {
        return(hash);
    }

    ## xml
    if (req.method == "GET" && req.url ~ "\.(xml)$") {
        return(hash);
    }

    ## for some urls or request we can do a pass here (no caching)
    if (req.method == "GET" && (req.url ~ "aq_parent" || req.url ~ "manage$" || req.url ~ "manage_workspace$" || req.url ~ "manage_main$" || req.url ~ "@@rdf")) {
        return(pass);
    }

    ## lookup anything else
    return(hash);
}

sub vcl_pipe {
    # This is not necessary if we do not do any request rewriting
    set req.http.connection = "close";
}

sub vcl_backend_response {
    # needed for ban-lurker
    # Cleanup double slashes: '//' -> '/' - refs #95891
    set beresp.http.x-url = regsub(bereq.url, "\/\/", "/");

    # Varnish determined the object was not cacheable
    if (!(beresp.ttl > 0s)) {
        set beresp.http.X-Cacheable = "NO: Not Cacheable";
    }

    set beresp.http.X-Backend-Name = beresp.backend.name;
    set beresp.http.X-Backend-IP = beresp.backend.ip;

    set beresp.grace = 30m;

    # cache all XML and RDF objects for 1 day
    if (beresp.http.Content-Type ~ "(text\/xml|application\/xml|application\/atom\+xml|application\/rss\+xml|application\/rdf\+xml)") {
        set beresp.ttl = 1d;
        set beresp.http.X-Varnish-Caching-Rule-Id = "xml-rdf-files";
        set beresp.http.X-Varnish-Header-Set-Id = "cache-in-proxy-24-hours";
    }

    # Headers for webfonts and truetype fonts
    if (beresp.http.Content-Type ~ "(application\/vnd.ms-fontobject|font\/truetype|application\/font-woff|application\/x-font-woff)") {
        # fix for loading Font Awesome under IE11 on Win7, see #94853
        if (bereq.http.User-Agent ~ "Trident" || bereq.http.User-Agent ~ "Windows NT 6.1") {
            unset beresp.http.Vary;
        }
    }

    # intecept 5xx errors here. Better reliability than in Apache
    if ( beresp.status >= 500 && beresp.status <= 505) {
        return (abandon);
    }
}

sub vcl_deliver {
    # needed for ban-lurker, we remove it here
    unset resp.http.x-url;

    # add a note in the header regarding the backend
    set resp.http.X-Backend = req.backend_hint;

    # add more cache control params for authenticated users so browser does NOT cache, also do not cache ourselves
    if (resp.http.X-Backend ~ "auth") {
      set resp.http.Cache-Control = "max-age=0, no-cache, no-store, private, must-revalidate, post-check=0, pre-check=0";
      set resp.http.Pragma = "no-cache";
    }

    if (obj.hits > 0) {
        set resp.http.X-Cache = "HIT";
    } else {
        set resp.http.X-Cache = "MISS";
    }

    unset resp.http.error50x;
}

sub vcl_backend_error {
  if ( beresp.status >= 500 && beresp.status <= 505) {
    # synthetic(std.fileread("/etc/varnish/500msg.html"));
    synthetic({"
        <?xml version="1.0" encoding="utf-8"?>
        <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
        <html>
          <head>
            <title>Varnish cache server: "} + resp.status + " " + resp.reason + {" </title>
          </head>
          <body>
            <h1>Error "} + resp.status + " " + resp.reason + {"</h1>
            <p>"} + resp.reason + {"</p>
            <h3>Guru Meditation:</h3>
            <p>XID: "} + req.xid + {"</p>
            <hr>
            <p>Varnish cache server</p>
          </body>
        </html>
    "});
  }

  return (deliver);
}

sub vcl_synth {
    if (resp.status == 503 && resp.http.X-Backend ~ "auth" && req.method == "GET" && req.restarts < 2) {
      return (restart);
    }

    set resp.http.Content-Type = "text/html; charset=utf-8";

    if (req.http.X-Username ~ "Anonymous") {
        set req.http.X-Isanon = "Anonymous";
    }
    else {
        set req.http.X-Isanon = "Authenticated";
    }

    if ( resp.status >= 500 && resp.status <= 505) {
        # synthetic(std.fileread("/etc/varnish/500msg.html"));
        synthetic({"
        <?xml version="1.0" encoding="utf-8"?>
        <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
        <html>
          <head>
            <title>Varnish cache server: "} + resp.status + " " + resp.reason + {" </title>
          </head>
          <body>
            <h1>Error "} + resp.status + " " + resp.reason + {"</h1>
            <p>"} + resp.reason + {"</p>
            <h3>Guru Meditation:</h3>
            <p>XID: "} + req.xid + {"</p>
            <hr>
            <p>Varnish cache server</p>
          </body>
        </html>
    "});
    } else {
        synthetic({"<?xml version="1.0" encoding="utf-8"?>
        <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
        "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
        <html>
        <head>
        <title>"} + resp.status + " " + resp.http.response + {"</title>
        </head>
        <body>
        <h1>Error "} + resp.status + " " + resp.http.response + {"</h1>
        <p>"} + resp.http.response + {"</p>
        <h3>Guru Meditation:</h3>
        <p>XID: "} + req.xid + {"</p>
        <address>
        <a href="http://www.varnish-cache.org/">Varnish</a>
        </address>
        </body>
        </html>
        "});
    }

    return (deliver);
}
