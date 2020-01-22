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

    set req.http.X-Username = "Anonymous";

    # Do not cache RestAPI authenticated requests
    if (req.http.Authorization || req.http.Authenticate) {
        set req.http.X-Username = "Authenticated (RestAPI)";
        set req.backend_hint = cluster_haproxy.backend();

        # pass (no caching)
        unset req.http.If-Modified-Since;
        return(pass);
    }

    # Do not cache authenticated requests
    if (req.http.Cookie && req.http.Cookie ~ "__ac__eionet(|_(name|password|persistent))=")
    {
        set req.http.X-Username = regsub( req.http.Cookie, "^.*?__ac__eionet=([^;]*);*.*$", "\1" );

        # pick up a round-robin instance for authenticated users
        set req.backend_hint = cluster_haproxy.backend();

        # pass (no caching)
        unset req.http.If-Modified-Since;
        return(pass);
    }

    # Do not cache login form
    if (req.url ~ "login_form$" || req.url ~ "login$")
    {
        set req.backend_hint = cluster_haproxy.backend();

        # pass (no caching)
        unset req.http.If-Modified-Since;
        return(pass);
    }

    # Pick up a random instance for anonymous users
    set req.backend_hint = cluster_haproxy.backend();

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

    # javascript and css
    if (req.method == "GET" && req.url ~ "\.(js|css)") {
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

#sub vcl_purge {
#    return (synth(200, "Purged"));
#}

#sub vcl_pass {
#    return (fetch);
#}

sub vcl_backend_error {
  if ( beresp.status >= 500 && beresp.status <= 505) {
    # synthetic(std.fileread("/etc/varnish/500msg.html"));
    synthetic({"
        <?xml version="1.0" encoding="utf-8"?>
        <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
        <html>
          <head>
            <title>Varnish cache server: "} + beresp.status + " " + beresp.reason + {" </title>
          </head>
          <body>
            <h1>Error "} + beresp.status + " " + beresp.reason + {"</h1>
            <p>"} + beresp.reason + {"</p>
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
        synthetic({"<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
            <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en-US" lang="en-US">
            <head>
            <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
            <style type="text/css">
            html,
            body {
              height: 100%;
              width: 100%;
              padding: 0;
              margin: 0;
              border: 0;
              overflow: auto;
              background-color: #006699;
              color: #fff;
              font-family: Arial,sans-serif;
            }
            .vertical-align {
              display: block;
              width: 400px;
              position: relative;
              top: 50%;
              *top: 25%;
              -webkit-transform: translateY(-50%);
              -ms-transform: translateY(-50%);
              transform: translateY(-50%);
              margin: 0 auto;
            }
            button,
            a.button,
            a.button:link,
            a.button:visited {
              -webkit-appearance: none;
              -webkit-border-radius: 3px;
              -moz-border-radius: 3px;
              -ms-border-radius: 3px;
              -o-border-radius: 3px;
              border-radius: 3px;
              -webkit-background-clip: padding;
              -moz-background-clip: padding;
              background-clip: padding-box;
              background: #dddddd repeat-x;
              background-image: -webkit-gradient(linear, 50% 0%, 50% 100%, color-stop(0%, #ffffff), color-stop(100%, #dddddd));
              background-image: -webkit-linear-gradient(#ffffff, #dddddd);
              background-image: -moz-linear-gradient(#ffffff, #dddddd);
              background-image: -o-linear-gradient(#ffffff, #dddddd);
              background-image: linear-gradient(#ffffff, #dddddd);
              border: 1px solid;
              border-color: #bbbbbb;
              cursor: pointer;
              color: #333333;
              display: inline-block;
              font: 15px/20px Arial, sans-serif;
              overflow: visible;
              margin: 0;
              padding: 3px 10px;
              text-decoration: none;
              vertical-align: top;
              width: auto;
              *padding-top: 2px;
              *padding-bottom: 0;
            }
            .btn-eea {
              background: #478ea5 repeat-x;
              background-image: -webkit-gradient(linear, 50% 0%, 50% 100%, color-stop(0%, #478ea5), color-stop(100%, #346f83));
              background-image: -webkit-linear-gradient(#478ea5, #346f83);
              background-image: -moz-linear-gradient(#478ea5, #346f83);
              background-image: -o-linear-gradient(#478ea5, #346f83);
              background-image: linear-gradient(#478ea5, #346f83);
              border: 1px solid;
              border-color: #265a6c;
              color: white;
            }
            button:hover,
            a.button:hover {
              background-image:none;
            }
            hr {
              opacity: 0.5;
              margin: 12px 0;
              border: 0!important;
              height: 1px;
              background: white;
            }
            a,
            a:link,
            a:visited {
              color: white;
            }
            .huge {
              font-size: 72px;
            }
            .clearfix:before,
            .clearfix:after {
                display:table;
                content:" ";
            }
            .clearfix:after{
                clear:both;
            }
            .pull-left {
                float: left;
            }
            .pull-right {
                float: right;
            }
            </style>
            </head>
            <body>
            <div class="vertical-align">
              <div style="text-align: center;">
                <h2 style="margin: 12px 0;">Our apologies, the website has encountered an error.</h2>
                <hr>
                <p style="font-style: italic;">We have been notified by the error and will look at it as soon as possible. You may want to visit the <a href="">EEA Systems Status</a> site to see latest status updates from EEA Systems.</p>
                <p style="font-size: 90%"><a href="http://www.eea.europa.eu/">European Environment Agency</a>, Kongens Nytorv 6, 1050 Copenhagen K, Denmark - Phone: +45 3336 7100</p>  <br>
                </p>
              </div>
            </div>
            <script type="text/javascript">
              document.getElementById("focus").focus();
            </script>
            <!-- Matomo -->
            <script type="text/javascript">
              var _paq = _paq || [];
              /* tracker methods like "setCustomDimension" should be called before "trackPageView" */
              _paq.push(["setDocumentTitle", document.domain + "/" + document.title]);
              _paq.push(["setCookieDomain", "*.eea.europa.eu"]);
              _paq.push(['trackPageView']);
              _paq.push(['enableLinkTracking']);
              _paq.push(['trackEvent', 'Errors', beresp.status, window.location.href, 1]);
              (function() {
                var u="https://matomo.eea.europa.eu/";
                _paq.push(['setTrackerUrl', u+'piwik.php']);
                _paq.push(['setSiteId', '2']);
                var d=document, g=d.createElement('script'), s=d.getElementsByTagName('script')[0];
                g.type='text/javascript'; g.async=true; g.defer=true; g.src=u+'piwik.js'; s.parentNode.insertBefore(g,s);
              })();
            </script>
            <noscript><p><img src="https://matomo.eea.europa.eu/piwik.php?idsite=3&amp;rec=1" style="border:0;" alt="" /></p></noscript>
            <!-- End Matomo Code -->
            </body></html>
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
        <h3>Sorry, an error occured. If this problem persists Contact EEA Web Team (web.helpdesk at eea.europa.eu)</h3>
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
