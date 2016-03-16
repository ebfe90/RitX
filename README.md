# RitX

Project was on Google Code : *http://code.google.com/p/ritx*


Reverse IP Lookup Tool that allows you to use an IP address to identify all websites hosted on a server.

RitX is a Reverse IP Lookup Tool that will allows you to use an IP address or domain name to identify all currently domains hosted on a server using multiple services and various techniques

RitX is a Perl script which uses multiple web services that provide this feature.

This is the list of services that RitX support: * Ewhois.com * Pagesinventory.com * Viewdns.info * Yougetsignal.com * Myiptest.com * Ip-adress.com * DNStrails.com * My-ip-neighbors.com * Domainsbyip.com * Bing.com * Whois.WebHosting.info * Robtex.com * Tools.web-max.ca * Sameip.org

Current Version: 1.6

RitX 1.6:
  * now RitX uses the new version of Bing Search API (--bing-api)
  * using random info in User Agent and Referrer headers
  * using the the ViewDNS.info API service --vd-api (free)
  * added option --max to set the maximum number of pages to fetch (10)
  * added Pagesinvestigator.com support (cool website)
  * updated Cloudflare detection technique
  * now you can update RitX with Subversion (svn update)
  * now results are more accurate
  * made several changes
