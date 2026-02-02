/* dnsmasq is Copyright (c) 2000-2025 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991, or
   (at your option) version 3 dated 29 June, 2007.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "dnsmasq.h"

/* Mapping from OPT_* boolean flags to config file option names. */
static const struct {
  int opt;
  const char *name;
} bool_opts[] = {
  { OPT_BOGUSPRIV, "bogus-priv" },
  { OPT_FILTER, "filterwin2k" },
  { OPT_SELFMX, "selfmx" },
  { OPT_NO_HOSTS, "no-hosts" },
  { OPT_NO_POLL, "no-poll" },
  { OPT_DEBUG, "no-daemon" },
  { OPT_NODOTS_LOCAL, "domain-needed" },
  { OPT_NOWILD, "bind-interfaces" },
  { OPT_ORDER, "strict-order" },
  { OPT_NO_RESOLV, "no-resolv" },
  { OPT_EXPAND, "expand-hosts" },
  { OPT_LOCALMX, "localmx" },
  { OPT_NO_NEG, "no-negcache" },
  { OPT_ETHERS, "read-ethers" },
  { OPT_NO_FORK, "keep-in-foreground" },
  { OPT_AUTHORITATIVE, "dhcp-authoritative" },
  { OPT_LOCALISE, "localise-queries" },
  { OPT_DHCP_FQDN, "dhcp-fqdn" },
  { OPT_NO_PING, "no-ping" },
  { OPT_LEASE_RO, "leasefile-ro" },
  { OPT_ALL_SERVERS, "all-servers" },
  { OPT_RELOAD, "clear-on-reload" },
  { OPT_LOCAL_REBIND, "rebind-localhost-ok" },
  { OPT_NO_REBIND, "stop-dns-rebind" },
  { OPT_LOG_OPTS, "log-dhcp" },
  { OPT_NO_OVERRIDE, "dhcp-no-override" },
  { OPT_CLEVERBIND, "bind-dynamic" },
  { OPT_TFTP_SECURE, "tftp-secure" },
  { OPT_TFTP_NOBLOCK, "tftp-no-blocksize" },
  { OPT_TFTP_LC, "tftp-lowercase" },
  { OPT_TFTP_NO_FAIL, "tftp-no-fail" },
  { OPT_SINGLE_PORT, "tftp-single-port" },
  { OPT_DNSSEC_PROXY, "proxy-dnssec" },
  { OPT_CONSEC_ADDR, "dhcp-sequential-ip" },
  { OPT_IGNORE_CLID, "dhcp-ignore-clid" },
  { OPT_CONNTRACK, "conntrack" },
  { OPT_FQDN_UPDATE, "dhcp-client-update" },
  { OPT_RA, "enable-ra" },
  { OPT_DNSSEC_VALID, "dnssec" },
  { OPT_DNSSEC_DEBUG, "dnssec-debug" },
  { OPT_DNSSEC_TIME, "dnssec-no-timecheck" },
  { OPT_QUIET_DHCP, "quiet-dhcp" },
  { OPT_QUIET_DHCP6, "quiet-dhcp6" },
  { OPT_QUIET_RA, "quiet-ra" },
  { OPT_QUIET_TFTP, "quiet-tftp" },
  { OPT_LOG_DEBUG, "log-debug" },
  { OPT_LOOP_DETECT, "dns-loop-detect" },
  { OPT_SCRIPT_ARP, "script-arp" },
  { OPT_RAPID_COMMIT, "dhcp-rapid-commit" },
  { OPT_LEASE_RENEW, "script-on-renewal" },
  { OPT_NORR, "no-round-robin" },
  { OPT_STRIP_ECS, "strip-subnet" },
  { OPT_STRIP_MAC, "strip-mac" },
  { OPT_NO_IDENT, "no-ident" },
  { OPT_NO_0x20, "no-0x20-encode" },
  { OPT_DO_0x20, "do-0x20-encode" },
  { -1, NULL }
};

static void dump_bool_opts(void)
{
  int i, first = 1;

  for (i = 0; bool_opts[i].name; i++)
    if (option_bool(bool_opts[i].opt))
      {
	if (first)
	  {
	    printf("# Boolean options\n");
	    first = 0;
	  }
	printf("%s\n", bool_opts[i].name);
      }

  /* log-queries has optional =extra flag */
  if (option_bool(OPT_LOG))
    {
      if (first)
	{
	  printf("# Boolean options\n");
	  first = 0;
	}
      if (option_bool(OPT_EXTRALOG))
	printf("log-queries=extra\n");
      else
	printf("log-queries\n");
    }

  if (option_bool(OPT_TFTP))
    {
      if (first)
	{
	  printf("# Boolean options\n");
	  first = 0;
	}
      printf("enable-tftp\n");
    }

  if (!first)
    printf("\n");
}

static void dump_network_opts(void)
{
  int printed = 0;
  struct iname *in;

#define NET_HEADER() do { if (!printed) { printf("# Network\n"); printed = 1; } } while(0)

  if (daemon->port != NAMESERVER_PORT)
    { NET_HEADER(); printf("port=%d\n", daemon->port); }
  if (daemon->query_port)
    { NET_HEADER(); printf("query-port=%d\n", daemon->query_port); }
  if (daemon->min_port)
    { NET_HEADER(); printf("min-port=%d\n", daemon->min_port); }
  if (daemon->max_port)
    { NET_HEADER(); printf("max-port=%d\n", daemon->max_port); }

  for (in = daemon->if_names; in; in = in->next)
    if (in->name)
      { NET_HEADER(); printf("interface=%s\n", in->name); }

  for (in = daemon->if_addrs; in; in = in->next)
    {
      char buf[ADDRSTRLEN];
      NET_HEADER();
      if (in->addr.sa.sa_family == AF_INET)
	printf("listen-address=%s\n",
	       inet_ntop(AF_INET, &in->addr.in.sin_addr, buf, sizeof(buf)));
      else if (in->addr.sa.sa_family == AF_INET6)
	printf("listen-address=%s\n",
	       inet_ntop(AF_INET6, &in->addr.in6.sin6_addr, buf, sizeof(buf)));
    }

  for (in = daemon->if_except; in; in = in->next)
    if (in->name)
      { NET_HEADER(); printf("except-interface=%s\n", in->name); }

  for (in = daemon->dhcp_except; in; in = in->next)
    if (in->name)
      { NET_HEADER(); printf("no-dhcp-interface=%s\n", in->name); }

  if (daemon->tftp_prefix)
    { NET_HEADER(); printf("tftp-root=%s\n", daemon->tftp_prefix); }

  if (printed)
    printf("\n");

#undef NET_HEADER
}

static void dump_cache_opts(void)
{
  int printed = 0;

#define CACHE_HEADER() do { if (!printed) { printf("# Cache and TTL\n"); printed = 1; } } while(0)

  if (daemon->cachesize != CACHESIZ)
    { CACHE_HEADER(); printf("cache-size=%d\n", daemon->cachesize); }
  if (daemon->edns_pktsz != EDNS_PKTSZ)
    { CACHE_HEADER(); printf("edns-packet-max=%d\n", daemon->edns_pktsz); }
  if (daemon->local_ttl)
    { CACHE_HEADER(); printf("local-ttl=%lu\n", daemon->local_ttl); }
  if (daemon->neg_ttl)
    { CACHE_HEADER(); printf("neg-ttl=%lu\n", daemon->neg_ttl); }
  if (daemon->max_ttl)
    { CACHE_HEADER(); printf("max-ttl=%lu\n", daemon->max_ttl); }
  if (daemon->min_cache_ttl)
    { CACHE_HEADER(); printf("min-cache-ttl=%lu\n", daemon->min_cache_ttl); }
  if (daemon->max_cache_ttl)
    { CACHE_HEADER(); printf("max-cache-ttl=%lu\n", daemon->max_cache_ttl); }
  if (daemon->dhcp_ttl)
    { CACHE_HEADER(); printf("dhcp-ttl=%lu\n", daemon->dhcp_ttl); }
  if (daemon->ftabsize != FTABSIZ)
    { CACHE_HEADER(); printf("dns-forward-max=%d\n", daemon->ftabsize); }
  if (daemon->randport_limit != 1)
    { CACHE_HEADER(); printf("port-limit=%d\n", daemon->randport_limit); }
  if (daemon->max_procs != MAX_PROCS)
    { CACHE_HEADER(); printf("max-tcp-connections=%d\n", daemon->max_procs); }

  if (printed)
    printf("\n");

#undef CACHE_HEADER
}

static void dump_string_opts(void)
{
  int printed = 0;

#define STR_HEADER() do { if (!printed) { printf("# Paths and identities\n"); printed = 1; } } while(0)

  if (daemon->username && strcmp(daemon->username, CHUSER) != 0)
    { STR_HEADER(); printf("user=%s\n", daemon->username); }
  /* user="" means no user switch, still output */
  else if (!daemon->username)
    { STR_HEADER(); printf("user=\n"); }

  if (daemon->groupname)
    { STR_HEADER(); printf("group=%s\n", daemon->groupname); }

  if (daemon->runfile && strcmp(daemon->runfile, RUNFILE) != 0)
    { STR_HEADER(); printf("pid-file=%s\n", daemon->runfile); }
  else if (!daemon->runfile)
    { STR_HEADER(); printf("pid-file=\n"); }

  if (daemon->lease_file)
    { STR_HEADER(); printf("dhcp-leasefile=%s\n", daemon->lease_file); }

  if (daemon->log_file)
    { STR_HEADER(); printf("log-facility=%s\n", daemon->log_file); }

  if (daemon->domain_suffix)
    { STR_HEADER(); printf("domain=%s\n", daemon->domain_suffix); }

  if (daemon->lease_change_command)
    { STR_HEADER(); printf("dhcp-script=%s\n", daemon->lease_change_command); }

  if (daemon->luascript)
    { STR_HEADER(); printf("dhcp-luascript=%s\n", daemon->luascript); }

  if (daemon->dns_client_id)
    { STR_HEADER(); printf("add-cpe-id=%s\n", daemon->dns_client_id); }

  if (daemon->mxtarget)
    { STR_HEADER(); printf("mx-target=%s\n", daemon->mxtarget); }

  if (daemon->scriptuser)
    { STR_HEADER(); printf("dhcp-scriptuser=%s\n", daemon->scriptuser); }

  if (printed)
    printf("\n");

#undef STR_HEADER
}

static void dump_file_opts(void)
{
  int printed = 0;
  struct hostsfile *hf;
  struct resolvc *res;
  struct dyndir *dd;

#define FILE_HEADER() do { if (!printed) { printf("# File paths\n"); printed = 1; } } while(0)

  /* resolv-file: only dump if not the default */
  if (!option_bool(OPT_NO_RESOLV))
    for (res = daemon->resolv_files; res; res = res->next)
      if (!res->is_default && res->name)
	{ FILE_HEADER(); printf("resolv-file=%s\n", res->name); }

  if (daemon->servers_file)
    { FILE_HEADER(); printf("servers-file=%s\n", daemon->servers_file); }

  for (hf = daemon->addn_hosts; hf; hf = hf->next)
    { FILE_HEADER(); printf("addn-hosts=%s\n", hf->fname); }

  for (dd = daemon->dynamic_dirs; dd; dd = dd->next)
    if (dd->dname)
      { FILE_HEADER(); printf("hostsdir=%s\n", dd->dname); }

  for (hf = daemon->dhcp_hosts_file; hf; hf = hf->next)
    { FILE_HEADER(); printf("dhcp-hostsfile=%s\n", hf->fname); }

  for (hf = daemon->dhcp_opts_file; hf; hf = hf->next)
    { FILE_HEADER(); printf("dhcp-optsfile=%s\n", hf->fname); }

  if (printed)
    printf("\n");

#undef FILE_HEADER
}

static void print_server_addr(union mysockaddr *addr, char *interface)
{
  char buf[ADDRSTRLEN];
  int port;

  if (addr->sa.sa_family == AF_INET)
    {
      inet_ntop(AF_INET, &addr->in.sin_addr, buf, sizeof(buf));
      port = ntohs(addr->in.sin_port);
    }
  else
    {
      inet_ntop(AF_INET6, &addr->in6.sin6_addr, buf, sizeof(buf));
      port = ntohs(addr->in6.sin6_port);
    }

  printf("%s", buf);
  if (port != NAMESERVER_PORT)
    printf("#%d", port);
  if (interface[0])
    printf("@%s", interface);
}

static void dump_servers(void)
{
  struct server *serv;
  int printed = 0;
  char buf[ADDRSTRLEN];

#define SRV_HEADER() do { if (!printed) { printf("# DNS servers\n"); printed = 1; } } while(0)

  /* Upstream servers */
  for (serv = daemon->servers; serv; serv = serv->next)
    {
      /* Skip servers from resolv.conf or servers-file (runtime, not config) */
      if (serv->flags & (SERV_FROM_RESOLV | SERV_FROM_FILE | SERV_MARK))
	continue;

      SRV_HEADER();
      printf("server=");

      if (serv->domain && serv->domain[0])
	{
	  if (serv->flags & SERV_WILDCARD)
	    printf("/*%s/", serv->domain);
	  else
	    printf("/%s/", serv->domain);
	}

      print_server_addr(&serv->addr, serv->interface);

      if (serv->flags & SERV_HAS_SOURCE)
	{
	  printf("@");
	  if (serv->source_addr.sa.sa_family == AF_INET)
	    {
	      inet_ntop(AF_INET, &serv->source_addr.in.sin_addr, buf, sizeof(buf));
	      printf("%s", buf);
	    }
	  else
	    {
	      inet_ntop(AF_INET6, &serv->source_addr.in6.sin6_addr, buf, sizeof(buf));
	      printf("%s", buf);
	    }
	}

      printf("\n");
    }

  /* Local domains (local=, address=) */
  for (serv = daemon->local_domains; serv; serv = serv->next)
    {
      if (serv->flags & SERV_MARK)
	continue;

      SRV_HEADER();

      if (serv->flags & SERV_ALL_ZEROS)
	{
	  /* address=/domain/# */
	  printf("address=");
	  if (serv->domain && serv->domain[0])
	    printf("/%s/", serv->domain);
	  printf("#\n");
	}
      else if (serv->flags & SERV_4ADDR)
	{
	  /* address=/domain/ip4 */
	  printf("address=");
	  if (serv->domain && serv->domain[0])
	    printf("/%s/", serv->domain);
	  inet_ntop(AF_INET, &((struct serv_addr4 *)serv)->addr, buf, sizeof(buf));
	  printf("%s\n", buf);
	}
      else if (serv->flags & SERV_6ADDR)
	{
	  /* address=/domain/ip6 */
	  printf("address=");
	  if (serv->domain && serv->domain[0])
	    printf("/%s/", serv->domain);
	  inet_ntop(AF_INET6, &((struct serv_addr6 *)serv)->addr, buf, sizeof(buf));
	  printf("%s\n", buf);
	}
      else if (serv->flags & SERV_USE_RESOLV)
	{
	  /* server=/domain/  (use resolv for this domain) */
	  printf("server=");
	  if (serv->domain && serv->domain[0])
	    printf("/%s/", serv->domain);
	  printf("\n");
	}
      else
	{
	  /* local=/domain/ */
	  printf("local=");
	  if (serv->domain && serv->domain[0])
	    printf("/%s/", serv->domain);
	  printf("\n");
	}
    }

  /* Bogus NXDOMAIN addresses */
  {
    struct bogus_addr *ba;
    for (ba = daemon->bogus_addr; ba; ba = ba->next)
      {
	SRV_HEADER();
	if (ba->is6)
	  {
	    inet_ntop(AF_INET6, &ba->addr.addr6, buf, sizeof(buf));
	    printf("bogus-nxdomain=%s", buf);
	  }
	else
	  {
	    inet_ntop(AF_INET, &ba->addr.addr4, buf, sizeof(buf));
	    printf("bogus-nxdomain=%s", buf);
	  }
	if (ba->prefix > 0)
	  printf("/%d", ba->prefix);
	printf("\n");
      }
  }

  /* Rebind domain exceptions */
  {
    struct rebind_domain *rd;
    for (rd = daemon->no_rebind; rd; rd = rd->next)
      { SRV_HEADER(); printf("rebind-domain-ok=%s\n", rd->domain); }
  }

  if (printed)
    printf("\n");

#undef SRV_HEADER
}

static void format_lease_time(unsigned int leasetime, char *buf, size_t buflen)
{
  if (leasetime == 0xffffffff)
    snprintf(buf, buflen, "infinite");
  else if (leasetime >= 86400 && (leasetime % 86400) == 0)
    snprintf(buf, buflen, "%ud", leasetime / 86400);
  else if (leasetime >= 3600 && (leasetime % 3600) == 0)
    snprintf(buf, buflen, "%uh", leasetime / 3600);
  else if (leasetime >= 60 && (leasetime % 60) == 0)
    snprintf(buf, buflen, "%um", leasetime / 60);
  else
    snprintf(buf, buflen, "%u", leasetime);
}

#ifdef HAVE_DHCP
static void dump_dhcp_ranges(void)
{
  struct dhcp_context *ctx;
  int printed = 0;
  char buf[ADDRSTRLEN], tbuf[32];

  for (ctx = daemon->dhcp; ctx; ctx = ctx->next)
    {
      if (!printed)
	{
	  printf("# DHCP ranges\n");
	  printed = 1;
	}

      printf("dhcp-range=");

      inet_ntop(AF_INET, &ctx->start, buf, sizeof(buf));
      printf("%s,", buf);
      inet_ntop(AF_INET, &ctx->end, buf, sizeof(buf));
      printf("%s", buf);

      if (ctx->flags & CONTEXT_NETMASK)
	{
	  inet_ntop(AF_INET, &ctx->netmask, buf, sizeof(buf));
	  printf(",%s", buf);
	}

      if (ctx->flags & CONTEXT_STATIC)
	printf(",static");
      else if (ctx->flags & CONTEXT_PROXY)
	printf(",proxy");
      else if (ctx->lease_time)
	{
	  format_lease_time(ctx->lease_time, tbuf, sizeof(tbuf));
	  printf(",%s", tbuf);
	}

      printf("\n");
    }

#ifdef HAVE_DHCP6
  for (ctx = daemon->dhcp6; ctx; ctx = ctx->next)
    {
      if (!printed)
	{
	  printf("# DHCP ranges\n");
	  printed = 1;
	}

      printf("dhcp-range=");

      if (ctx->flags & CONTEXT_TEMPLATE)
	printf("::");
      else
	{
	  inet_ntop(AF_INET6, &ctx->start6, buf, sizeof(buf));
	  printf("%s", buf);
	}

      if (ctx->flags & CONTEXT_RA_STATELESS)
	printf(",ra-stateless");
      else if (ctx->flags & CONTEXT_STATIC)
	printf(",static");
      else
	{
	  inet_ntop(AF_INET6, &ctx->end6, buf, sizeof(buf));
	  printf(",%s", buf);
	}

      if (ctx->prefix != 64)
	printf(",%d", ctx->prefix);

      if (ctx->lease_time)
	{
	  format_lease_time(ctx->lease_time, tbuf, sizeof(tbuf));
	  printf(",%s", tbuf);
	}

      printf("\n");
    }
#endif

  if (printed)
    printf("\n");
}

static void dump_dhcp_hosts(void)
{
  struct dhcp_config *conf;
  int printed = 0;
  char buf[ADDRSTRLEN];

  for (conf = daemon->dhcp_conf; conf; conf = conf->next)
    {
      struct hwaddr_config *hw;
      int need_comma = 0;

      /* Skip entries from files (ethers, etc.) */
      if (conf->flags & (CONFIG_FROM_ETHERS | CONFIG_ADDR_HOSTS | CONFIG_ADDR6_HOSTS))
	continue;

      if (!printed)
	{
	  printf("# DHCP hosts\n");
	  printed = 1;
	}

      printf("dhcp-host=");

      /* MAC addresses */
      for (hw = conf->hwaddr; hw; hw = hw->next)
	{
	  int j;
	  if (need_comma) printf(",");
	  for (j = 0; j < hw->hwaddr_len; j++)
	    printf("%s%02x", j ? ":" : "", (unsigned char)hw->hwaddr[j]);
	  need_comma = 1;
	}

      /* Client ID */
      if (conf->flags & CONFIG_CLID)
	{
	  int j;
	  if (need_comma) printf(",");
	  printf("id:");
	  for (j = 0; j < conf->clid_len; j++)
	    printf("%02x", (unsigned char)conf->clid[j]);
	  need_comma = 1;
	}

      /* Hostname */
      if ((conf->flags & CONFIG_NAME) && conf->hostname)
	{
	  if (need_comma) printf(",");
	  printf("%s", conf->hostname);
	  need_comma = 1;
	}

      /* IPv4 address */
      if (conf->flags & CONFIG_ADDR)
	{
	  if (need_comma) printf(",");
	  inet_ntop(AF_INET, &conf->addr, buf, sizeof(buf));
	  printf("%s", buf);
	  need_comma = 1;
	}

#ifdef HAVE_DHCP6
      /* IPv6 addresses */
      if (conf->flags & CONFIG_ADDR6)
	{
	  struct addrlist *al;
	  for (al = conf->addr6; al; al = al->next)
	    {
	      if (need_comma) printf(",");
	      inet_ntop(AF_INET6, &al->addr.addr6, buf, sizeof(buf));
	      printf("[%s]", buf);
	      need_comma = 1;
	    }
	}
#endif

      /* Lease time */
      if (conf->flags & CONFIG_TIME)
	{
	  char tbuf[32];
	  if (need_comma) printf(",");
	  format_lease_time(conf->lease_time, tbuf, sizeof(tbuf));
	  printf("%s", tbuf);
	  need_comma = 1;
	}

      /* Disabled */
      if (conf->flags & CONFIG_DISABLE)
	{
	  if (need_comma) printf(",");
	  printf("ignore");
	}

      printf("\n");
    }

  if (printed)
    printf("\n");
}

static void print_dhcp_opt_val(struct dhcp_opt *opt)
{
  int i;
  char buf[ADDRSTRLEN];

  if (opt->len == 0)
    return;

  printf(",");

  if (opt->flags & DHOPT_ADDR)
    {
      /* IPv4 addresses, INADDRSZ (4) bytes each */
      int naddrs = opt->len / INADDRSZ;
      for (i = 0; i < naddrs; i++)
	{
	  struct in_addr addr;
	  memcpy(&addr, opt->val + (i * INADDRSZ), INADDRSZ);
	  inet_ntop(AF_INET, &addr, buf, sizeof(buf));
	  printf("%s%s", i ? "," : "", buf);
	}
    }
  else if (opt->flags & DHOPT_ADDR6)
    {
      /* IPv6 addresses, IN6ADDRSZ (16) bytes each */
      int naddrs = opt->len / IN6ADDRSZ;
      for (i = 0; i < naddrs; i++)
	{
	  struct in6_addr addr6;
	  memcpy(&addr6, opt->val + (i * IN6ADDRSZ), IN6ADDRSZ);
	  inet_ntop(AF_INET6, &addr6, buf, sizeof(buf));
	  printf("%s[%s]", i ? "," : "", buf);
	}
    }
  else if (opt->flags & DHOPT_STRING)
    {
      fwrite(opt->val, 1, opt->len, stdout);
    }
  else
    {
      /* Raw hex with colon separators */
      for (i = 0; i < opt->len; i++)
	printf("%s%02x", i ? ":" : "", (unsigned char)opt->val[i]);
    }
}

static void dump_dhcp_opts(void)
{
  struct dhcp_opt *opt;
  int printed = 0;

  for (opt = daemon->dhcp_opts; opt; opt = opt->next)
    {
      /* Skip bank (file-sourced) entries */
      if (opt->flags & DHOPT_BANK)
	continue;

      if (!printed)
	{
	  printf("# DHCP options\n");
	  printed = 1;
	}

      if (opt->flags & DHOPT_FORCE)
	printf("dhcp-option-force=");
      else
	printf("dhcp-option=");

      /* Tag matching */
      if (opt->netid)
	{
	  struct dhcp_netid *id;
	  for (id = opt->netid; id; id = id->next)
	    printf("tag:%s,", id->net);
	}

      /* Encapsulated options */
      if (opt->flags & DHOPT_ENCAPSULATE)
	printf("encap:%d,", opt->u.encap);

      /* Vendor class */
      if (opt->flags & DHOPT_VENDOR)
	printf("vendor:");

      printf("%d", opt->opt);
      print_dhcp_opt_val(opt);
      printf("\n");
    }

#ifdef HAVE_DHCP6
  for (opt = daemon->dhcp_opts6; opt; opt = opt->next)
    {
      if (opt->flags & DHOPT_BANK)
	continue;

      if (!printed)
	{
	  printf("# DHCP options\n");
	  printed = 1;
	}

      if (opt->flags & DHOPT_FORCE)
	printf("dhcp-option-force=");
      else
	printf("dhcp-option=");

      if (opt->netid)
	{
	  struct dhcp_netid *id;
	  for (id = opt->netid; id; id = id->next)
	    printf("tag:%s,", id->net);
	}

      printf("option6:%d", opt->opt);
      print_dhcp_opt_val(opt);
      printf("\n");
    }
#endif

  if (printed)
    printf("\n");
}

static void dump_dhcp_extra(void)
{
  int printed = 0;

#define DHCP_HEADER() do { if (!printed) { printf("# DHCP settings\n"); printed = 1; } } while(0)

  if (daemon->dhcp_max != MAXLEASES)
    { DHCP_HEADER(); printf("dhcp-lease-max=%d\n", daemon->dhcp_max); }

  if (daemon->dhcp_server_port != DHCP_SERVER_PORT)
    {
      DHCP_HEADER();
      printf("dhcp-alternate-port=%d", daemon->dhcp_server_port);
      if (daemon->dhcp_client_port != DHCP_CLIENT_PORT)
	printf(",%d", daemon->dhcp_client_port);
      printf("\n");
    }

  if (daemon->min_leasetime)
    {
      char tbuf[32];
      DHCP_HEADER();
      format_lease_time(daemon->min_leasetime, tbuf, sizeof(tbuf));
      printf("dhcp-lease-max=%s\n", tbuf);
    }

  if (printed)
    printf("\n");

#undef DHCP_HEADER
}
#endif /* HAVE_DHCP */

static void dump_dns_records(void)
{
  int printed = 0;
  char buf[ADDRSTRLEN];

#define REC_HEADER() do { if (!printed) { printf("# DNS records\n"); printed = 1; } } while(0)

  /* host-record */
  {
    struct host_record *hr;
    for (hr = daemon->host_records; hr; hr = hr->next)
      {
	struct name_list *nl;
	int need_comma;

	REC_HEADER();
	printf("host-record=");
	need_comma = 0;
	for (nl = hr->names; nl; nl = nl->next)
	  {
	    if (need_comma) printf(",");
	    printf("%s", nl->name);
	    need_comma = 1;
	  }
	if (hr->flags & HR_4)
	  {
	    inet_ntop(AF_INET, &hr->addr, buf, sizeof(buf));
	    printf(",%s", buf);
	  }
	if (hr->flags & HR_6)
	  {
	    inet_ntop(AF_INET6, &hr->addr6, buf, sizeof(buf));
	    printf(",%s", buf);
	  }
	if (hr->ttl)
	  printf(",%d", hr->ttl);
	printf("\n");
      }
  }

  /* cname */
  {
    struct cname *cn;
    for (cn = daemon->cnames; cn; cn = cn->next)
      {
	REC_HEADER();
	printf("cname=%s,%s", cn->alias, cn->target);
	if (cn->ttl)
	  printf(",%d", cn->ttl);
	printf("\n");
      }
  }

  /* txt-record */
  {
    struct txt_record *txt;
    for (txt = daemon->txt; txt; txt = txt->next)
      {
	REC_HEADER();
	if (txt->class == C_IN && txt->len > 0)
	  {
	    unsigned char *p = txt->txt;
	    int remaining = txt->len;

	    printf("txt-record=%s", txt->name);

	    while (remaining > 0)
	      {
		int slen = *p++;
		remaining--;
		if (slen > remaining)
		  slen = remaining;
		printf(",");
		fwrite(p, 1, slen, stdout);
		p += slen;
		remaining -= slen;
	      }
	    printf("\n");
	  }
      }
  }

  /* dns-rr records */
  {
    struct txt_record *rr;
    for (rr = daemon->rr; rr; rr = rr->next)
      {
	int i;
	REC_HEADER();
	printf("dns-rr=%s,%d,", rr->name, rr->class);
	for (i = 0; i < rr->len; i++)
	  printf("%s%02x", i ? ":" : "", (unsigned char)rr->txt[i]);
	printf("\n");
      }
  }

  /* ptr-record */
  {
    struct ptr_record *ptr;
    for (ptr = daemon->ptr; ptr; ptr = ptr->next)
      {
	REC_HEADER();
	printf("ptr-record=%s", ptr->name);
	if (ptr->ptr)
	  printf(",%s", ptr->ptr);
	printf("\n");
      }
  }

  /* mx-host and srv-host */
  {
    struct mx_srv_record *mx;
    for (mx = daemon->mxnames; mx; mx = mx->next)
      {
	REC_HEADER();
	if (mx->issrv)
	  {
	    printf("srv-host=%s,%s,%d,%d,%d\n",
		   mx->name, mx->target ? mx->target : "",
		   mx->srvport, mx->priority, mx->weight);
	  }
	else
	  {
	    printf("mx-host=%s", mx->name);
	    if (mx->target)
	      printf(",%s", mx->target);
	    if (mx->priority)
	      printf(",%d", mx->priority);
	    printf("\n");
	  }
      }
  }

  /* naptr-record */
  {
    struct naptr *na;
    for (na = daemon->naptr; na; na = na->next)
      {
	REC_HEADER();
	printf("naptr-record=%s,%u,%u,\"%s\",\"%s\",\"%s\",%s\n",
	       na->name, na->order, na->pref,
	       na->flags ? na->flags : "",
	       na->services ? na->services : "",
	       na->regexp ? na->regexp : "",
	       na->replace ? na->replace : "");
      }
  }

  /* interface-name */
  {
    struct interface_name *in;
    for (in = daemon->int_names; in; in = in->next)
      {
	REC_HEADER();
	printf("interface-name=%s,%s\n", in->name, in->intr);
      }
  }

  if (printed)
    printf("\n");

#undef REC_HEADER
}

#ifdef HAVE_AUTH
static void dump_auth_dns(void)
{
  int printed = 0;
  char buf[ADDRSTRLEN];

#define AUTH_HEADER() do { if (!printed) { printf("# Auth DNS\n"); printed = 1; } } while(0)

  /* auth-zone */
  {
    struct auth_zone *zone;
    for (zone = daemon->auth_zones; zone; zone = zone->next)
      {
	AUTH_HEADER();
	printf("auth-zone=%s", zone->domain);

	/* Interface names */
	{
	  struct auth_name_list *nl;
	  for (nl = zone->interface_names; nl; nl = nl->next)
	    printf(",%s", nl->name);
	}

	/* Subnets */
	{
	  struct addrlist *al;
	  for (al = zone->subnet; al; al = al->next)
	    {
	      if (al->flags & ADDRLIST_IPV6)
		{
		  inet_ntop(AF_INET6, &al->addr.addr6, buf, sizeof(buf));
		  printf(",%s", buf);
		}
	      else
		{
		  inet_ntop(AF_INET, &al->addr.addr4, buf, sizeof(buf));
		  printf(",%s", buf);
		}
	      if (al->prefixlen > 0)
		printf("/%d", al->prefixlen);
	    }
	}

	/* Exclude */
	{
	  struct addrlist *al;
	  for (al = zone->exclude; al; al = al->next)
	    {
	      if (al->flags & ADDRLIST_IPV6)
		{
		  inet_ntop(AF_INET6, &al->addr.addr6, buf, sizeof(buf));
		  printf(",exclude:%s", buf);
		}
	      else
		{
		  inet_ntop(AF_INET, &al->addr.addr4, buf, sizeof(buf));
		  printf(",exclude:%s", buf);
		}
	      if (al->prefixlen > 0)
		printf("/%d", al->prefixlen);
	    }
	}

	printf("\n");
      }
  }

  /* auth-server */
  if (daemon->authserver)
    {
      AUTH_HEADER();
      printf("auth-server=%s", daemon->authserver);
      if (daemon->authinterface)
	{
	  struct iname *in;
	  for (in = daemon->authinterface; in; in = in->next)
	    if (in->name)
	      printf(",%s", in->name);
	}
      printf("\n");
    }

  /* auth-sec-servers */
  {
    struct name_list *nl;
    for (nl = daemon->secondary_forward_server; nl; nl = nl->next)
      {
	AUTH_HEADER();
	printf("auth-sec-servers=%s\n", nl->name);
      }
  }

  /* auth-peer */
  {
    struct iname *in;
    for (in = daemon->auth_peers; in; in = in->next)
      {
	AUTH_HEADER();
	if (in->name)
	  printf("auth-peer=%s\n", in->name);
	else
	  {
	    if (in->addr.sa.sa_family == AF_INET)
	      {
		inet_ntop(AF_INET, &in->addr.in.sin_addr, buf, sizeof(buf));
		printf("auth-peer=%s\n", buf);
	      }
	    else if (in->addr.sa.sa_family == AF_INET6)
	      {
		inet_ntop(AF_INET6, &in->addr.in6.sin6_addr, buf, sizeof(buf));
		printf("auth-peer=%s\n", buf);
	      }
	  }
      }
  }

  /* auth-ttl */
  if (daemon->auth_ttl != AUTH_TTL)
    { AUTH_HEADER(); printf("auth-ttl=%lu\n", daemon->auth_ttl); }

  /* auth-soa */
  if (daemon->soa_sn || daemon->soa_refresh != SOA_REFRESH ||
      daemon->soa_retry != SOA_RETRY || daemon->soa_expiry != SOA_EXPIRY)
    {
      AUTH_HEADER();
      printf("auth-soa=%lu,%lu,%lu,%lu\n",
	     daemon->soa_sn, daemon->soa_refresh,
	     daemon->soa_retry, daemon->soa_expiry);
    }

  if (daemon->hostmaster)
    { AUTH_HEADER(); printf("# hostmaster=%s (derived from auth-server)\n", daemon->hostmaster); }

  if (printed)
    printf("\n");

#undef AUTH_HEADER
}
#endif /* HAVE_AUTH */

void dump_config(void)
{
  printf("# dnsmasq configuration dump\n");
  printf("# Generated by --dump-config\n\n");

  dump_bool_opts();
  dump_network_opts();
  dump_cache_opts();
  dump_string_opts();
  dump_file_opts();
  dump_servers();

#ifdef HAVE_DHCP
  dump_dhcp_ranges();
  dump_dhcp_hosts();
  dump_dhcp_opts();
  dump_dhcp_extra();
#endif

  dump_dns_records();

#ifdef HAVE_AUTH
  dump_auth_dns();
#endif
}
