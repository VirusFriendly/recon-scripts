import framework
# unique to module
import dns.resolver
import os.path

class Module(framework.module):

    def __init__(self, params):
        framework.module.__init__(self, params)
        self.register_option('domain', self.goptions['domain']['value'], 'yes', self.goptions['domain']['desc'])
        self.register_option('wordlist', './data/hostnames.txt', 'yes', 'path to hostname wordlist')
        self.register_option('nameserver', '8.8.8.8', 'yes', 'ip address of a valid nameserver')
        self.register_option('attempts', 3, 'yes', 'number of retry attempts per host')
        self.register_option('depth', 0, 'yes', '')
        self.register_option('scan', 'domain', 'yes', 'if set to table, module will also scan domains already in \'hosts\'')
        self.register_option('glue', True, 'yes', 'check for subdomains only when an A record is found.')
        self.info = {
                     'Name': 'DNS Hostname Brute Forcer',
                     'Author': 'Tim Tomes (@LaNMaSteR53), Eric Gragsone',
                     'Description': 'Brute forces host names using DNS and updates the \'hosts\' table of the database with the results.',
                     'Comments': [
                                  'If \'depth\' is 0, brute_force will not check for subdomains. If \'depth\' is -1, brute_force will attempt to find and traverse subdomains. Each level can significantly increase the time required.',
                                  'Setting \'glue\' to \'false\' will take significantly longer but may find subdomains on networks that don\'t use glue A records.',
                                  '\'Scan\' can be set to \'domain\', \'table\', or \'both\'. Setting it to \'table\' will have brute_force check each entry in the \'hosts\' table for subdomains. Setting it to \'both\' will have brute_force check both the \'domain\' value and entries in the \'hosts\' table for subdomains.'
                                 ]
                     }

    def module_run(self):
        wordlist = self.options['wordlist']['value']
        max_attempts = self.options['attempts']['value']
        scan = self.options['scan']['value']
        glue = self.options['glue']['value']
        depth = self.options['depth']['value']
        q = dns.resolver.get_default_resolver()
        q.nameservers = [self.options['nameserver']['value']]
        q.lifetime = 3
        q.timeout = 2
        cnt, tot, sub_cnt = 0, 0, 0
        if scan != 'domain' and scan != 'table' and scan != 'both':
            self.output('scan must be set to either \'domain\', \'table\', or \'both\'. Type \'info\' for more information.')
            return
        if depth < 0:
            depth = 127
        domains=[]
        if scan == 'domain' or scan == 'both':
            domains.append(self.options['domain']['value'])
        if scan == 'table' or scan == 'both':
            rows=self.query('SELECT * FROM "%s" ORDER BY 1' % ('hosts'))
            for row in rows:
                domains.append(row[0])
        if os.path.exists(wordlist):
            words = open(wordlist).read().split()
            while len(domains) > 0:
                domain = domains[0]
                domains.pop(0)
                fake_host = 'sudhfydgssjdue.%s' % domain
                check_hosts, check_domains = 0, 0
                try:
                    answers = q.query(fake_host)
                    self.output('Wildcard DNS entry found. Cannot brute force hostnames for %s.' % (domain))
                except (dns.resolver.NoNameservers, dns.resolver.Timeout):
                    self.error('Invalid nameserver. Cannot brute force hostnames for %s.' % (domain))
                    continue
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                    self.verbose('No Wildcard DNS entry found. Attempting to brute force A & CNAME records for %s.' % (domain))
                    host_wildcard = False
                if depth > 0:
                    try:
                        answers = q.query(fake_host, 'NS')
                        self.output('Wildcard DNS entry found. Cannot brute force nameservers for %s.' % (domain))
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                        self.verbose('No Wildcard DNS entry found. Attempting to brute force NS records for %s.' % (domain))
                        ns_wildcard = False
                else:
                    ns_wildcard = True
                for word in words:
                    attempt = 0
                    host = '%s.%s' % (word, domain)
                    a_found = False
                    if not host_wildcard:
                        while attempt < max_attempts:
                            try:
                                answers = q.query(host)
                            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                                self.verbose('%s => Not a host.' % (host))
                                break;
                            except dns.resolver.Timeout:
                                self.verbose('%s => Request timed out.' % (host))
                                attempt += 1
                                continue
                            else:
                                # process answers
                                for answer in answers.response.answer:
                                    for rdata in answer:
                                        if rdata.rdtype == 1:
                                            self.alert('%s => (A) %s - Host found!' % (host, host))
                                            cnt += self.add_host(host)
                                            tot += 1
                                            a_found = True
                                        if rdata.rdtype == 5:
                                            cname = rdata.target.to_text()[:-1]
                                            self.alert('%s => (CNAME) %s - Host found!' % (host, cname))
                                            if host != cname:
                                                cnt += self.add_host(cname)
                                                tot += 1
                                            cnt += self.add_host(host)
                                            tot += 1
                                break
                    if (not ns_wildcard) and (attempt < max_attempts) and ((not glue) or a_found):
                        attempt = 0
                        while attempt < max_attempts:
                            try:
                                answers = q.query(host, 'NS')
                            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                                self.verbose('%s => Not a subdomain.' % (host))
                                break;
                            except dns.resolver.Timeout:
                                self.verbose('%s => Request timed out.' % (host))
                                attempt += 1
                                continue
                            else:
                                for answer in answers.response.answer:
                                    for rdata in answer:
                                        if rdata.rdtype == 2:
                                            nsrr = rdata.target.to_text()[:-1]
                                            if domains.count(host) == 0:
                                                self.alert('%s => (NS) %s - Subdomain found!' % (host, host))
                                                domains.append(host)
                                                sub_cnt += self.add_host(host)
                                            self.alert('%s => (NS) %s - Host found!' % (host, nsrr))
                                            cnt += self.add_host(nsrr)
                                            tot += 1
                                break
            self.output('%d total hosts found.' % (tot))
            if cnt: self.alert('%d NEW hosts found!' % (cnt))
            if depth > 0: self.output('%d subdomains found!' % (sub_cnt))
        else:
            self.error('Wordlist file not found.')
