"""Fortigate generator."""

__author__ = 'john.pan@uber.com'

'''
Right now the generator is not handling ipv6 correctly. If ipv6 net objs are
referenced in the policy, the generator will fail. I am working on fixing it
ASAP.
'''


'''
header {
  comment:: "fortigate filtre example"
  target:: fortigate <filter_name> vdom <vdom_name> <inet/inet6> <conf/json>
}
term ALLOW_ICMP {
  source-interface:: port1
  destination-interface:: port2
  source-address:: mysource
  destination-address: yourdestination
  protocol:: icmp
  icmp-type:: echo-reply echo-request time-exceeded source-quench
  action:: accept
  comment:: "I'm allowing ICMP in"
  schedule:: mysechedule
  comment:: 'this is one good looking filter'
}

in the "target" header, you have the option to output thie filter in either
"conf" format for CLI-stype syntax or "json" that can be used to POST to
Fortigate API.


'''

import aclgenerator
import nacaddr
import collections
import itertools
import datetime
import json

class FortigatePolicyError(Exception):
  """generic error class."""


def Dedupe(a_list):
    unique = []
    [unique.append(item) for item in a_list if item not in unique]
    return unique

class Term(aclgenerator.Term):
    def __init__(self, term, term_type, policyid):
        self.term = term
        self.term_type = term_type
        self.policyid = policyid

    def __str__(self):
        if self.term.platform:
            if 'fortigate' not in self.term.platform:
                return ''
        if self.term.platform_exclude:
            if 'fortigate' in self.term.platform_exclude:
                return ''
        ret_str = []


        ret_str.append(Fortigate.INDENT + 'edit {}'.format(self.policyid))
        #not sure about what the max is, but 100 seems to be a reasonable number
        comment_max_width = 100
        comments = aclgenerator.WrapWords(self.term.comment, comment_max_width)
        if comments:
            ret_str.append(Fortigate.INDENT * 2 +
                'set comments \"{}\"'.format(' '.join(comments)))

        #source interface
        if not self.term.source_interface:
            raise FortigatePolicyError('no source-interface specified')
        else:
            ret_str.append(Fortigate.INDENT * 2 +
                'set srcintf \"{}\"'.format(self.term.source_interface))

        #destination interface
        if not self.term.destination_interface:
            raise FortigatePolicyError('no destination-interface specified')
        else:
            ret_str.append(Fortigate.INDENT * 2 +
                'set dstintf \"{}\"'.format(self.term.destination_interface))

        #source address
        if self.term.source_address:
            saddr_list_string = ' '.join(Dedupe(
                ['\"{}\"'.format(saddr.parent_token +
                '_' + self.term.source_interface) for
                saddr in self.term.source_address]))
            ret_str.append(Fortigate.INDENT * 2 +
                'set srcaddr {}'.format(saddr_list_string))
        else:
            ret_str.append(Fortigate.INDENT * 2 + 'set srcaddr \"all\"')

        #destination address
        if self.term.destination_address:
            daddr_list_string = ' '.join(Dedupe(
                ['\"{}\"'.format(daddr.parent_token +
                '_' + self.term.destination_interface) for
                daddr in self.term.destination_address]))
            ret_str.append(Fortigate.INDENT * 2 +
                'set dstaddr {}'.format(daddr_list_string))
        else:
            ret_str.append(Fortigate.INDENT * 2 + 'set dstaddr \"all\"')

        #service
        if (not self.term.source_port and not self.term.destination_port and not
            self.term.icmp_type and not self.term.protocol):
          ret_str.append(Fortigate.INDENT * 2 + 'set service \"ALL\"')
        else:
            ret_str.append(Fortigate.INDENT * 2 + 'set service \"' +
                           self.term.name + '-svc\"')

        #schedule
        if not self.term.schedule:
            ret_str.append(Fortigate.INDENT * 2 + 'set schedule always')
        else:
            ret_str.append(Fortigate.INDENT * 2 +
                           'set schedule \"{}\"'.format(self.term.schedule))

        #action
        for action in self.term.action:
            ret_str.append(Fortigate.INDENT * 2 +
                'set action {}'.format(action))
        return '\n'.join(ret_str)


    def json(self):
        if self.term.platform:
            if 'fortigate' not in self.term.platform:
                return {}
        if self.term.platform_exclude:
            if 'fortigate' in self.term.platform_exclude:
                return {}
        term_entry = {}
        #policyid
        term_entry['policyid'] = self.policyid
        #comments
        comment_max_width = 100
        comments = aclgenerator.WrapWords(self.term.comment, comment_max_width)
        if comments:
            term_entry['comments'] = comments
        #srcintf
        if not self.term.source_interface:
            raise FortigatePolicyError('no source-interface specified')
        else:
            term_entry['srcintf'] = [{'name':self.term.source_interface}]
        #dstintf
        if not self.term.destination_interface:
            raise FortigatePolicyError('no destination-interface specified')
        else:
            term_entry['dstintf'] = [{'name':self.term.destination_interface}]
        #srcaddr
        if self.term.source_address:
            term_entry['srcaddr'] = []
            saddr_list = Dedupe(
                [(saddr.parent_token + '_' +
                self.term.source_interface) for saddr in
                self.term.source_address]
                )
            for saddr in saddr_list:
                term_entry['srcaddr'].append({'name':saddr})
        else:
            term_entry['srcaddr'] = [{'name':'all'}]
        #dstaddr
        if self.term.destination_address:
            term_entry['dstaddr'] = []
            daddr_list = Dedupe(
                [(daddr.parent_token + '_' +
                self.term.destination_interface) for daddr in
                self.term.destination_address]
                )
            for daddr in daddr_list:
                term_entry['dstaddr'].append({'name':daddr})
        else:
            term_entry['dstaddr'] = [{'name':'all'}]
        #service
        if (not self.term.source_port and not self.term.destination_port and not
            self.term.icmp_type and not self.term.protocol):
            term_entry['service'] = [{'name':'ALL'}]
        else:
            term_entry['service'] = [{'name':self.term.name + '-svc'}]
        #schedule
        if not self.term.schedule:
            term_entry['schedule'] = {'name':'always'}
        else:
            term_entry['schedule'] = {'name':self.term.schedule}
        #rule_action
        term_entry['action'] = []
        for action in self.term.action:
            term_entry['action'].append(action)
        return term_entry


class Fortigate(aclgenerator.ACLGenerator):
    """A Fortigate policy object."""

    _PLATFORM = 'fortigate'
    SUFFIX = '.forti'
    _SUPPORTED_AF = ('inet','inet6')
    INDENT = '    '
    PROTO_MAP = {'hop-by-hop': 0,
               'icmp': 1,
               'igmp': 2,
               'ggp': 3,
               'ipencap': 4,
               'tcp': 6,
               'egp': 8,
               'igp': 9,
               'udp': 17,
               'rdp': 27,
               'ipv6': 41,
               'ipv6-route': 43,
               'fragment': 44,
               'rsvp': 46,
               'gre': 47,
               'esp': 50,
               'ah': 51,
               'icmpv6': 58,
               'ipv6-nonxt': 59,
               'ipv6-opts': 60,
               'ospf': 89,
               'ipip': 94,
               'pim': 103,
               'vrrp': 112,
               'l2tp': 115,
               'sctp': 132,
              }
    _OPTIONAL_SUPPORTED_KEYWORDS = set(['destination_interface',
                                        'source_interface',
                                        'schedule'])

    def _TranslatePolicy(self, pol, exp_info):
        self.fortigate_policies = []
        self.addrgrps = {}
        self.services = []
        self.ports = []
        self.vdom = ''
        self.output_format = 'conf'

        current_date = datetime.date.today()
        exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

        for header, terms in pol.filters:
            if self._PLATFORM not in header.platforms:
                continue

            filter_options = header.FilterOptions(self._PLATFORM)
            if (len(filter_options) < 3 or filter_options[1] != 'vdom'):
                raise FortigatePolicyError(
                    'Fortigate filter arguments must specify vdom')

            self.vdom = filter_options[2]

            self.filter_type = 'inet'
            #vdom value is mandatory; address family is defaulted to inet,
            #but it supports inet6; output format is defaulted to "conf"
            #but can be set to json for fortigate configuration through api
            if len(filter_options) > 3:
                for fop in filter_options[3:]:
                    if fop == 'conf' or fop == 'json':
                        self.output_format = fop
                    elif fop in self._SUPPORTED_AF:
                        self.filter_type = fop
                    else:
                        raise FortigatePolicyError(
                        'Fortinet library currently does not support '
                        '{} as a header option'.format(self.filter_type))

            term_dup_check = set()
            new_terms = []
            for index, term in enumerate(terms):
                term.name = self.FixTermLength(term.name)
                if term.name in term_dup_check:
                    raise FortigatePolicyError(
                        'You have a duplicate term: {0}'.format(term.name))

                term_dup_check.add(term.name)

                if term.expiration:
                    if term.expiration <= exp_info_date:
                        logging.info('INFO: Term {} in policy vdom {} expires '
                                     'in less than two weeks.'.format(term.name,
                                     self.vdom))
                    if term.expiration <= current_date:
                        logging.warn('WARNING: Term {} in policy vdom {} is '
                                   'expired.'.format(term.name, self.vdom))
                        continue

                #Fortigate uses numeric policyid instead of policy name
                #Therefore we move the capirca policy name to comment
                term.comment = [term.name] + term.comment

                for i in term.source_address_exclude:
                    term.source_address = nacaddr.RemoveAddressFromList(
                        term.source_address, i)

                for i in term.destination_address_exclude:
                    term.destination_address = nacaddr.RemoveAddressFromList(
                        term.destination_address, i)

                for addr in term.source_address:
                    self._BuildAddrGrps(term.source_interface,addr)

                for addr in term.destination_address:
                    self._BuildAddrGrps(term.destination_interface,addr)
                #increment policyid by 100 to allow inserting new rules
                #between existing rules
                new_term = Term(term, self.filter_type, index * 100 + 1)
                new_terms.append(new_term)
                tmp_icmptype = new_term.NormalizeIcmpTypes(
                    term.icmp_type, term.protocol, self.filter_type)
                normalized_icmptype = tmp_icmptype if tmp_icmptype != [''] else []
                protocol = term.protocol
                self.services.append({'sport': self._BuildPort(term.source_port),
                                      'dport': self._BuildPort(
                                          term.destination_port),
                                      'name': term.name,
                                      'protocol': term.protocol,
                                      'icmp-type': normalized_icmptype})
            self.fortigate_policies.append((header, new_terms,
                filter_options))


    def _BuildAddrGrps(self, associated_intf, address):
        addrgrp_name = address.parent_token + '_' + associated_intf
        if addrgrp_name not in self.addrgrps:
            self.addrgrps[addrgrp_name] = (associated_intf,[])
        for ip in self.addrgrps[addrgrp_name][1]:
            if str(address) == str(ip[1]):
                return
        counter = len(self.addrgrps[addrgrp_name][1])
        name = '{}_{}'.format(addrgrp_name, str(counter))
        self.addrgrps[addrgrp_name][1].append((associated_intf, address, name))

    def _BuildPort(self, ports):

        port_string_list = []
        for lower_port, higher_port in ports:
            if lower_port == higher_port:
                port_string_list.append(str(lower_port))
            else:
                port_string_list.append('{}-{}'.format(lower_port, higher_port))
        return port_string_list

    def __str__(self):
        #I can't find a way to do a wholesale atomic change to the entire
        #ruleset. Under "config firewall policy", we could do "purge" but
        #it requires interactive confirmation by typing 'y'
        target = []
        if self.output_format == 'conf':
            #switch to vdom
            target.append('config vdom')
            target.append('edit {}'.format(self.vdom))

            #populate address
            target.append('config firewall address')
            for addrgrp_name, addrgrp_value in self.addrgrps.iteritems():
                for intf, ip, name in addrgrp_value[1]:
                    target.append(self.INDENT + 'edit {}'.format(name))
                    target.append(self.INDENT * 2 +
                        'set associated-interface {}'.format(intf))
                    target.append(self.INDENT * 2 + 'set subnet {}'.format(ip))
                    target.append(self.INDENT * 2 + 'next')
            target.append(self.INDENT + 'end')

            #populate addrgrp
            target.append('config firewall addrgrp')
            for addrgrp_name, addrgrp_value in self.addrgrps.iteritems():
                target.append(self.INDENT +
                    'edit {}'.format(addrgrp_name))
                addr_list = [addr[2] for addr in addrgrp_value[1]]
                target.append(
                    self.INDENT * 2 +
                    'set member {}'.format(' '.join(addr_list )))
                target.append(self.INDENT * 2 + 'next')
            target.append(self.INDENT + 'end')


            #populate services
            target.append('config firewall service custom')
            done_apps = []
            for app in self.services:
                if app in done_apps:
                    continue
                target.append(self.INDENT +
                    'edit \"{}-svc\"'.format(app['name']))
                if (app['protocol'] or app['sport'] or app['dport'] or
                    app['icmp-type']):
                    if app['icmp-type']:
                        if self.filter_type == 'inet':
                            target.append(self.INDENT * 2 +
                                'set protocol ICMP')
                        elif self.filter_type == 'inet6':
                            target.append(self.INDENT * 2 +
                                'set protocol ICMP6')
                        for icmptype in app['icmp-type']:
                            target.append(self.INDENT * 2 +
                                'set icmptype {}'.format(icmptype))
                    elif (app['sport'] or app['dport']):
                        target.append(self.INDENT * 2 +
                            'set protocol TCP/UDP/SCTP')
                        for proto, sp, dp in itertools.product(
                            app['protocol'] or [''],
                            app['sport'] or [''],
                            app['dport'] or ['']):
                            if proto:
                                line = (self.INDENT * 2 +
                                    'set {}-portrange '.format(proto))
                                if sp and dp:
                                    target.append(line + '{}:{}'.format(dp, sp))
                                elif sp:
                                    target.append(line +
                                        '1-65535:{}'.format(sp))
                                elif dp:
                                    target.append(line + dp)
                                else:
                                    target.append(line + '1-65535')
                            else:
                                tcp_line = (self.INDENT * 2 +
                                    'set tcp-portrange ')
                                udp_line = (self.INDENT * 2 +
                                    'set udp-portrange ')
                                if sp and dp:
                                    target.append(tcp_line +
                                        '{}:{}'.format(dp, sp))
                                    target.append(udp_line +
                                        '{}:{}'.format(dp, sp))
                                elif sp:
                                    target.append(tcp_line +
                                        '1-65535:{}'.format(sp))
                                    target.append(udp_line +
                                        '1-65535:{}'.format(sp))
                                elif dp:
                                    target.append(tcp_line + dp)
                                    target.append(udp_line + dp)
                    else:
                        target.append(self.INDENT * 2 + 'set protocol IP')
                        for proto in app['protocol']:
                            proto_num = self.PROTO_MAP.get(proto)
                            target.append(self.INDENT * 2 +
                                'set protocol-number {}'.format(proto_num))
                else:
                    target.append(self.INDENT * 2 + 'set protocol IP')
                done_apps.append(app)
                target.append(self.INDENT * 2 + 'next')
            target.append(self.INDENT + 'end')

            #populate rules
            if self.filter_type == 'inet':
                target.append('config firewall policy')
            if self.filter_type == 'inet6':
                target.append('config firewall policy6')
            for (_, terms, _) in self.fortigate_policies:
                for term in terms:
                    target.append(str(term))
                    target.append(self.INDENT * 2 + 'next')
                target.append(self.INDENT + 'end')
            return '\n'.join(target)
        elif self.output_format == 'json':
            output = {}
            #vdom
            output['vdom'] = self.vdom

            #address
            output['address'] = []
            for addrgrp_name, addrgrp_value in self.addrgrps.iteritems():
                for intf, ip, name in addrgrp_value[1]:
                    addr_entry = {}
                    addr_entry['name'] = name
                    addr_entry['associated-interface'] = intf
                    addr_entry['subnet'] = '{} {}'.format(str(ip.network),
                        str(ip.netmask))
                    output['address'].append(addr_entry)

            #addrgrp
            output['addrgrp'] = []
            for addrgrp_name, addrgrp_value in self.addrgrps.iteritems():
                addrgrp_entry = {}
                addrgrp_entry['name'] = addrgrp_name
                addr_list = [addr[2] for addr in addrgrp_value[1]]
                addrgrp_entry['member'] = []
                for addr in addr_list:
                    addrgrp_entry['member'].append({'name':addr})
                output['addrgrp'].append(addrgrp_entry)

            #services
            output['service'] = []
            target.append('config firewall service custom')
            done_apps = []
            for app in self.services:
                if app in done_apps:
                    continue
                svc_entry = {}
                svc_entry['name'] = app['name'] + '-svc'
                if (app['protocol'] or app['sport'] or app['dport'] or
                    app['icmp-type']):
                    svc_entry['protocol'] = []
                    if app['icmp-type']:
                        if self.filter_type == 'inet':
                            svc_entry['protocol'].append('ICMP')
                        elif self.filter_type == 'inet6':
                            svc_entry['protocol'].append('ICMP6')
                        if app.get('icmp-type'):
                            svc_entry['icmptype'] = []
                        for icmptype in app['icmp-type']:
                            svc_entry['icmptype'].append(icmptype)
                    elif (app['sport'] or app['dport']):
                        svc_entry['protocol'].append('TCP/UDP/SCTP')
                        svc_entry['tcp-portrange'] = []
                        svc_entry['udp-portrange'] = []
                        for proto, sp, dp in itertools.product(
                            app['protocol'] or [''],
                            app['sport'] or [''],
                            app['dport'] or ['']):
                            if proto:
                                if sp and dp:
                                    port_range = '{}:{}'.format(dp, sp)
                                elif sp:
                                    port_range = '1-65535:{}'.format(sp)
                                elif dp:
                                    port_range = dp
                                else:
                                    port_range = '1-65535'
                                svc_entry['{}-portrange'.format(proto)].append(
                                    port_range)
                            else:
                                if sp and dp:
                                    port_range = '{}:{}'.format(dp, sp)
                                elif sp:
                                    port_range = '1-65535:{}'.format(sp)
                                elif dp:
                                    port_range = dp
                                svc_entry['tcp-portrange'].append(port_range)
                                svc_entry['udp-portrange'].append(port_range)
                    else:
                        svc_entry['protocol'].append('IP')
                        svc_entry['protocol-number'] = []
                        for proto in app['protocol']:
                            proto_num = self.PROTO_MAP.get(proto)
                            svc_entry['protocol-number'].append(proto_num)
                else:
                    svc_entry['protocol'] = ['IP']
                done_apps.append(app)
                output['service'].append(svc_entry)

            #rules
            if self.filter_type == 'inet':
                policy_type = 'policy'
            if self.filter_type == 'inet6':
                policy_type = 'policy6'
            output[policy_type] = []
            for (_, terms, _) in self.fortigate_policies:
                for term in terms:
                    term_entry = term.json()
                    output[policy_type].append(term_entry)
            return json.dumps(output,indent=4, sort_keys=True)
