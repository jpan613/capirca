"""Fortigate generator."""

__author__ = 'john.pan@uber.com'


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
        self.fortigate_policies = {}
        self.addrgrps = {}
        self.services = {}
        current_date = datetime.date.today()
        exp_info_date = current_date + datetime.timedelta(weeks=exp_info)

        for header, terms in pol.filters:
            if self._PLATFORM not in header.platforms:
                continue

            filter_options = header.FilterOptions(self._PLATFORM)
            if (len(filter_options) < 3 or filter_options[1] != 'vdom'):
                raise FortigatePolicyError(
                    'Fortigate filter arguments must specify vdom')

            vdom = filter_options[2]
            output_format = 'conf'
            filter_type = 'inet'

            #vdom value is mandatory; address family is defaulted to inet,
            #but it supports inet6; output format is defaulted to "conf"
            #but can be set to json for fortigate configuration through api
            if len(filter_options) > 3:
                for fop in filter_options[3:]:
                    if fop == 'conf' or fop == 'json':
                        output_format = fop
                    elif fop in self._SUPPORTED_AF:
                        filter_type = fop
                    else:
                        raise FortigatePolicyError(
                        'Fortinet library currently does not support '
                        '{} as a header option'.format(filter_type))
            if vdom not in self.fortigate_policies:
                self.fortigate_policies[vdom] = []
            term_dup_check = set()
            new_terms = []
            index_v4 = 0
            index_v6 = 0
            for term in terms:
                ipv4_src = False
                ipv4_dst = False
                ipv6_src = False
                ipv6_dst = False
                term.name = self.FixTermLength(term.name)
                if term.name in term_dup_check:
                    raise FortigatePolicyError(
                        'You have a duplicate term: {0}'.format(term.name))

                term_dup_check.add(term.name)

                if term.expiration:
                    if term.expiration <= exp_info_date:
                        logging.info('INFO: Term {} in policy vdom {} expires '
                                     'in less than two weeks.'.format(term.name,
                                      vdom))
                    if term.expiration <= current_date:
                        logging.warn('WARNING: Term {} in policy vdom {} is '
                                   'expired.'.format(term.name, vdom))
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
                    if filter_type == 'inet' and addr.version == 4:
                        self._BuildAddrGrps(vdom, term.source_interface,
                                            addr, 'inet')
                        ipv4_src = True
                    elif filter_type == 'inet6' and addr.version == 6:
                        self._BuildAddrGrps(vdom, term.source_interface,
                                            addr, 'inet6')
                        ipv6_src = True

                for addr in term.destination_address:
                    if filter_type == 'inet' and addr.version == 4:
                        self._BuildAddrGrps(vdom, term.destination_interface,
                                            addr, 'inet')
                        ipv4_dst = True
                    elif filter_type == 'inet6' and addr.version == 6:
                        self._BuildAddrGrps(vdom, term.destination_interface,
                                            addr, 'inet6')
                        ipv6_dst = True
                #increment policyid by 100 to allow inserting new rules
                #between existing rules
                if ((term.source_address == [] or ipv4_src) and
                    (term.destination_address == [] or ipv4_dst) and
                    filter_type == 'inet'):
                    new_term = Term(term, filter_type, index_v4 * 10 + 1)
                    new_terms.append(new_term)
                    index_v4 += 1
                if ((term.source_address == [] or ipv6_src) and
                    (term.destination_address == [] or ipv6_dst) and
                    filter_type == 'inet6'):
                    new_term = Term(term, filter_type, index_v6 * 10 + 1)
                    new_terms.append(new_term)
                    index_v6 += 1
                tmp_icmptype = new_term.NormalizeIcmpTypes(
                    term.icmp_type, term.protocol, filter_type)
                if tmp_icmptype != ['']:
                    normalized_icmptype = tmp_icmptype
                else:
                    normalized_icmptype = []
                protocol = term.protocol
                new_service = {'sport':self._BuildPort(term.source_port),
                               'dport':self._BuildPort(term.destination_port),
                               'name':term.name,
                               'protocol':term.protocol,
                               'icmp-type':normalized_icmptype
                              }
                if vdom not in self.services:
                    self.services[vdom] = []
                self.services[vdom].append(new_service)
            self.fortigate_policies[vdom].append((new_terms, filter_type,
                output_format))


    def _BuildAddrGrps(self, vdom, associated_intf, address, af):
        if af == 'inet':
            addrgrp_name = (address.parent_token + '_' +
                associated_intf + '_' + af)
        elif af == 'inet6':
            addrgrp_name = (address.parent_token + '_' + af)
        if vdom not in self.addrgrps:
            self.addrgrps[vdom] = {}
        if addrgrp_name not in self.addrgrps[vdom]:
            self.addrgrps[vdom][addrgrp_name] = (associated_intf,[], af)
        for ip in self.addrgrps[vdom][addrgrp_name][1]:
            if str(address) == str(ip[1]):
                return
        counter = len(self.addrgrps[vdom][addrgrp_name][1])
        name = '{}_{}'.format(addrgrp_name, str(counter))
        self.addrgrps[vdom][addrgrp_name][1].append((address, name))

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
        output = ''
        for vdom, policies in self.fortigate_policies.iteritems():
            for policy in policies:
                target = []
                terms, filter_type, output_format = policy
                if output_format == 'conf':
                    #switch to vdom
                    target.append('config vdom')
                    target.append('edit {}'.format(vdom))

                    #populate address
                    if filter_type == 'inet':
                        target.append('config firewall address')
                    elif filter_type == 'inet6':
                        target.append('config firewall address6')
                    for ag_name, ag_value in self.addrgrps[vdom].iteritems():
                        if ag_value[2] != filter_type:
                            continue
                        for ip, name in ag_value[1]:
                            target.append(self.INDENT + 'edit ' + name)
                            if filter_type == 'inet':
                                target.append(self.INDENT * 2 +
                                    'set associated-interface ' + ag_value[0])
                                target.append(self.INDENT * 2 +
                                    'set subnet ' + str(ip))
                            elif filter_type == 'inet6':
                                target.append(self.INDENT * 2 + 'set ip6 '+
                                    str(ip))
                                target.append(self.INDENT * 2 + 'next')
                    target.append(self.INDENT + 'end')

                    #populate addrgrp
                    if filter_type == 'inet':
                        target.append('config firewall addrgrp')
                    elif filter_type == 'inet6':
                        target.append('config firewall addrgrp6')
                    for ag_name, ag_value in self.addrgrps[vdom].iteritems():
                        if ag_value[2] != filter_type:
                            continue
                        target.append(self.INDENT + 'edit ' + ag_name)
                        addr_list = [addr[1] for addr in ag_value[1]]
                        target.append(
                            self.INDENT * 2 + 'set member ' +
                            ' '.join(addr_list))
                        target.append(self.INDENT * 2 + 'next')
                    target.append(self.INDENT + 'end')


                    #populate services
                    target.append('config firewall service custom')
                    done_apps = []
                    for app in self.services[vdom]:
                        if app in done_apps:
                            continue
                        target.append(self.INDENT +
                            'edit \"{}-svc\"'.format(app['name']))
                        if (app['protocol'] or app['sport'] or app['dport'] or
                            app['icmp-type']):
                            if app['icmp-type']:
                                if filter_type == 'inet':
                                    target.append(self.INDENT * 2 +
                                        'set protocol ICMP')
                                elif filter_type == 'inet6':
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
                                            target.append(line + dp + ':' + sp)
                                        elif sp:
                                            target.append(line + '1-65535:' +
                                                sp)
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
                                            target.append(tcp_line + dp + ':' +
                                                sp)
                                            target.append(udp_line + dp + ':' +
                                                sp)
                                        elif sp:
                                            target.append(tcp_line +
                                                '1-65535:' + sp)
                                            target.append(udp_line +
                                                '1-65535:' + sp)
                                        elif dp:
                                            target.append(tcp_line + dp)
                                            target.append(udp_line + dp)
                            else:
                                target.append(self.INDENT * 2 +
                                    'set protocol IP')
                                for proto in app['protocol']:
                                    proto_num = self.PROTO_MAP.get(proto)
                                    target.append(self.INDENT * 2 +
                                        'set protocol-number ' + str(proto_num))
                        else:
                            target.append(self.INDENT * 2 + 'set protocol IP')
                        done_apps.append(app)
                        target.append(self.INDENT * 2 + 'next')
                    target.append(self.INDENT + 'end')

                    #populate rules
                    if filter_type == 'inet':
                        target.append('config firewall policy')
                    if filter_type == 'inet6':
                        target.append('config firewall policy6')
                    for term in terms:
                        target.append(str(term))
                        target.append(self.INDENT * 2 + 'next')
                    target.append(self.INDENT + 'end')
                    output += '\n'.join(target)
                    output += '\nend\n\n\n'
                elif output_format == 'json':
                    target = {}
                    #vdom
                    target['vdom'] = vdom
                    #address
                    target['address'] = []
                    for ag_name, ag_value in self.addrgrps[vdom].iteritems():
                        for ip, name in ag_value[1]:
                            addr_entry = {}
                            addr_entry['name'] = name
                            addr_entry['associated-interface'] = ag_value[0]
                            addr_entry['subnet'] = '{} {}'.format(
                                str(ip.network), str(ip.netmask))
                            target['address'].append(addr_entry)

                    #addrgrp
                    target['addrgrp'] = []
                    for ag_name, ag_value in self.addrgrps[vdom].iteritems():
                        addrgrp_entry = {}
                        addrgrp_entry['name'] = ag_name
                        addr_list = [addr[1] for addr in ag_value[1]]
                        addrgrp_entry['member'] = []
                        for addr in addr_list:
                            addrgrp_entry['member'].append({'name':addr})
                        target['addrgrp'].append(addrgrp_entry)

                    #services
                    target['service'] = []
                    target['service'].append('config firewall service custom')
                    done_apps = []
                    for app in self.services[vdom]:
                        if app in done_apps:
                            continue
                        svc_entry = {}
                        svc_entry['name'] = app['name'] + '-svc'
                        if (app['protocol'] or app['sport'] or app['dport'] or
                            app['icmp-type']):
                            svc_entry['protocol'] = []
                            if app['icmp-type']:
                                if filter_type == 'inet':
                                    svc_entry['protocol'].append('ICMP')
                                elif filter_type == 'inet6':
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
                                        svc_entry[proto + '-portrange'].append(
                                            port_range)
                                    else:
                                        if sp and dp:
                                            port_range = '{}:{}'.format(dp, sp)
                                        elif sp:
                                            port_range = '1-65535:{}'.format(sp)
                                        elif dp:
                                            port_range = dp
                                        svc_entry['tcp-portrange'].append(
                                            port_range)
                                        svc_entry['udp-portrange'].append(
                                            port_range)
                            else:
                                svc_entry['protocol'].append('IP')
                                svc_entry['protocol-number'] = []
                                for proto in app['protocol']:
                                    proto_num = self.PROTO_MAP.get(proto)
                                    svc_entry['protocol-number'].append(
                                        proto_num)
                        else:
                            svc_entry['protocol'] = ['IP']
                        done_apps.append(app)
                        target['service'].append(svc_entry)

                    #rules
                    if filter_type == 'inet':
                        policy_type = 'policy'
                    if filter_type == 'inet6':
                        policy_type = 'policy6'
                    target[policy_type] = []
                    for term in terms:
                        term_entry = term.json()
                        target[policy_type].append(term_entry)
                    output += json.dumps(target,indent=4, sort_keys=True)
                    output += '\n'
        return output
