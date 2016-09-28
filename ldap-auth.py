#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""

    Author: Ricardo F Klein
    Email : klein.rfk at gmail dot com
    github: https://github.com/kleinstuff

    This script help the openvpn authentication on Active Directory using
    pure LDAP (no Kerberos/NTLM/Whatever) based in 3 facts:
     - The user is using a certificate with CN = his username (you need to
       create the client certificate with that in mind). With this you can
       ensure that a user and only him is using its certificate.
     - The User(SamAccountName) and Password are correct and the user is not
       disabled/blocked on the active directory.
     - The user belongs to the "group_filter", so you can control who should
       or shouldn't have VPN access (even if the user is active and has an
       active client cert).

    We use environment variables for user/password/cn, so you need to set
    your OpenVPN to work like that, you can check examples of the config
    in the README.md

    The process is quite simple, openvpn runs the script, if it doesn't returns
    an "exit 1" the auth is granted.

    @TODO
     - Create filters to enable disable functions of the script? Maybe?
     - Make this script PEP8 compliant
     - Change the "SamAccountName" to a parameter so one can use the same
       script with OpenLDAP (need help on testing this as I don't have a
       production OpenLDAP here, plz open an issue for that if you want)
     - Use a configuration file instead of setting config hardcoded?


"""

import os
import sys
import ldap

# CONFIGURATIONS
bind_user    = "CN=binduser,OU=foo,OU=bar,DC=example,DC=com"
bind_pass    = "somepass"
base_dn      = "DC=example,DC=com"
domain       = "example.com"
host         = "ldaps://ldapserver"
group_filter = "(&(objectClass=user)(samaccountname={0})(!(useraccountcontrol:1.2.840.113556.1.4.803:=2))(memberof=CN=OPENVPN_ALLOWED_GROUP,OU=Groups,OU=foo,OU=bar,DC=example,DC=com))"


def getLDAPConnection(username=bind_user, password=bind_pass):
    # Connects to the ldap server and returns the connection object
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
    con = ldap.initialize(host)
    con.protocol_version = 3
    con.set_option(ldap.OPT_REFERRALS, 0)
    print "connectiong with user {0} and password {1}".format(username, password)
    con.simple_bind_s(username, password)
    return con


def checkCertCommonName(username, commonname):
    # Checks if the auth user is using the correct client certificate
    if username != commonname:
        print "LDAP AUTH -- NOPE: username and cert commonname does not match"
        sys.exit(1)
    else:
        print "LDAP AUTH -- OK: username and cert commonname match"


def checkPW(username, password):
    # Checks if the user/password are correct
    try:
        username = "{0}@{1}".format(username,domain)
        con = getLDAPConnection(username, password)
        print "LDAP AUTH -- OK: Valid credentials"
    except ldap.LDAPError as e:
        # print e
        print "LDAP AUTH -- NOPE: Invalid credentials"
        sys.exit(1)


def getMembership(samaccountname):
    # Checks if the auth user belongs to the vpn authorized group
    con = getLDAPConnection()
    searchfilter = group_filter.format(samaccountname)
    attrs = ['SamAccountName']
    results = con.search_s(base_dn, ldap.SCOPE_SUBTREE, searchfilter, attrs)
    result = results[0][0]
    # print type(result)
    if isinstance(result, str):
        print "LDAP AUTH -- OK: User is inside vpn group"
        # sys.exit(0)
    else:
        print "LDAP AUTH -- NOPE: User is not inide vpn group"
        sys.exit(1)


checkCertCommonName(os.environ['username'], os.environ['common_name'])
checkPW(os.environ['username'], os.environ['password'])
getMembership(os.environ['username'])


