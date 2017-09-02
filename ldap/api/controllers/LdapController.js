/**
 * LdapController
 *
 * @description :: Server-side logic for managing ldaps
 * @help        :: See http://sailsjs.org/#!/documentation/concepts/Controllers
 */

var LdapAuth = require('ldapauth-fork');

module.exports = {
  auth: function (req, res) {
    if (!req.param('user') || req.param('user').length == 0) {
      return res.badRequest("User field is missing or empty!");
    }

    if (!req.param('pass') || req.param('pass').length == 0) {
      return res.badRequest("User field is missing or empty!");
    }

    var config = {
      ldap: {
        url: "ldap://ldap.forumsys.com:389",
        bindDn: "cn=read-only-admin,dc=example,dc=com",
        bindCredentials: "password",
        searchBase: "dc=example,dc=com",
        searchFilter: "(uid={{username}})"
      }
    };

    var ldap = new LdapAuth({
      url: config.ldap.url,
      bindDn: config.ldap.bindDn,
      bindCredentials: config.ldap.bindCredentials,
      searchBase: config.ldap.searchBase,
      searchFilter: config.ldap.searchFilter,
      cache: true
    });

    var authenticate = function (username, password) {
      ldap.authenticate(username, password, function (err, user) {
        if (err) {
          return res.negotiate(err);
        } else {
          return res.json(user);
        }

      });
    }
    authenticate(req.param('user'), req.param('pass'));
  }
};
