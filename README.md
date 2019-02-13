# nginxauth
[![Build Status](https://travis-ci.org/EndFirstCorp/auth.svg?branch=master)](https://travis-ci.org/EndFirstCorp/auth) [![Coverage Status](https://coveralls.io/repos/github/EndFirstCorp/nginxauth/badge.svg?branch=master)](https://coveralls.io/github/EndFirstCorp/nginxauth?branch=master)

A Go http server or middleware that can be used as an authentication backend with NGINX or directly in a Go web server
Capabilities included:
1. Session management (through Redis by default)
2. User authentication and hashing (OpenLDAP or SQL database)
3. Email notification