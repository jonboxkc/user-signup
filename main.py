#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import re
import os
from string import letters

import webapp2


class Index(webapp2.RequestHandler):
    def get(self):
        header = "<h1>Signup</h1>"


        signup = """
        <form action="/signup" method="post">
                    <form>
                        <label>User Name
                            <input name = "username">
                            <br>
                        <label>Password
                            <input name = "password">
                            <br>
                        <label>Confirm Password
                            <input name = "verify">
                            <br>
                        <label>"Email (Optional)"
                            <input name = "email">
                        </label>
                        <br>
                     <input type="submit" value="Submit"/>
                    </form>
                """

        self.response.write(header + signup)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(webapp2.RequestHandler):

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        #username = "jonbox"
        #password = "Letmein89"
        #verify = "Letmein89"
        #email = "jonharinggmail.com"
        params = ""

        if not valid_username(username):
            params = params + "&error_username=That's not a valid username."
            have_error = True

        if not valid_password(password):
            params = params + "&error_password=That wasn't a valid password."
            have_error = True
        elif password != verify:
            params = params + "&error_verify=Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params = params + "&error_email=That's not a valid email."
            have_error = True

        if have_error:
            self.redirect('/errors?username=' + username + '&email=' + email + params)
        else:
            self.redirect('/welcome?username=' + username)

class errors(webapp2.RequestHandler):
    def get(self):
        username = self.request.get('username')
        email = self.request.get('email')
        error_username = self.request.get('error_username')
        error_password = self.request.get('error_password')
        error_verify = self.request.get('error_verify')
        error_email = self.request.get('error_email')
        header = """<!DOCTYPE html>
                   <html>
                   <head>
                    <title>FlickList</title>
                    <style type="text/css">
                        .error {
                        color: red;
                            }
                    </style>
                    </head>
                    <body><h1>Signup</h1>"""

        signup = """
         <form action="/signup" method="post">
          <table>
           <tr>
             <td class="label">
               Username
             </td>
             <td>
               <input type="text" name="username" value="{0}">
             </td>
             <td class="error">
               {2}
             </td>
           </tr>

           <tr>
            <td class="label">
             Password
           </td>
           <td>
            <input type="password" name="password" value="">
           </td>
           <td class="error">
             {3}
           </td>
          </tr>

          <tr>
           <td class="label">
             Verify Password
           </td>
           <td>
             <input type="password" name="verify" value="">
           </td>
           <td class="error">
             {4}
           </td>
         </tr>

         <tr>
           <td class="label">
             Email (optional)
           </td>
           <td>
             <input type="text" name="email" value="{1}">
           </td>
           <td class="error">
             {5}
           </td>
         </tr>
        </table>

       <input type="submit" value="submit">
      </form>
      </body>
                """.format(username,email,error_username,error_password,error_verify,error_email)

        self.response.write(header + signup)



class Welcome(webapp2.RequestHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.response.write("WELCOME " + username )
        else:
            self.redirect('/signup')

app = webapp2.WSGIApplication([('/', Index),
                               ('/signup', Signup),
                               ('/errors',errors),
                               ('/welcome', Welcome)],
                              debug=True)
