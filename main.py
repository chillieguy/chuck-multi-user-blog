import webapp2
import jinja2

import re
import time

import random
import hashlib
import hmac

import os
from string import letters

from google.appengine.ext import db

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
JINJA_ENV = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR), autoescape=True)

#### Secret used for salting and hasing

secret = 'mysecret'

#### Rendering helper functions

def render_str(template, **params):
    t = JINJA_ENV.get_template(template)
    return t.render(params)

#### Set blog key for future use

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

#### Password salting and hashing helper functions

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '{},{}'.format(salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

def make_secure_val(val):
    return '{}|{}'.format(val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

#### Regex function helpers to validate input

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

#### Posts db model

class Posts(db.Model):
    user_id = db.IntegerProperty(required=True)
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    updated = db.DateTimeProperty(auto_now=True)
    likes = db.IntegerProperty(default=0)
    liked_by = db.ListProperty(str)

    def get_user_name(self):
        user = User.by_id(self.user_id)
        return user.name

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

### Users db Model

class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

#### Comments db Model

class Comment(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def get_user_name(self):
        user = User.by_id(self.user_id)
        return user.name

#### Define out base Blog class

class Blog(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = JINJA_ENV.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '{}={}; Path=/'.format(name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

#### Blog pages

class Front(Blog):
    def get(self):
        posts = Posts.all().order('-created')
        self.render("index.html", posts=posts, user=self.user)

class PostPage(Blog):
    def get(self, post_id):
        key = db.Key.from_path('Posts', int(post_id), parent=blog_key())
        post = db.get(key)
        
        # comments = db.Query(Comment)
        # print(post_id)
        # comments.filter('post_id =', post_id)
        comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id =" 
                               + post_id + 
                               "ORDER BY created")
    
        if not post:
            self.redirect('/404page')
            return

        self.render("permalink.html", post=post, user=self.user, comments=comments)

    def post(self, post_id):
        if not self.user:
            self.redirect("/login")
        else:
            key = db.Key.from_path('Posts', int(post_id), parent=blog_key())
            post = db.get(key)
            author = post.get_user_name()
            user = self.user.name

            if author == user or user in post.liked_by:
                self.redirect("/{}".format(post_id))
            else:
                post.likes += 1
                post.liked_by.append(user)
                post.put()

                self.redirect("/{}".format(post_id))

class New(Blog):
    def get(self):
        if self.user:
            self.render("newpost.html", user=self.user)
        else:
            self.redirect("/login")

    def post(self):
        title = self.request.get('title')
        content = self.request.get('content')

        if title and content:
            p = Posts(parent=blog_key(), title=title, content=content, user_id=self.user.key().id())
            p.put()
            self.redirect('/{}'.format(str(p.key().id())))
        else:
            error = "Need to add title and content."
            self.render("newpost.html", title=title, content=content, error=error, user=self.user)

class Login(Blog):
    def get(self):
        self.render('login.html', user=None)

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login.html', error = msg, user=None)

class Signup(Blog):
    def get(self):
        self.render("signup.html", user=None)

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        
        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        print(self.username)
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')


class Logout(Blog):
    def get(self):
        self.logout()
        self.redirect('/')

class Edit(Blog):
    def get(self, post_id):
        if self.user:
            
            key = db.Key.from_path('Posts', int(post_id), parent=blog_key())
            post = db.get(key)

            if not post:
                self.redirect('/404page')
                return

            self.render("edit.html", post=post, user=self.user)
        
        else:
            self.redirect("/login")

    def post(self, post_id):
        
        title = self.request.get('title')
        content = self.request.get('content')

        key = db.Key.from_path('Posts', int(post_id), parent=blog_key())
        p = db.get(key)
        p.title = self.request.get('title')
        p.content = self.request.get('content')

        print(self.user)
        if p.user_id == self.user.key().id():
            if title and content:
                p.put()
                self.redirect('/{}'.format(str(p.key().id())))
            else:
                error = "Need to add title and content."
                self.render("edit.html", title=title, content=content, error=error, post=p)
        else:
            error = "Can not edit a post that is you did not create!"
            self.render("edit.html", title=title, content=content, error=error, post=p)

class Delete(Blog):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Posts', int(post_id), parent=blog_key())
            p = db.get(key)

            if p.user_id == self.user.key().id():
                p.delete()
                time.sleep(.1)
                self.redirect('/')
            else:
                self.redirect('/')

class NewComment(Blog):
    def get(self, post_id):
        return self.redirect('/{}'.format(post_id))
    
    def post(self, post_id):
        key = db.Key.from_path('Posts', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            comment = self.request.get('content')

            if comment:# and self.user:
                c = Comment(parent=blog_key(),
                            comment=comment,
                            user_id=self.user.key().id(),
                            post_id=int(post_id))
                c.put()

                return self.redirect("/{}".format(post_id))
            else:
                return self.redirect("/{}".format(post_id))
        else:
            return self.redirect('/')

class EditComment(Blog):
    def get(self, post_id):
        return self.redirect('/{}'.format(post_id))

    def post(self, post_id):
        key = db.Key.from_path('Posts', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            comment_id = self.request.get('commentId')
            edit_comment = self.request.get('editComment')
            if comment_id and edit_comment and self.user:
                key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
                comment = db.get(key)
                if comment:
                    if comment.get_user_name() == self.user.name:
                        comment.comment = edit_comment
                        comment.put()
                        return self.redirect('/{}'.format(post_id))
                else:
                    return self.redirect('/{}'.format(post_id))
            else:
                return self.redirect('/')
        else:
            return self.redirect('/')

class DeleteComment(Blog):
    def get(self, post_id):
        return self.redirect('/{}'.format(post_id))

    def post(self, post_id):
        key = db.Key.from_path('Posts', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            comment_id = self.request.get('commentId')
            print(comment_id)
            # Retrieve current comment
            c = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
            comment = db.get(c)
            if comment:    
                if comment_id and self.user:
                    if comment.get_user_name() == self.user.name:
                        comment.delete()
                        return self.redirect('/{}'.format(post_id))
                    else:
                        return self.redirect('/{}'.format(post_id))
            else:
                return self.redirect('/')
        else:
            return self.redirect('/')

class HTTPError404(Blog):
    def get(self):
        self.render("404.html")

app = webapp2.WSGIApplication([
    ('/?', Front),
    ('/([0-9]+)', PostPage),
    ('/newpost', New),
    ('/login', Login),
    ('/signup', Register),
    ('/logout', Logout),
    ('/edit/([0-9]+)', Edit),
    ('/delete/([0-9]+)', Delete),
    ('/([0-9]+)/newcomment', NewComment),
    ('/([0-9]+)/editcomment', EditComment),
    ('/([0-9]+)/deletecomment', DeleteComment),
    ('/404page', HTTPError404)
], debug=True)
