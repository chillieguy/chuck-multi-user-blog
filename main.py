import webapp2
import jinja2

import os
from string import letters

from google.appengine.ext import db

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
JINJA_ENV = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR), autoescape=True)

def render_str(template, **params):
    t = JINJA_ENV.get_template(template)
    return t.render(params)

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

class Blog(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = JINJA_ENV.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

#### Posts db model

class Posts(db.Model):
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    updated = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

#### Blog pages

class Front(Blog):
    def get(self):
        posts = Posts.all().order('-created')
        self.render("index.html", posts=posts)

class PostPage(Blog):
    def get(self, post_id):
        key = db.Key.from_path('Posts', int(post_id), parent=blog_key())
        print(key.to_path())
        post = db.get(key)
        print(post)


        if not post:
            # TODO - Add custom 404
            self.error(404)
            return

        self.render("permalink.html", post=post) 

class New(Blog):
    def get(self):
        self.render("newpost.html")

    def post(self):
        title = self.request.get('title')
        content = self.request.get('content')

        if title and content:
            p = Posts(parent=blog_key(), title=title, content=content)
            p.put()
            self.redirect('/{}'.format(str(p.key().id())))
        else:
            error = "Need to add title and content."
            self.render("newpost.html", title=title, content=content, error=error)
        


app = webapp2.WSGIApplication([
    ('/?', Front),
    ('/([0-9]+)', PostPage),
    ('/newpost', New)
], debug=True)
