import os
from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_ckeditor import CKEditor
from datetime import date
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

PASSWORD_METHOD = os.environ.get('PASSWORD_METHOD')
SALT_LENGTH = int(os.environ.get('SALT_LENGTH'))
ADMIN_ID = int(os.environ.get('ADMIN_ID'))

app = Flask(__name__)
login_manager = LoginManager()

app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLITE_PATH')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager.init_app(app)

is_admin = False


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship('User', back_populates='posts')
    comments = relationship('Comment', back_populates='post')


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    posts = relationship('BlogPost', back_populates='author')
    comments = relationship('Comment', back_populates='commenter')


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    commenter_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    commenter = relationship('User', back_populates='comments')
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    post = relationship('BlogPost', back_populates='comments')


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_admin:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def get_all_posts():
    all_posts = db.session.query(BlogPost).all()
    return render_template(
        "index.html",
        all_posts=all_posts,
        logged_in=current_user.is_authenticated,
        is_admin=is_admin
    )


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        if User.query.filter_by(email=form.email.data).first():
            flash('You\'ve already signed up with that email. Log in instead!')
            return redirect(url_for('login'))

        secure_password = generate_password_hash(
            form.password.data,
            method=PASSWORD_METHOD,
            salt_length=SALT_LENGTH
        )

        register_user = User(
            email=form.email.data,
            password=secure_password,
            name=form.name.data
        )

        db.session.add(register_user)
        db.session.commit()
        login_user(register_user)

        global is_admin
        is_admin = (register_user.id == ADMIN_ID)

        return redirect(url_for('get_all_posts'))
    return render_template('register.html', form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = db.session.query(User).filter_by(email=email).first()

        if not user:
            flash('That email is invalid. Please try again!')
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password invalid. Please try again!')
            return redirect(url_for('login'))
        else:
            login_user(user)

            global is_admin
            is_admin = (user.id == ADMIN_ID)

            return redirect(url_for('get_all_posts'))

    return render_template('login.html', form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()

    global is_admin
    is_admin = False

    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)

    if request.method and form.validate_on_submit():
        if not current_user.is_authenticated:
            flash('You need to login before posting a comment.')
            return redirect(url_for('login'))
        print('should only print on submit')
        new_comment = Comment(
            text=form.text.data,
            commenter=current_user,
            post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        form = CommentForm()
        return redirect(url_for('get_all_posts'))

    return render_template(
        "post.html",
        post=requested_post,
        logged_in=current_user.is_authenticated,
        is_admin=is_admin,
        comment_form=form
    )


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for('show_post', index=post.id))
    return render_template('make-post.html', form=edit_form, is_edit=True, logged_in=current_user.is_authenticated)


@app.route('/new-post', methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template('make-post.html', form=form, logged_in=current_user.is_authenticated)


@app.route('/delete/<int:post_id>')
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect('/')


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
